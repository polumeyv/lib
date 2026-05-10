import { Effect, Option, ParseResult, Schema } from 'effect';
import { Postgres, encryptSecret, decryptSecret } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { UserSub } from '../model';
import { AuthConfig } from '../config';

export type OAuthAccountStatus = 'active' | 'revoked' | 'hijacked';

/**
 * A row from `oidc_accounts`. Tokens are ciphertext when read raw from `pg`,
 * plaintext after going through `decodeRow`. The TypeScript shape is the same
 * either way; the encryption boundary is enforced at the function level.
 */
export type OAuthAccount = {
	sub: typeof UserSub.Type;
	provider: string;
	subject: string;
	email: string | null;
	locale: string | null;
	access_token: string | null;
	refresh_token: string | null;
	scopes: string | null;
	token_expires: Date | null;
	status: OAuthAccountStatus;
};

/** Input shape for `link` — no status (always upserts as 'active'), token_expires optional. */
export type OAuthAccountInput = Omit<OAuthAccount, 'status' | 'token_expires'> & { token_expires?: Date | null };

const COLUMNS = 'sub, provider, subject, email, locale, access_token, refresh_token, scopes, token_expires, status';

/**
 * Sole writer to `oidc_accounts`. Owns the row lifecycle and seals the
 * at-rest encryption invariant inside the `EncryptedString` codec — callers
 * pass and receive plaintext tokens.
 */
export class OAuthAccountStore extends Effect.Service<OAuthAccountStore>()('OAuthAccountStore', {
	effect: Effect.gen(function* () {
		const pg = yield* Postgres;
		const { cryptoKey } = yield* AuthConfig;

		const Enc = Schema.NullOr(
			Schema.transformOrFail(Schema.String, Schema.String, {
				strict: true,
				decode: (ciphertext, _, ast) =>
					Effect.try({
						try: () => decryptSecret(ciphertext, cryptoKey),
						catch: () => new ParseResult.Type(ast, ciphertext, 'Decryption failed'),
					}),
				encode: (plaintext, _, ast) =>
					Effect.try({
						try: () => encryptSecret(plaintext, cryptoKey),
						catch: () => new ParseResult.Type(ast, plaintext, 'Encryption failed'),
					}),
			}),
		);
		const encode = Schema.encode(Enc);
		const decode = Schema.decode(Enc);

		const decodeRow = (row: OAuthAccount | null) =>
			row === null
				? Effect.succeedNone
				: Effect.zipWith(decode(row.access_token), decode(row.refresh_token), (access_token, refresh_token) => Option.some({ ...row, access_token, refresh_token } satisfies OAuthAccount));

		return {
			/** Insert or update an account for a user; sets status='active'. Tokens encrypted via codec. */
			link: (input: OAuthAccountInput) =>
				Effect.gen(function* () {
					const access = yield* encode(input.access_token);
					const refresh = yield* encode(input.refresh_token);
					return yield* pg.use(
						(sql) => sql`
							INSERT INTO oidc_accounts (sub, provider, subject, email, locale, access_token, refresh_token, scopes, token_expires)
							VALUES (${input.sub}, ${input.provider}, ${input.subject}, ${input.email}, ${input.locale}, ${access}, ${refresh}, ${input.scopes}, ${input.token_expires ?? null})
							ON CONFLICT (sub) DO UPDATE SET
								email = EXCLUDED.email,
								locale = EXCLUDED.locale,
								access_token = EXCLUDED.access_token,
								refresh_token = COALESCE(EXCLUDED.refresh_token, oidc_accounts.refresh_token),
								scopes = EXCLUDED.scopes,
								token_expires = EXCLUDED.token_expires,
								status = 'active'
						`,
					);
				}),

			/** Find by user `sub`. Plaintext tokens. */
			getBySub: (sub: typeof UserSub.Type) =>
				Effect.flatMap(
					pg.first((sql) => sql<OAuthAccount[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_accounts WHERE sub = ${sub}`),
					decodeRow,
				),

			/** Find an active account by `(sub, provider)`. Used by the token vault. */
			getActive: (sub: typeof UserSub.Type, provider: string) =>
				Effect.flatMap(
					pg.first((sql) => sql<OAuthAccount[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_accounts WHERE sub = ${sub} AND provider = ${provider} AND status = 'active'`),
					decodeRow,
				),

			/** Look up `users.sub` + terms-acceptance state by email. Used by auth-flow's email-fallback path. */
			getByEmail: (email: typeof Email.Type) =>
				Effect.map(
					pg.first((sql) => sql<{ sub: typeof UserSub.Type; terms_acc: boolean }[]>`SELECT sub, terms_acc IS NOT NULL AS terms_acc FROM users WHERE email = ${email}`),
					Option.fromNullable,
				),

			/** Find by external `(provider, subject)` key. */
			getByProviderSubject: (provider: string, subject: string) =>
				Effect.flatMap(
					pg.first((sql) => sql<OAuthAccount[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_accounts WHERE provider = ${provider} AND subject = ${subject}`),
					decodeRow,
				),

			/**
			 * OAuth callback resolution: refresh tokens for an existing link and look up the user, OR fall back to
			 * email lookup for an existing user that hasn't yet linked this provider.
			 *
			 * Returns:
			 *   Some({ sub, email, terms_acc, linked: true })  — provider+subject row existed; tokens refreshed
			 *   Some({ sub, email, terms_acc, linked: false }) — no provider link yet, but a user exists with this email
			 *   None                                            — neither (caller starts signup)
			 */
			resolveLogin: (params: Pick<OAuthAccount, 'provider' | 'subject' | 'refresh_token' | 'scopes'> & { email: typeof Email.Type; access_token: string }) =>
				Effect.flatMap(Effect.zip(encode(params.access_token), encode(params.refresh_token), { concurrent: true }), ([access, refresh]) =>
					Effect.map(
						pg.first(
							(sql) => sql<{ sub: typeof UserSub.Type; email: typeof Email.Type; terms_acc: boolean; linked: boolean }[]>`
								WITH updated AS (
									UPDATE oidc_accounts
									SET email = ${params.email},
										access_token = ${access},
										refresh_token = COALESCE(${refresh}, oidc_accounts.refresh_token),
										scopes = COALESCE(${params.scopes}, oidc_accounts.scopes)
									WHERE provider = ${params.provider} AND subject = ${params.subject}
									RETURNING sub
								)
								SELECT u.sub, u.email, u.terms_acc IS NOT NULL AS terms_acc, TRUE AS linked
								FROM updated JOIN users u USING (sub)
								UNION ALL
								SELECT u.sub, u.email, u.terms_acc IS NOT NULL AS terms_acc, FALSE AS linked
								FROM users u
								WHERE u.email = ${params.email} AND NOT EXISTS (SELECT 1 FROM updated)
							`,
						),
						Option.fromNullable,
					),
				),

			/** All accounts linked to a user (any status). Plaintext tokens. */
			listForUser: (sub: typeof UserSub.Type) =>
				Effect.flatMap(
					pg.use((sql) => sql<OAuthAccount[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_accounts WHERE sub = ${sub}`),
					(rows) => Effect.forEach(rows, (r) => Effect.map(decodeRow(r), Option.getOrThrow)),
				),

			/** Replace just the access_token + token_expires for a specific provider. Used by token vault on refresh. */
			replaceAccessToken: (sub: typeof UserSub.Type, provider: string, access_token: string, expires_at: Date) =>
				Effect.flatMap(encode(access_token), (enc) =>
					pg.use((sql) => sql`UPDATE oidc_accounts SET access_token = ${enc}, token_expires = ${expires_at} WHERE sub = ${sub} AND provider = ${provider}`),
				),

			/** Null out tokens + scopes for a provider; row stays. Used by disconnect flows. */
			clearTokens: (sub: typeof UserSub.Type, provider: string) =>
				pg.use((sql) => sql`UPDATE oidc_accounts SET access_token = NULL, refresh_token = NULL, scopes = NULL WHERE sub = ${sub} AND provider = ${provider}`),

			/** Delete every linked account for a user. Used by full disconnect. */
			unlinkAll: (sub: typeof UserSub.Type) => pg.use((sql) => sql`DELETE FROM oidc_accounts WHERE sub = ${sub}`),

			/** Delete a row by external `(provider, subject)` key. Used by RISC tokens-revoked. */
			unlinkByProviderSubject: (provider: string, subject: string) => pg.use((sql) => sql`DELETE FROM oidc_accounts WHERE provider = ${provider} AND subject = ${subject}`),

			/** Update status for a row keyed by external `(provider, subject)`. Optionally null tokens at the same time. */
			setStatus: (provider: string, subject: string, status: OAuthAccountStatus, opts?: { clear?: 'refresh' | 'all' }) => {
				const clear = opts?.clear;
				const set = { status, ...(clear && { refresh_token: null }), ...(clear === 'all' && { access_token: null }) };
				return pg.use((sql) => sql`UPDATE oidc_accounts SET ${sql(set)} WHERE provider = ${provider} AND subject = ${subject} ${clear ? sql`` : sql`AND status != ${status}`}`);
			},
		};
	}),
}) {}

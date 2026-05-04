import { Effect, Option, Schema } from 'effect';
import { Postgres } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { UserSub } from '../model';
import { AuthConfig } from '../config';
import { makeEncryptedString } from './encrypted';

export type OAuthAccountStatus = 'active' | 'revoked' | 'hijacked';

/** A row from `oidc_accounts` with `access_token`/`refresh_token` decoded to plaintext. */
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

/** Input shape for `link` — plaintext tokens, no status (always upserts as 'active'). */
export type OAuthAccountInput = {
	sub: typeof UserSub.Type;
	provider: string;
	subject: string;
	email: string | null;
	locale: string | null;
	access_token: string | null;
	refresh_token: string | null;
	scopes: string | null;
	token_expires?: Date | null;
};

type RawRow = {
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
		const Enc = makeEncryptedString(cryptoKey);
		const encode = Schema.encode(Enc);
		const decode = Schema.decode(Enc);

		const decodeMaybe = (v: string | null) => (v ? Effect.map(decode(v), (s): string | null => s) : Effect.succeed<string | null>(null));
		const encodeMaybe = (v: string | null | undefined) => (v ? Effect.map(encode(v), (s): string | null => s) : Effect.succeed<string | null>(null));

		const decodeRow = (row: RawRow) =>
			Effect.gen(function* () {
				const access = yield* decodeMaybe(row.access_token);
				const refresh = yield* decodeMaybe(row.refresh_token);
				return { ...row, access_token: access, refresh_token: refresh } satisfies OAuthAccount;
			});

		return {
			/** Insert or update an account for a user; sets status='active'. Tokens encrypted via codec. */
			link: (input: OAuthAccountInput) =>
				Effect.gen(function* () {
					const access = yield* encodeMaybe(input.access_token);
					const refresh = yield* encodeMaybe(input.refresh_token);
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
			findBySub: (sub: typeof UserSub.Type) =>
				Effect.flatMap(
					pg.first((sql) => sql<RawRow[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_accounts WHERE sub = ${sub}`),
					(row) => (row ? Effect.map(decodeRow(row), Option.some) : Effect.succeed(Option.none<OAuthAccount>())),
				),

			/** Find an active account by `(sub, provider)`. Used by the token vault. */
			findActive: (sub: typeof UserSub.Type, provider: string) =>
				Effect.flatMap(
					pg.first(
						(sql) => sql<RawRow[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_accounts WHERE sub = ${sub} AND provider = ${provider} AND status = 'active'`,
					),
					(row) => (row ? Effect.map(decodeRow(row), Option.some) : Effect.succeed(Option.none<OAuthAccount>())),
				),

			/** Look up `users.sub` + terms-acceptance state by email. Used by auth-flow's email-fallback path. */
			findByEmail: (email: typeof Email.Type) =>
				Effect.map(
					pg.first(
						(sql) => sql<{ sub: typeof UserSub.Type; terms_acc: boolean }[]>`SELECT sub, terms_acc IS NOT NULL AS terms_acc FROM users WHERE email = ${email}`,
					),
					Option.fromNullable,
				),

			/** Find by external `(provider, subject)` key. */
			findByProviderSubject: (provider: string, subject: string) =>
				Effect.flatMap(
					pg.first(
						(sql) => sql<RawRow[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_accounts WHERE provider = ${provider} AND subject = ${subject}`,
					),
					(row) => (row ? Effect.map(decodeRow(row), Option.some) : Effect.succeed(Option.none<OAuthAccount>())),
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
			resolveLogin: (params: {
				provider: string;
				subject: string;
				email: typeof Email.Type;
				access_token: string;
				refresh_token?: string | null;
				scopes?: string | null;
			}) =>
				Effect.gen(function* () {
					const access = yield* encodeMaybe(params.access_token);
					const refresh = yield* encodeMaybe(params.refresh_token);
					return yield* Effect.map(
						pg.first(
							(sql) => sql<{ sub: typeof UserSub.Type; email: typeof Email.Type; terms_acc: boolean; linked: boolean }[]>`
								WITH updated AS (
									UPDATE oidc_accounts
									SET email = ${params.email},
										access_token = ${access},
										refresh_token = COALESCE(${refresh}, oidc_accounts.refresh_token),
										scopes = COALESCE(${params.scopes ?? null}, oidc_accounts.scopes)
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
					);
				}),

			/** All accounts linked to a user (any status). Plaintext tokens. */
			listForUser: (sub: typeof UserSub.Type) =>
				Effect.flatMap(
					pg.use((sql) => sql<RawRow[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_accounts WHERE sub = ${sub}`),
					(rows) => Effect.forEach(rows, decodeRow),
				),

			/** Replace just the access_token + token_expires for a specific provider. Used by token vault on refresh. */
			replaceAccessToken: (sub: typeof UserSub.Type, provider: string, access_token: string, expires_at: Date) =>
				Effect.flatMap(
					encode(access_token),
					(enc) => pg.use(
						(sql) => sql`UPDATE oidc_accounts SET access_token = ${enc}, token_expires = ${expires_at} WHERE sub = ${sub} AND provider = ${provider}`,
					),
				),

			/** Null out tokens + scopes for a provider; row stays. Used by disconnect flows. */
			clearTokens: (sub: typeof UserSub.Type, provider: string) =>
				pg.use(
					(sql) => sql`UPDATE oidc_accounts SET access_token = NULL, refresh_token = NULL, scopes = NULL WHERE sub = ${sub} AND provider = ${provider}`,
				),

			/** Delete every linked account for a user. Used by full disconnect. */
			unlinkAll: (sub: typeof UserSub.Type) => pg.use((sql) => sql`DELETE FROM oidc_accounts WHERE sub = ${sub}`),

			/** Delete a row by external `(provider, subject)` key. Used by RISC tokens-revoked. */
			unlinkByProviderSubject: (provider: string, subject: string) =>
				pg.use((sql) => sql`DELETE FROM oidc_accounts WHERE provider = ${provider} AND subject = ${subject}`),

			/** Update status for a row keyed by external `(provider, subject)`. Optionally null tokens at the same time. */
			setStatus: (
				provider: string,
				subject: string,
				status: OAuthAccountStatus,
				opts?: { clear?: 'refresh' | 'all' },
			) => {
				if (opts?.clear === 'all') {
					return pg.use(
						(sql) => sql`UPDATE oidc_accounts SET status = ${status}, refresh_token = NULL, access_token = NULL WHERE provider = ${provider} AND subject = ${subject}`,
					);
				}
				if (opts?.clear === 'refresh') {
					return pg.use(
						(sql) => sql`UPDATE oidc_accounts SET status = ${status}, refresh_token = NULL WHERE provider = ${provider} AND subject = ${subject}`,
					);
				}
				return pg.use(
					(sql) => sql`UPDATE oidc_accounts SET status = ${status} WHERE provider = ${provider} AND subject = ${subject} AND status != ${status}`,
				);
			},
		};
	}),
}) {}

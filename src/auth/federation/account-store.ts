import { Effect, Option } from 'effect';
import { Postgres, CryptoService } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { UserSub } from '../../user/model';
import type { OAuthResult } from './oidc.model';

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

/**
 * Sole writer to `oidc_accounts`. Owns the row lifecycle and seals the
 * at-rest encryption invariant inside the `EncryptedString` codec — callers
 * pass and receive plaintext tokens.
 */
export class OAuthAccountStore extends Effect.Service<OAuthAccountStore>()('OAuthAccountStore', {
	effect: Effect.gen(function* () {
		const pg = yield* Postgres;
		const { encode, decode } = yield* CryptoService;

		// Decrypts both token columns in one shot, returning the row with plaintext tokens.
		const decryptRow = (row: OAuthAccount) =>
			Effect.zipWith(
				decode(row.access_token),
				decode(row.refresh_token),
				(access_token, refresh_token) => ({ ...row, access_token, refresh_token }) satisfies OAuthAccount,
			);

		// Encrypts the access+refresh token pair from an OAuthResult concurrently.
		const encodeTokens = (r: OAuthResult) => Effect.zip(encode(r.access_token), encode(r.refresh_token), { concurrent: true });

		return {
			/** Insert or update an account for `sub`; sets status='active'. Tokens encrypted via codec. The OAuthResult shape comes straight from `OidcAuthFlow.exchangeCode` — no per-call-site mapping. */
			link: (sub: typeof UserSub.Type, r: OAuthResult) =>
				Effect.andThen(encodeTokens(r), ([access, refresh]) =>
					pg.use(
						(sql) => sql`
                    INSERT INTO oidc_accounts (sub, provider, subject, email, locale, access_token, refresh_token, scopes, token_expires)
                    VALUES (${sub}, ${r.provider}, ${r.claims.sub}, ${r.claims.email}, ${r.claims.locale}, ${access}, ${refresh}, ${r.scopes}, ${r.expires_at})
                    ON CONFLICT (sub) DO UPDATE SET
                        email = EXCLUDED.email,
                        locale = EXCLUDED.locale,
                        access_token = EXCLUDED.access_token,
                        refresh_token = COALESCE(EXCLUDED.refresh_token, oidc_accounts.refresh_token),
                        scopes = EXCLUDED.scopes,
                        token_expires = EXCLUDED.token_expires,
                        status = 'active'
                `,
					),
				),

			/** Find the active `(sub, provider)` account with plaintext tokens. Used by the token vault. */
			getBySub: (sub: typeof UserSub.Type, provider: string) =>
				Effect.flatMap(
					pg.first(
						(sql) => sql<OAuthAccount[]>`
							SELECT sub, provider, subject, email, locale, access_token, refresh_token, scopes, token_expires, status
							FROM oidc_accounts WHERE sub = ${sub} AND provider = ${provider} AND status = 'active'
						`,
						{ onNull: 'option' },
					),
					(opt) => Effect.transposeOption(Option.map(opt, decryptRow)),
				),

			/** Lightweight linked-identity lookup — provider + email only, no token decryption. For UI display. */
			getIdentityBySub: (sub: typeof UserSub.Type) =>
				pg.first(
					(sql) => sql<{ provider: string; email: string | null }[]>`
						SELECT provider, email FROM oidc_accounts WHERE sub = ${sub}
					`,
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
			refreshLinkOrResolveUser: (r: OAuthResult) =>
				Effect.flatMap(encodeTokens(r), ([access, refresh]) =>
					pg.first(
						(sql) => sql<{ sub: typeof UserSub.Type; email: typeof Email.Type; terms_acc: boolean; linked: boolean }[]>`
							WITH updated AS (
								UPDATE oidc_accounts
								SET email = ${r.claims.email},
									access_token = ${access},
									refresh_token = COALESCE(${refresh}, oidc_accounts.refresh_token),
									scopes = COALESCE(${r.scopes}, oidc_accounts.scopes)
								WHERE provider = ${r.provider} AND subject = ${r.claims.sub}
								RETURNING sub
							)
							SELECT u.sub, u.email, u.terms_acc IS NOT NULL AS terms_acc, TRUE AS linked
							FROM updated JOIN users u USING (sub)
							UNION ALL
							SELECT u.sub, u.email, u.terms_acc IS NOT NULL AS terms_acc, FALSE AS linked
							FROM users u
							WHERE u.email = ${r.claims.email} AND NOT EXISTS (SELECT 1 FROM updated)
						`,
						{ onNull: 'option' },
					),
				),

			/** Replace just the access_token + token_expires for a specific provider. Used by token vault on refresh. */
			replaceAccessToken: (sub: typeof UserSub.Type, provider: string, access_token: string, expires_at: Date) =>
				Effect.flatMap(encode(access_token), (enc) =>
					pg.use((sql) => sql`UPDATE oidc_accounts SET access_token = ${enc}, token_expires = ${expires_at} WHERE sub = ${sub} AND provider = ${provider}`),
				),

			/** Delete every linked account for a user. Used by full disconnect. */
			unlinkAll: (sub: typeof UserSub.Type) => pg.use((sql) => sql`DELETE FROM oidc_accounts WHERE sub = ${sub}`),

			/** Delete a row by external `(provider, subject)` key. Used by RISC tokens-revoked. */
			unlinkByProviderSubject: (provider: string, subject: string) =>
				pg.use((sql) => sql`DELETE FROM oidc_accounts WHERE provider = ${provider} AND subject = ${subject}`),

			/** Update status for a row keyed by external `(provider, subject)`. Optionally null tokens at the same time. */
			setStatus: (provider: string, subject: string, status: OAuthAccountStatus, opts?: { clear?: 'refresh' | 'all' }) => {
				const clear = opts?.clear;
				const set = { status, ...(clear && { refresh_token: null }), ...(clear === 'all' && { access_token: null }) };
				return pg.use(
					(sql) => sql`UPDATE oidc_accounts SET ${sql(set)} WHERE provider = ${provider} AND subject = ${subject} ${clear ? sql`` : sql`AND status != ${status}`}`,
				);
			},
		};
	}),
	dependencies: [CryptoService.Default],
}) {}

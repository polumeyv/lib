import { Context, Effect, Cause, Schema, Option } from 'effect';
import { UserSub } from '../model';
import { Email } from '@polumeyv/lib/public/types';
import { Postgres, Redis, encryptSecret, decryptSecret } from '@polumeyv/lib/server';
import { SessionService } from '@polumeyv/lib/server';
import {
	discovery,
	buildAuthorizationUrl,
	authorizationCodeGrant,
	AuthorizationResponseError,
	ResponseBodyError,
	randomState,
	randomNonce,
	randomPKCECodeVerifier,
	calculatePKCECodeChallenge,
	type Configuration,
} from 'openid-client';
import { OAuthClaims, OAuthResult, type OidcAccount } from './oidc.model';
import { OAuthError } from '../errors';
import { AuthConfig, HasOidcKey } from '../config';
import { AuthenticatedUser } from '../otp/otp.model';

export class OidcProviderRegistry extends Context.Tag('OidcProviderRegistry')<
	OidcProviderRegistry,
	ReadonlyMap<
		string,
		{
			readonly discoveryUrl: string;
			readonly clientId: string;
			readonly clientSecret: string;
			readonly redirectUri: string;
		}
	>
>() {}

const OAuthSessionKey = (state: string) => `oauth:${state}`;
const SignupKey = (uuid: string) => `oidc:${uuid}`;
const LinkingKey = (email: string) => `link_oidc:${email}`;

export class OidcService extends Effect.Service<OidcService>()('OidcService', {
	effect: Effect.gen(function* () {
		const { oauthSessionTtl, oauthScopes, cryptoKey } = yield* AuthConfig;
		const session = yield* SessionService;
		const pg = yield* Postgres;
		const registry = yield* OidcProviderRegistry;

		// --- Repository methods (formerly OidcRepository) ---

		const findBy = (column: 'subject' | 'sub', value: string) =>
			Effect.map(
				pg.first((sql) => sql<OidcAccount[]>`SELECT * FROM oidc_accounts WHERE ${sql(column)} = ${value}`),
				Option.fromNullable,
			);

		const upsertRaw = (req: OidcAccount) =>
			Effect.asVoid(
				pg.use(
					(sql) => sql`
			INSERT INTO oidc_accounts (sub, provider, subject, email, locale, access_token, refresh_token, scopes)
			VALUES (${req.sub}, ${req.provider}, ${req.subject}, ${req.email}, ${req.locale}, ${req.access_token ? encryptSecret(req.access_token, cryptoKey) : null}, ${req.refresh_token ? encryptSecret(req.refresh_token, cryptoKey) : null}, ${req.scopes})
			ON CONFLICT (sub) DO UPDATE SET
				email = EXCLUDED.email,
				locale = EXCLUDED.locale,
				access_token = EXCLUDED.access_token,
				refresh_token = COALESCE(EXCLUDED.refresh_token, oidc_accounts.refresh_token),
				scopes = EXCLUDED.scopes
		`,
				),
			);

		const upsert = (sub: typeof UserSub.Type, r: typeof OAuthResult.Type) =>
			Effect.asVoid(
				pg.use(
					(sql) => sql`
				INSERT INTO oidc_accounts (sub, provider, subject, email, locale, access_token, refresh_token, scopes, token_expires)
				VALUES (${sub}, ${r.provider}, ${r.claims.sub}, ${r.claims.email}, ${r.claims.locale ?? null}, ${encryptSecret(r.access_token, cryptoKey)}, ${r.refresh_token ? encryptSecret(r.refresh_token, cryptoKey) : null}, ${r.scopes}, ${r.expires_at ?? null})
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
			);

		const resolveLogin = (req: { subject: string; email: string; access_token: string; refresh_token?: string | null; scopes?: string | null }) =>
			Effect.map(
				pg.first(
					(sql) => sql<{ sub: typeof UserSub.Type; email: typeof Email.Type; terms_acc: boolean; linked: boolean }[]>`
					WITH updated AS (
						UPDATE oidc_accounts
						SET email = ${req.email},
							access_token = ${encryptSecret(req.access_token, cryptoKey)},
							refresh_token = COALESCE(${req.refresh_token ? encryptSecret(req.refresh_token, cryptoKey) : null}, oidc_accounts.refresh_token),
							scopes = COALESCE(${req.scopes ?? null}, oidc_accounts.scopes)
						WHERE subject = ${req.subject}
						RETURNING sub
					)
					SELECT u.sub, u.email, u.terms_acc IS NOT NULL AS terms, TRUE AS linked
					FROM updated JOIN users u USING (sub)
					UNION ALL
					SELECT u.sub, u.email, u.terms_acc IS NOT NULL AS terms, FALSE AS linked
					FROM users u
					WHERE u.email = ${req.email} AND NOT EXISTS (SELECT 1 FROM updated)
				`,
				),
				Option.fromNullable,
			);

		const remove = (sub: typeof UserSub.Type) => pg.use((sql) => sql`DELETE FROM oidc_accounts WHERE sub = ${sub}`);

		// --- Provider resolution (config + entry + cached discovery) ---

		const configs = new Map<string, Configuration>();

		const resolveProvider = (provider: string) =>
			Effect.andThen(
				Effect.mapError(Effect.fromNullable(registry.get(provider)), () => new OAuthError({ message: `Unknown OIDC provider: ${provider}` })),
				(entry) =>
					configs.has(provider)
						? Effect.succeed({ config: configs.get(provider)!, entry })
						: Effect.map(
								Effect.tap(
									Effect.tryPromise({
										try: () => discovery(new URL(entry.discoveryUrl), entry.clientId, entry.clientSecret),
										catch: (e) => new OAuthError({ cause: e, message: `OIDC discovery failed for ${provider}` }),
									}),
									(cfg) => Effect.sync(() => configs.set(provider, cfg)),
								),
								(config) => ({ config, entry }),
							),
			);

		const exchangeCode = (callbackUrl: URL) =>
			Effect.andThen(
				Effect.filterOrFail(
					Effect.sync(() => callbackUrl.searchParams.get('state')),
					(s): s is string => s !== null,
					() => new OAuthError({ message: 'Missing state parameter in callback URL' }),
				),
				(state) =>
					Effect.andThen(session.pop<{ nonce: string; codeVerifier: string; provider: string; redirectUri?: string }>(OAuthSessionKey(state)), ({ nonce, codeVerifier, provider, redirectUri }) =>
						Effect.andThen(resolveProvider(provider), ({ config, entry }) =>
							Effect.andThen(
								Effect.tryPromise({
									try: () =>
										authorizationCodeGrant(
											config,
											callbackUrl,
											{ expectedState: state, expectedNonce: nonce, pkceCodeVerifier: codeVerifier },
											{ redirect_uri: redirectUri ?? entry.redirectUri },
										),
									catch: (e) =>
										e instanceof AuthorizationResponseError
											? new OAuthError({ cause: e, message: e.error_description || e.error })
											: e instanceof ResponseBodyError
												? new OAuthError({ cause: e, message: e.error_description || e.error })
												: new OAuthError({ cause: e, message: 'Token exchange failed' }),
								}),
								(tokens) => {
									const claims = tokens.claims() as Record<string, unknown> | undefined;
									return !claims
										? Effect.fail(new OAuthError({ message: 'No ID token claims returned' }))
										: claims.email_verified === false
											? Effect.fail(new OAuthError({ message: 'Email not verified by provider' }))
											: Effect.map(
													Effect.mapError(Schema.decodeUnknown(OAuthClaims)(claims), (e) => new OAuthError({ cause: e, message: 'Invalid ID token claims' })),
													(claims) => ({
														claims,
														provider,
														access_token: tokens.access_token,
														scopes: tokens.scope ?? oauthScopes,
														refresh_token: tokens.refresh_token,
														expires_at: tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : undefined,
													}),
												);
								},
							),
						),
					),
			);

		const handleCallback = (callbackUrl: URL) =>
			Effect.andThen(exchangeCode(callbackUrl), (result) =>
				Effect.map(
					resolveLogin({
						subject: result.claims.sub,
						email: result.claims.email,
						access_token: result.access_token,
						refresh_token: result.refresh_token,
						scopes: result.scopes,
					}),
					(login) => ({ result, login }),
				),
			);

		// --- Signup sessions (Case 2) ---
		const createSignupSession = (result: typeof OAuthResult.Type) =>
			Effect.tap(
				Effect.sync(() => Bun.randomUUIDv7()),
				(token) =>
					session.push(SignupKey(token), 600, {
						email: result.claims.email,
						provider: result.provider,
						subject: result.claims.sub,
						locale: result.claims.locale ?? null,
						picture: result.claims.picture ?? null,
						access_token: result.access_token,
						refresh_token: result.refresh_token ?? null,
						scopes: result.scopes,
					}),
			);

		const validateSignupSession = (uuid: string) => session.peek<typeof OAuthResult.Type>(SignupKey(uuid));

		const clearSignupSession = (uuid: string) => session.delete(SignupKey(uuid));

		// --- Linking sessions (Case 3) -- >

		const clearLinkingData = (email: string) => session.delete(LinkingKey(email));

		// --- Full linking flow (Case 3) ---

		const linkAccount = (user: AuthenticatedUser) => Effect.andThen(session.pop<typeof OAuthResult.Type>(LinkingKey(user.email)), (r) => upsert(user.sub, r));

		return {
			findBy,
			upsert,
			upsertRaw,
			resolveLogin,
			remove,
			buildAuthUrl: (provider: string, opts?: { scopes?: string; redirectUri?: string; extras?: Record<string, string> }) =>
				Effect.andThen(resolveProvider(provider), ({ config, entry }) =>
					Effect.andThen(
						Effect.tryPromise({
							try: (
								(codeVerifier) => () =>
									calculatePKCECodeChallenge(codeVerifier).then((code_challenge) => ({
										state: randomState(),
										nonce: randomNonce(),
										codeVerifier,
										code_challenge,
									}))
							)(randomPKCECodeVerifier()),
							catch: (e) => new OAuthError({ cause: e, message: 'PKCE challenge calculation failed' }),
						}),
						({ state, nonce, codeVerifier, code_challenge }) =>
							session.push(OAuthSessionKey(state), oauthSessionTtl, { nonce, codeVerifier, provider, redirectUri: opts?.redirectUri ?? entry.redirectUri }).pipe(
								Effect.as(
									buildAuthorizationUrl(config, {
										redirect_uri: opts?.redirectUri ?? entry.redirectUri,
										scope: opts?.scopes ?? oauthScopes,
										state,
										nonce,
										code_challenge,
										code_challenge_method: 'S256',
										...(opts?.extras ?? {}),
									}),
								),
							),
					),
				),
			exchangeCode,
			handleCallback,
			createSignupSession,
			validateSignupSession,
			clearSignupSession,
			clearLinkingData,
			linkAccount,
		};
	}),
	dependencies: [],
}) {}

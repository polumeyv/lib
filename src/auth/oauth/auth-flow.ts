import { Effect, Schema } from 'effect';
import { SessionService } from '@polumeyv/lib/server';
import {
	authorizationCodeGrant,
	AuthorizationResponseError,
	buildAuthorizationUrl,
	calculatePKCECodeChallenge,
	randomNonce,
	randomPKCECodeVerifier,
	randomState,
	ResponseBodyError,
} from 'openid-client';
import { OAuthClaims, type OAuthResult } from './oidc.model';
import { OAuthError } from '../errors';
import { AuthConfig } from '../config';
import { AuthenticatedUser } from '../otp/otp.model';
import { OAuthProviderResolver } from './provider-resolver';
import { OAuthAccountStore } from './account-store';

const OAuthSessionKey = (state: string) => `oauth:${state}`;
const SignupKey = (uuid: string) => `oauth_signup:${uuid}`;
const LinkingKey = (email: string) => `link_oidc:${email}`;

/**
 * OIDC sign-in / link / signup orchestration. Composes `OAuthProviderResolver`
 * for provider config + discovery, `SessionService` for ephemeral state (PKCE
 * params, signup payloads, linking payloads), and `OAuthAccountStore` for the
 * persistent OAuth account row.
 *
 * Persistent storage of `oidc_accounts` rows lives in `OAuthAccountStore`;
 * this module only orchestrates the flow.
 */
export class OidcAuthFlow extends Effect.Service<OidcAuthFlow>()('OidcAuthFlow', {
	effect: Effect.gen(function* () {
		const { oauthSessionTtl, oauthScopes, signupSessionTtl, oidcLinkSessionTtl } = yield* AuthConfig;
		const session = yield* SessionService;
		const resolver = yield* OAuthProviderResolver;
		const store = yield* OAuthAccountStore;

		const buildAuthUrl = (provider: string, opts?: { scopes?: string; extras?: Record<string, string>; redirectUri?: string }) =>
			Effect.flatMap(resolver.resolve(provider), ({ config, entry }) => {
				const codeVerifier = randomPKCECodeVerifier();
				const state = randomState();
				const nonce = randomNonce();
				const redirectUri = opts?.redirectUri ?? entry.redirectUri;
				return Effect.zipRight(
					session.push(OAuthSessionKey(state), oauthSessionTtl, { nonce, codeVerifier, provider, redirectUri }),
					Effect.map(
						Effect.promise(() => calculatePKCECodeChallenge(codeVerifier)),
						(code_challenge) =>
							buildAuthorizationUrl(config, {
								redirect_uri: redirectUri,
								scope: opts?.scopes ?? oauthScopes,
								state,
								nonce,
								code_challenge,
								code_challenge_method: 'S256',
								...(opts?.extras ?? {}),
							}),
					),
				);
			});

		const exchangeCode = (callbackUrl: URL) => {
			const state = callbackUrl.searchParams.get('state');
			if (!state) return Effect.fail(new OAuthError({ message: 'Missing state parameter in callback URL' }));
			return Effect.flatMap(
				session.pop<{ nonce: string; codeVerifier: string; provider: string; redirectUri?: string }>(OAuthSessionKey(state)),
				({ nonce, codeVerifier, provider, redirectUri }) =>
					Effect.flatMap(resolver.resolve(provider), ({ config, entry }) =>
						Effect.flatMap(
							Effect.tryPromise({
								try: () => authorizationCodeGrant(config, callbackUrl, { expectedState: state, expectedNonce: nonce, pkceCodeVerifier: codeVerifier }, { redirect_uri: redirectUri ?? entry.redirectUri }),
								catch: (e) =>
									e instanceof AuthorizationResponseError || e instanceof ResponseBodyError
										? new OAuthError({ cause: e, message: e.error_description || e.error })
										: new OAuthError({ cause: e, message: 'Token exchange failed' }),
							}),
							(tokens) => {
								const claimsRaw = tokens.claims() as Record<string, unknown> | undefined;
								if (!claimsRaw) return Effect.fail(new OAuthError({ message: 'No ID token claims returned' }));
								if (claimsRaw.email_verified === false) return Effect.fail(new OAuthError({ message: 'Email not verified by provider' }));
								return Effect.map(
									Effect.mapError(Schema.decodeUnknown(OAuthClaims)(claimsRaw), (e) => new OAuthError({ cause: e, message: 'Invalid ID token claims' })),
									(claims) =>
										({
											claims,
											provider,
											access_token: tokens.access_token,
											scopes: tokens.scope ?? oauthScopes,
											refresh_token: tokens.refresh_token,
											expires_at: tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : undefined,
										}) satisfies typeof OAuthResult.Type,
								);
							},
						),
					),
			);
		};

		/**
		 * Persist a signup payload behind a fresh UUIDv7 token. Caller sets the token in a cookie
		 * and the signup-completion handler retrieves the payload + creates the user + the OAuth account.
		 */
		const createSignupSession = (result: typeof OAuthResult.Type) =>
			Effect.tap(
				Effect.sync(() => Bun.randomUUIDv7()),
				(token) =>
					session.push(SignupKey(token), signupSessionTtl, {
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

		const createLinkingSession = (result: typeof OAuthResult.Type) => session.push(LinkingKey(result.claims.email), oidcLinkSessionTtl, result);

		/**
		 * Pop a parked linking session for `user.email` and persist the OAuth account against `user.sub`.
		 * Used after a returning user verifies via OTP and we need to link the previously-attempted OAuth account.
		 */
		const linkAccount = (user: AuthenticatedUser) =>
			Effect.flatMap(session.pop<typeof OAuthResult.Type>(LinkingKey(user.email)), (r) =>
				store.link({
					sub: user.sub,
					provider: r.provider,
					subject: r.claims.sub,
					email: r.claims.email,
					locale: r.claims.locale ?? null,
					access_token: r.access_token,
					refresh_token: r.refresh_token ?? null,
					scopes: r.scopes,
					token_expires: r.expires_at ?? null,
				}),
			);

		return {
			buildAuthUrl,
			exchangeCode,
			createSignupSession,
			createLinkingSession,
			linkAccount,
		};
	}),
	dependencies: [OAuthProviderResolver.Default, OAuthAccountStore.Default],
}) {}

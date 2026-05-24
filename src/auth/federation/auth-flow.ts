import { Cause, Context, Data, Effect, Layer, Schema } from 'effect';
import { SessionService } from '@polumeyv/lib/server';
import { redirect, type HttpStatusError } from '@polumeyv/lib/error';
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
import { UserSub } from '../../user/model';
import { Email } from '@polumeyv/lib/public/types';
import { OAuthProviderResolver } from './provider-resolver';
import { OAuthAccountStore } from './account-store';

/** Tagged error for the OIDC authorize-code flow (token exchange, ID-token claim validation, email verification). */
export class OAuthFlowError extends Data.TaggedError('OAuthFlowError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

const OAuthSessionKey = (state: string) => `oauth:${state}`;
export const LinkingKey = (email: string) => `link_oidc:${email}`;

/** Parked OAuth-flow state pushed to Redis under `OAuthSessionKey(state)` while the user is at the IdP, popped when they come back to the callback. */
interface OAuthFlowSession {
	readonly nonce: string;
	readonly code_verifier: string;
	readonly provider: string;
	readonly redirect_uri?: string;
}

export class OidcAuthFlowConfig extends Context.Service<
	OidcAuthFlowConfig,
	{
		/** TTL in seconds for PKCE OAuth sessions in Redis (default: 300 — 5 min). */
		readonly oauthSessionTtl: number;
		/** Space-separated OAuth scopes requested from the identity provider (default: 'openid email profile'). */
		readonly oauthScopes: string;
		/** TTL in seconds for parked signup payloads in Redis (default: 3 600 — 1 h). */
		readonly signupSessionTtl: number;
		/** TTL in seconds for OIDC account-linking sessions in Redis (default: 600 — 10 min). */
		readonly oidcLinkSessionTtl: number;
	}
>()('OidcAuthFlowConfig') {}

/**
 * OIDC sign-in / link / signup orchestration. Composes `OAuthProviderResolver`
 * for provider config + discovery, `SessionService` for ephemeral state (PKCE
 * params, signup payloads, linking payloads), and `OAuthAccountStore` for the
 * persistent OAuth account row.
 *
 * Persistent storage of `oidc_accounts` rows lives in `OAuthAccountStore`;
 * this module only orchestrates the flow.
 */
export class OidcAuthFlow extends Context.Service<OidcAuthFlow>()('OidcAuthFlow', {
	make: Effect.gen(function* () {
		const { oauthSessionTtl, oauthScopes } = yield* OidcAuthFlowConfig;
		const session = yield* SessionService;
		const resolver = yield* OAuthProviderResolver;
		const store = yield* OAuthAccountStore;

		/**
		 * Mints PKCE state, parks it in Redis under `OAuthSessionKey(state)`, builds the IdP's authorize URL, and fail-redirects (302) the user to it.
		 * Caller never sees the URL — this terminates the request via the lib `redirect` cause.
		 */
		const redirectToAuthUrl = (
			provider: string,
			{ scopes = oauthScopes, extras, redirect_uri: redirectOverride }: { scopes?: string; extras?: Record<string, string>; redirect_uri?: string } = {},
		) =>
			Effect.gen(function* () {
				const { config, entry } = yield* resolver.resolve(provider);
				const code_verifier = randomPKCECodeVerifier();
				const state = randomState();
				const nonce = randomNonce();
				const redirect_uri = redirectOverride ?? entry.redirectUri;
				yield* session.set(OAuthSessionKey(state), oauthSessionTtl, { nonce, code_verifier, provider, redirect_uri } satisfies OAuthFlowSession);
				const code_challenge = yield* Effect.promise(() => calculatePKCECodeChallenge(code_verifier));
				const url = buildAuthorizationUrl(config, { redirect_uri, scope: scopes, state, nonce, code_challenge, code_challenge_method: 'S256', ...extras });
				return yield* redirect(url.toString(), 302);
			});

		const exchangeCode = (callbackUrl: URL) =>
			Effect.gen(function* () {
				const state = callbackUrl.searchParams.get('state');
				if (!state) return yield* new Cause.IllegalArgumentError('Missing state parameter in callback URL');

				const { nonce, code_verifier, provider, redirect_uri } = yield* session.take<OAuthFlowSession>(OAuthSessionKey(state));
				const { config, entry } = yield* resolver.resolve(provider);

				const tokens = yield* Effect.tryPromise({
					try: () =>
						authorizationCodeGrant(
							config,
							callbackUrl,
							{ expectedState: state, expectedNonce: nonce, pkceCodeVerifier: code_verifier },
							{ redirect_uri: redirect_uri ?? entry.redirectUri },
						),
					catch: (e) =>
						new OAuthFlowError({
							cause: e,
							message: e instanceof AuthorizationResponseError || e instanceof ResponseBodyError ? e.error_description || e.error : 'Token exchange failed',
						}),
				});

				const claimsRaw = tokens.claims() as Record<string, unknown> | undefined;
				if (!claimsRaw) return yield* new OAuthFlowError({ message: 'No ID token claims returned' });
				if (claimsRaw.email_verified === false) return yield* new OAuthFlowError({ message: 'Email not verified by provider' });

				// Normalize the wire shape (provider may omit fields entirely) to the internal `string | null` shape so
				// downstream consumers don't each have to `?? null`. This is the single boundary where wire becomes storage shape.
				const normalizedClaims = {
					...claimsRaw,
					given_name: claimsRaw.given_name ?? null,
					family_name: claimsRaw.family_name ?? null,
					picture: claimsRaw.picture ?? null,
					locale: claimsRaw.locale ?? null,
				};
				return {
					claims: yield* Schema.decodeUnknownEffect(OAuthClaims)(normalizedClaims),
					provider,
					access_token: tokens.access_token,
					scopes: tokens.scope ?? oauthScopes,
					refresh_token: tokens.refresh_token ?? null,
					expires_at: tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : null,
				} satisfies typeof OAuthResult.Type;
			});

		/**
		 * Pop a parked linking session for `email` and persist the OAuth account against `sub`.
		 * Used after a returning user verifies via OTP and we need to link the previously-attempted OAuth account.
		 */
		const linkAccount = (sub: typeof UserSub.Type, email: typeof Email.Type) =>
			Effect.flatMap(session.take<typeof OAuthResult.Type>(LinkingKey(email)), (r) => store.link(sub, r));

		return {
			redirectToAuthUrl,
			exchangeCode,
			linkAccount,
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make).pipe(Layer.provide([OAuthProviderResolver.layer, OAuthAccountStore.layer]));
}

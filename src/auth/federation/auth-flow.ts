import { Cause, Context, Data, Effect, Layer, Schema } from 'effect';
import { SessionService } from '@polumeyv/lib/server';
import { type HttpStatusError } from '@polumeyv/lib/error';
import * as oauth from 'oauth4webapi';
import { GoogleClaims, OAuthResult } from './oidc.model';
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

/** Redis key for the parked PKCE/OAuth-flow state — written when the flow begins (auth app's `/oauth2/google` route) and popped here on callback. */
export const OAuthSessionKey = (state: string) => `oauth:${state}`;
export const LinkingKey = (email: string) => `link_oidc:${email}`;

/** Parked OAuth-flow state pushed to Redis under `OAuthSessionKey(state)` while the user is at the IdP, popped when they come back to the callback. */
export interface OAuthFlowSession {
	readonly nonce: string;
	readonly code_verifier: string;
	readonly provider: string;
}

export class OidcAuthFlowConfig extends Context.Service<
	OidcAuthFlowConfig,
	{
		/** Space-separated OAuth scopes requested from the identity provider (default: 'openid email profile'). */
		readonly oauthScopes: string;
	}
>()('OidcAuthFlowConfig') {}

/**
 * OIDC sign-in / link / signup orchestration. Composes `OAuthProviderResolver`
 * for provider config + discovery, `SessionService` for ephemeral state (PKCE
 * params, signup payloads, linking payloads), and `OAuthAccountStore` for the
 * persistent OAuth account row.
 *
 * Persistent storage of `oidc_accounts` rows lives in `OAuthAccountStore`; this
 * module only orchestrates the callback half. The begin half — mint PKCE state,
 * park it under `OAuthSessionKey`, redirect to the IdP — lives in the auth app's
 * `/oauth2/google` route, sharing `OAuthSessionKey`/`OAuthFlowSession` with `exchangeCode`.
 */
export class OidcAuthFlow extends Context.Service<OidcAuthFlow>()('OidcAuthFlow', {
	make: Effect.gen(function* () {
		const { oauthScopes } = yield* OidcAuthFlowConfig;
		const session = yield* SessionService;
		const resolver = yield* OAuthProviderResolver;
		const store = yield* OAuthAccountStore;

		const exchangeCode = (callbackUrl: URL) =>
			Effect.gen(function* () {
				const state = callbackUrl.searchParams.get('state');
				if (!state) return yield* new Cause.IllegalArgumentError('Missing state parameter in callback URL');

				const { nonce, code_verifier, provider } = yield* session.take<OAuthFlowSession>(OAuthSessionKey(state));
				const { as, client, clientAuth, redirectUri } = yield* resolver.resolve(provider);

				const tokens = yield* Effect.tryPromise({
					try: async () => {
						// Validate the callback params + bind the parked `state` (throws on an error redirect or state mismatch).
						const callbackParams = oauth.validateAuthResponse(as, client, callbackUrl, state);
						const res = await oauth.authorizationCodeGrantRequest(as, client, clientAuth, callbackParams, redirectUri, code_verifier);
						// Code flow: the id_token comes straight from the token endpoint over TLS, so its claims (iss/aud/exp/nonce)
						// are validated but the signature isn't required (OIDC Core §3.1.3.7) — no JWKS fetch needed.

						return await oauth.processAuthorizationCodeResponse(as, client, res, { expectedNonce: nonce, requireIdToken: true });
					},
					catch: (e) =>
						new OAuthFlowError({
							cause: e,
							message: e instanceof oauth.AuthorizationResponseError || e instanceof oauth.ResponseBodyError ? e.error_description || e.error : 'Token exchange failed',
						}),
				});
				const claimsRaw = oauth.getValidatedIdTokenClaims(tokens);
				if (!claimsRaw) return yield* new OAuthFlowError({ message: 'No ID token claims returned' });
				if (claimsRaw.email_verified === false) return yield* new OAuthFlowError({ message: 'Email not verified by provider' });

				// Claims stay exactly as the provider sends them — optional fields remain `string | undefined`.
				// Bun's SQL driver coerces `undefined` → `NULL` at the insert, so no normalization is needed here.
				return {
					claims: yield* Schema.decodeUnknownEffect(GoogleClaims)(claimsRaw),
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
			exchangeCode,
			linkAccount,
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make).pipe(Layer.provide([OAuthProviderResolver.layer, OAuthAccountStore.layer]));
}

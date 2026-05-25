import { Context, Data, Effect, Layer } from 'effect';
import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { HttpStatusError } from '@polumeyv/lib/error';

/**
 * Tagged error for downstream-app IdP client operations (discovery, token grant, refresh, revoke, access-token verify).
 * Surfaces as 500 — every operation here is a server-to-server call to *our* IdP, so a failure is an upstream/internal
 * fault, not an end-user auth problem. Consumers that gate on the *outcome* (e.g. the hooks' `.catch(() => null)` to
 * trigger a token refresh) don't read this status; it only matters when the error escapes to an HTTP response.
 */
export class IdpClientError extends Data.TaggedError('IdpClientError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 500 as const;
	}
}

/** Curried `catch`/`mapError` adapter: wraps any thrown value in an IdpClientError, preferring the Error's own message. */
const idpError = (fallback: string) => (cause: unknown) => new IdpClientError({ cause, message: cause instanceof Error ? cause.message : fallback });

export interface TokenResponse {
	access_token: string;
	refresh_token: string;
	expires_in: number;
	token_type: string;
	scope?: string;
}

const asTokenResponse = (t: { access_token: string; refresh_token?: string; expires_in?: number; token_type: string; scope?: string }): TokenResponse => ({
	access_token: t.access_token,
	refresh_token: t.refresh_token ?? '',
	expires_in: t.expires_in ?? 0,
	token_type: t.token_type,
	scope: t.scope,
});

/** Resolved configuration for the IdP client, injected into the service so discovery params (and the client itself) stay mockable. */
export interface IdpClientOptions {
	publicAuthUrl: string;
	clientId: string;
	clientSecret: string;
	redirectUri: string;
	/** Space-separated OAuth scopes requested at /authorize. */
	scope: string;
	/** Max-age in seconds for the tenant-side `pkce_ver` cookie. */
	pkceCookieMaxAge: number;
	/** Max-age in seconds for the tenant-side `access_token` cookie (matches IdP access TTL). */
	accessCookieMaxAge: number;
	/** Max-age in seconds for the tenant-side `refresh_token` cookie (matches IdP OAuth2 refresh TTL). */
	refreshCookieMaxAge: number;
}

// v4: Context.Service<Self, Shape>()(id) — replaces v3 Context.Tag(id)<Self, Shape>().
export class IdpClientConfig extends Context.Service<IdpClientConfig, IdpClientOptions>()('app/IdpClientConfig') {}

/**
 * Client for talking to *our* IdP (polumeyv-auth): token exchange, refresh, revoke, JWKS verify, authorize-URL.
 * This is the downstream-app side of the OAuth boundary — not to be confused with `OAuthProviderResolver`, which is the
 * auth app acting as a client of *external* IdPs like Google.
 *
 * Discovery runs **once at layer build** against `${publicAuthUrl}/.well-known/oauth-authorization-server`; a failure
 * fails the layer with a typed `IdpClientError` rather than being mis-reported on every later call. The resolved
 * `Configuration`, JWKS, and issuer are closed over by the returned methods.
 *
 * v4: Context.Service with `make` stores the constructor effect but does NOT auto-generate a layer — see `IdpClient.layer`.
 */
export class IdpClient extends Context.Service<IdpClient>()('app/IdpClient', {
	make: Effect.gen(function* () {
		const opts = yield* IdpClientConfig;
		const issuerUrl = new URL(opts.publicAuthUrl);

		// HTTPS is enforced by oauth4webapi; in local dev the IdP is plain http://localhost, so opt into insecure
		// requests for http URLs only — threaded into every request below. Prod (https) stays strict.
		const httpOpts = issuerUrl.protocol === 'http:' ? { [oauth.allowInsecureRequests]: true } : undefined;

		const { as, client, clientAuth } = yield* Effect.tryPromise({
			try: async () => {
				// RFC 8414 metadata at `${publicAuthUrl}/.well-known/oauth-authorization-server`; the response issuer is bound to `issuerUrl`.
				const res = await oauth.discoveryRequest(issuerUrl, { algorithm: 'oauth2', ...httpOpts });
				const as = await oauth.processDiscoveryResponse(issuerUrl, res);
				const client: oauth.Client = { client_id: opts.clientId };
				return { as, client, clientAuth: oauth.ClientSecretPost(opts.clientSecret) };
			},
			catch: idpError('IdP discovery failed'),
		});

		if (!as.authorization_endpoint) return yield* Effect.fail(new IdpClientError({ message: 'IdP discovery doc has no authorization_endpoint' }));
		if (!as.jwks_uri) return yield* Effect.fail(new IdpClientError({ message: 'IdP discovery doc has no jwks_uri' }));
		const authorizationEndpoint = as.authorization_endpoint;
		const jwks = createRemoteJWKSet(new URL(as.jwks_uri));
		const issuer = as.issuer;

		return {
			pkceCookieMaxAge: opts.pkceCookieMaxAge,
			accessCookieMaxAge: opts.accessCookieMaxAge,
			refreshCookieMaxAge: opts.refreshCookieMaxAge,

			/** Exchange an authorization code for tokens. `callbackUrl` is the IdP's redirect-back URL (carries `?code=…`). */
			exchangeCode: (callbackUrl: URL, codeVerifier: string) =>
				Effect.map(
					Effect.tryPromise({
						try: async () => {
							// No `state` is sent in this flow, so validateAuthResponse expects none; it still rejects an `?error=` redirect.
							const params = oauth.validateAuthResponse(as, client, callbackUrl);
							const res = await oauth.authorizationCodeGrantRequest(as, client, clientAuth, params, opts.redirectUri, codeVerifier, httpOpts);
							return await oauth.processAuthorizationCodeResponse(as, client, res);
						},
						catch: idpError('Token exchange failed'),
					}),
					asTokenResponse,
				),

			refreshTokens: (refreshToken: string | null | undefined) =>
				refreshToken
					? Effect.map(
							Effect.tryPromise({
								try: async () => {
									const res = await oauth.refreshTokenGrantRequest(as, client, clientAuth, refreshToken, httpOpts);
									return await oauth.processRefreshTokenResponse(as, client, res);
								},
								catch: idpError('Token refresh failed'),
							}),
							asTokenResponse,
						)
					: Effect.fail(new IdpClientError({ message: 'Missing refresh token' })),

			/** RFC 7009 token revocation — deletes the OAuth2 session on the auth server. */
			revoke: (token: string) =>
				Effect.tryPromise({
					try: async () => {
						const res = await oauth.revocationRequest(as, client, clientAuth, token, httpOpts);
						await oauth.processRevocationResponse(res);
					},
					catch: idpError('Revoke request failed'),
				}),

			/** Verify an OAuth2 access token against the IdP's discovered JWKS endpoint. Fails if missing, invalid, or within `bufferSeconds` of expiry (default 60s). */
			verifyAccessToken: <T extends JWTPayload = JWTPayload>(token: string | null | undefined, bufferSeconds = 60) =>
				Effect.andThen(
					Effect.mapError(Effect.fromNullishOr(token), () => new IdpClientError({ message: 'Missing access token' })),
					(t) =>
						Effect.map(
							Effect.tryPromise({
								try: () => jwtVerify(t, jwks, { issuer, requiredClaims: ['exp'], currentDate: new Date(Date.now() + bufferSeconds * 1000) }),
								catch: idpError('Access token verification failed'),
							}),
							({ payload }) => payload as T,
						),
				),

			generateAuthorizeUrl: () =>
				Effect.gen(function* () {
					const codeVerifier = oauth.generateRandomCodeVerifier();
					const code_challenge = yield* Effect.promise(() => oauth.calculatePKCECodeChallenge(codeVerifier));
					const url = new URL(authorizationEndpoint);
					for (const [k, v] of Object.entries({
						client_id: opts.clientId,
						response_type: 'code',
						redirect_uri: opts.redirectUri,
						scope: opts.scope,
						code_challenge,
						code_challenge_method: 'S256',
					}))
						url.searchParams.set(k, v);
					return { url: url.toString(), codeVerifier };
				}),
		};
	}),
}) {
	/** Primary layer (v4 convention): fills option defaults, provides them, and runs discovery once at build. */
	static layer = (opts: {
		publicAuthUrl: string;
		clientId: string;
		clientSecret: string;
		redirectUri: string;
		scope?: string;
		pkceCookieMaxAge?: number;
		accessCookieMaxAge?: number;
		refreshCookieMaxAge?: number;
	}) =>
		Layer.provide(
			Layer.effect(IdpClient, IdpClient.make),
			Layer.succeed(IdpClientConfig, {
				...opts,
				scope: opts.scope ?? 'profile email',
				pkceCookieMaxAge: opts.pkceCookieMaxAge ?? 600,
				accessCookieMaxAge: opts.accessCookieMaxAge ?? 900,
				refreshCookieMaxAge: opts.refreshCookieMaxAge ?? 7_776_000,
			}),
		);
}

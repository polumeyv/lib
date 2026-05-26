import { Context, Data, Effect, Layer, Schedule, SynchronizedRef } from 'effect';
import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { HttpStatusError } from '@polumeyv/lib/error';

/**
 * Tagged error for downstream-app IdP client operations. Surfaces as 500 — every operation is a server-to-server call
 * to *our* IdP, so a failure is an upstream/internal fault, not an end-user auth problem.
 */
export class IdpClientError extends Data.TaggedError('IdpClientError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 500 as const;
	}
}

/** Resolved configuration for the IdP client, injected into the service so discovery params (and the client itself) stay mockable. */
export interface IdpClientOptions {
	publicAuthUrl: URL;
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

export class IdpClientConfig extends Context.Service<IdpClientConfig, IdpClientOptions>()('app/IdpClientConfig') {}

/** Resolved IdP discovery state — AS metadata, client identity, JWKS, and issuer — cached after the first successful discovery. */
type ResolvedIdp = {
	as: Awaited<ReturnType<typeof oauth.processDiscoveryResponse>>;
	client: oauth.Client;
	clientAuth: ReturnType<typeof oauth.ClientSecretPost>;
	jwks: ReturnType<typeof createRemoteJWKSet>;
	issuer: string;
	authorizationEndpoint: string;
};

/**
 * Client for talking to *our* IdP (polumeyv-auth): token exchange, refresh, revoke, JWKS verify, authorize-URL.
 * This is the downstream-app side of the OAuth boundary — not to be confused with `OAuthProviderResolver`, which is the
 * auth app acting as a client of *external* IdPs like Google. Discovery is lazy and cached on success only — see `getResolved`.
 */
export class IdpClient extends Context.Service<IdpClient>()('app/IdpClient', {
	make: Effect.gen(function* () {
		const opts = yield* IdpClientConfig;

		// HTTPS is enforced by oauth4webapi; in local dev the IdP is plain http://localhost, so opt into insecure
		// requests for http URLs only — threaded into every request below. Prod (https) stays strict.
		const httpOpts = {
			headers: { origin: new URL(opts.redirectUri).origin },
			...(opts.publicAuthUrl.protocol === 'http:' ? { [oauth.allowInsecureRequests]: true } : {}),
		};

		// Resolve (and memoise) the AS metadata, JWKS, issuer, and authorize endpoint. Discovery is deferred to the
		// first call and cached on success only. Earlier this ran at layer build, so a failure was memoised into the
		// long-lived ManagedRuntime and 500'd every request until the process was restarted — fatal when auth + this
		// app restart together on one host during a deploy. `modifyEffect` gives single-flight (one discovery in
		// flight at a time); a failed discovery leaves the ref untouched, so the next request retries and the consumer
		// self-heals the moment the IdP is reachable again. The ~10s retry rides out a sub-blip within a single call.
		const cache = yield* SynchronizedRef.make<ResolvedIdp | undefined>(undefined);
		const getResolved = SynchronizedRef.modifyEffect(cache, (cur) =>
			cur
				? Effect.succeed([cur, cur] as const)
				: Effect.gen(function* () {
						// processDiscoveryResponse binds the response issuer to `publicAuthUrl`.
						const as = yield* Effect.tryPromise({
							try: () => oauth.discoveryRequest(opts.publicAuthUrl, { algorithm: 'oauth2', ...httpOpts }).then((res) => oauth.processDiscoveryResponse(opts.publicAuthUrl, res)),
							catch: (cause) => new IdpClientError({ cause, message: cause instanceof Error ? cause.message : 'IdP discovery failed' }),
						}).pipe(Effect.retry(Schedule.both(Schedule.exponential('300 millis'), Schedule.recurs(6))));

						if (!as.authorization_endpoint) return yield* new IdpClientError({ message: 'IdP discovery doc has no authorization_endpoint' });
						if (!as.jwks_uri) return yield* new IdpClientError({ message: 'IdP discovery doc has no jwks_uri' });

						const resolved: ResolvedIdp = {
							as,
							client: { client_id: opts.clientId } as oauth.Client,
							clientAuth: oauth.ClientSecretPost(opts.clientSecret),
							jwks: createRemoteJWKSet(new URL(as.jwks_uri)),
							issuer: as.issuer,
							authorizationEndpoint: as.authorization_endpoint,
						};
						return [resolved, resolved] as const;
					}),
		);

		return {
			pkceCookieMaxAge: opts.pkceCookieMaxAge,
			accessCookieMaxAge: opts.accessCookieMaxAge,
			refreshCookieMaxAge: opts.refreshCookieMaxAge,

			/** Exchange an authorization code for tokens. `callbackUrl` is the IdP's redirect-back URL (carries `?code=…`). */
			exchangeCode: (callbackUrl: URL, codeVerifier: string) =>
				Effect.flatMap(getResolved, ({ as, client, clientAuth }) =>
					Effect.tryPromise({
						try: async () => {
							// No `state` is sent in this flow, so validateAuthResponse expects none; it still rejects an `?error=` redirect.
							const params = oauth.validateAuthResponse(as, client, callbackUrl);
							const res = await oauth.authorizationCodeGrantRequest(as, client, clientAuth, params, opts.redirectUri, codeVerifier, httpOpts);
							// our IdP issues both tokens on every grant, so a missing refresh_token is a real fault, not a default-to-'' case
							const tokens = await oauth.processAuthorizationCodeResponse(as, client, res);
							if (!tokens.refresh_token) throw new Error('IdP token response is missing refresh_token');
							return { access_token: tokens.access_token, refresh_token: tokens.refresh_token };
						},
						catch: (cause) => new IdpClientError({ cause, message: cause instanceof Error ? cause.message : 'Token exchange failed' }),
					}),
				),

			refreshTokens: (refreshToken: string | null | undefined) =>
				Effect.andThen(Effect.fromNullishOr(refreshToken), (rt) =>
					Effect.flatMap(getResolved, ({ as, client, clientAuth }) =>
						Effect.tryPromise({
							try: async () => {
								const tokens = await oauth
									.refreshTokenGrantRequest(as, client, clientAuth, rt, httpOpts)
									.then((res) => oauth.processRefreshTokenResponse(as, client, res));
								if (!tokens.refresh_token) throw new Error('IdP token response is missing refresh_token');
								return { access_token: tokens.access_token, refresh_token: tokens.refresh_token };
							},
							catch: (cause) => new IdpClientError({ cause, message: cause instanceof Error ? cause.message : 'Token refresh failed' }),
						}),
					),
				),
			/** RFC 7009 token revocation — deletes the OAuth2 session on the auth server. */
			revoke: (token: string) =>
				Effect.flatMap(getResolved, ({ as, client, clientAuth }) =>
					Effect.tryPromise({
						try: () => oauth.revocationRequest(as, client, clientAuth, token, httpOpts).then(oauth.processRevocationResponse),
						catch: (cause) => new IdpClientError({ cause, message: cause instanceof Error ? cause.message : 'Revoke request failed' }),
					}),
				),

			/** Verify an OAuth2 access token against the IdP's discovered JWKS endpoint. Fails if missing, invalid, or within `bufferSeconds` of expiry (default 60s). */
			verifyAccessToken: <T extends JWTPayload = JWTPayload>(token: string | null | undefined, bufferSeconds = 60) =>
				Effect.andThen(
					Effect.mapError(Effect.fromNullishOr(token), () => new IdpClientError({ message: 'Missing access token' })),
					(t) =>
						Effect.map(
							Effect.flatMap(getResolved, ({ jwks, issuer }) =>
								Effect.tryPromise({
									try: () => jwtVerify(t, jwks, { issuer, requiredClaims: ['exp'], currentDate: new Date(Date.now() + bufferSeconds * 1000) }),
									catch: (cause) => new IdpClientError({ cause, message: cause instanceof Error ? cause.message : 'Access token verification failed' }),
								}),
							),
							({ payload }) => payload as T,
						),
				),

			generateAuthorizeUrl: () =>
				Effect.gen(function* () {
					const { authorizationEndpoint } = yield* getResolved;
					const codeVerifier = crypto.getRandomValues(new Uint8Array(32)).toBase64({ alphabet: 'base64url', omitPadding: true });
					const code_challenge = new Bun.CryptoHasher('sha256').update(codeVerifier).digest('base64url');
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
	/** Primary layer (v4 convention): fills option defaults and provides them. Discovery is deferred to first use (see `make`). */
	static layer = (opts: Pick<IdpClientOptions, 'publicAuthUrl' | 'clientId' | 'clientSecret' | 'redirectUri'> & Partial<IdpClientOptions>) =>
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

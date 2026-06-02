import { Context, Data, Effect, Layer, Option, Result, Schedule, SynchronizedRef, Cause } from 'effect';
import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, decodeJwt, type JWTPayload } from 'jose';
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
	// Session side-effects, supplied by the consuming app so it owns cookie names/options/max-ages. The client calls
	// these to persist the outcome of an auth flow; they run per-request (define them via SvelteKit's `getRequestEvent`).
	setAccessToken: (token: string) => void;
	setRefreshToken: (token: string) => void;
	deleteAccessToken: () => void;
	deleteRefreshToken: () => void;
	setPkceVerifier: (verifier: string) => void;
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
 * auth app acting as a client of *external* IdPs like Google. Discovery is lazy + self-healing at runtime (see `getResolved`),
 * and validated once at boot via the `ready` probe so a broken IdP fails startup instead of 500'ing requests.
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

		// Resolve (and memoise) the AS metadata, JWKS, issuer, and authorize endpoint. Discovery is cached on success
		// only and is NOT done at layer build: doing so memoised a failure into the long-lived ManagedRuntime and 500'd
		// every request until restart — fatal when auth + this app restart together on one host during a deploy.
		// `modifyEffect` gives single-flight (one discovery in flight at a time); a failed discovery leaves the ref
		// untouched, so the next request retries and the consumer self-heals the moment the IdP is reachable again. The
		// ~10s retry rides out a sub-blip within a single call. For fail-fast on misconfig, consumers force this once at
		// boot via the `ready` probe (their SvelteKit `init` hook) — a failed boot crashes and the supervisor restarts
		// it, instead of serving a running process that 500s forever.
		const cache = yield* SynchronizedRef.make<ResolvedIdp | undefined>(undefined);
		const getResolved = SynchronizedRef.modifyEffect(cache, (cur) =>
			cur
				? Effect.succeed([cur, cur] as const)
				: Effect.gen(function* () {
						// processDiscoveryResponse binds the response issuer to `publicAuthUrl`.
						const as = yield* Effect.tryPromise({
							try: () =>
								oauth.discoveryRequest(opts.publicAuthUrl, { algorithm: 'oauth2', ...httpOpts }).then((res) => oauth.processDiscoveryResponse(opts.publicAuthUrl, res)),
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

		/** Exchange an authorization code for tokens. `callbackUrl` is the IdP's redirect-back URL (carries `?code=…`). */
		const exchangeCode = (callbackUrl: URL, codeVerifier: string) =>
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
			);

		// Returns the new tokens plus the access token's decoded `claims` — it came straight from the token endpoint over
		// TLS, so we decode rather than re-verify (see `decodeAccessToken`), saving the caller a redundant JWKS check.
		const refreshTokens = <T extends JWTPayload = JWTPayload>(refreshToken: string | undefined) =>
			Effect.andThen(Effect.fromNullishOr(refreshToken), (rt) =>
				Effect.flatMap(getResolved, ({ as, client, clientAuth }) =>
					Effect.tryPromise({
						try: async () =>
							oauth
								.refreshTokenGrantRequest(as, client, clientAuth, rt, httpOpts)
								.then((res) => oauth.processRefreshTokenResponse(as, client, res))
								.then((t) => {
									if (!t.refresh_token) throw new Error('IdP token response is missing refresh_token');
									return { access_token: t.access_token, refresh_token: t.refresh_token, claims: decodeJwt(t.access_token) as T };
								}),

						catch: () => new Cause.NoSuchElementError(),
					}),
				),
			).pipe(Effect.catchNoSuchElement);

		/** RFC 7009 token revocation — deletes the OAuth2 session on the auth server. */
		const revoke = (token: string) =>
			Effect.flatMap(getResolved, ({ as, client, clientAuth }) =>
				Effect.tryPromise({
					try: () => oauth.revocationRequest(as, client, clientAuth, token, httpOpts).then(oauth.processRevocationResponse),
					catch: (cause) => new IdpClientError({ cause, message: cause instanceof Error ? cause.message : 'Revoke request failed' }),
				}),
			);

		/**
		 * Decode (WITHOUT signature verification) the payload of an access token we just received over a direct TLS call
		 * to the IdP's token endpoint (i.e. from `exchangeCode` or `refreshTokens`). Safe per RFC 6749 (access tokens are
		 * opaque to the client) and OIDC Core §3.1.3.7: a token taken straight from the token endpoint over TLS may skip
		 * the signature check, since TLS already authenticates the issuer. Use `verifyAccessToken` for tokens that arrive
		 * by any *other* means (e.g. a browser cookie), which are untrusted and must be signature-verified.
		 */
		const decodeAccessToken = <T extends JWTPayload = JWTPayload>(token: string): T => decodeJwt(token) as T;

		/** Verify an OAuth2 access token against the IdP's discovered JWKS endpoint. Returns None for a missing token; errors for an invalid one. Use only for tokens from untrusted sources (cookies). */
		const verifyAccessToken = <T extends JWTPayload = JWTPayload>(token: string | null | undefined) =>
			Effect.andThen(Effect.fromNullishOr(token), (t) =>
				Effect.flatMap(getResolved, ({ jwks, issuer }) =>
					Effect.tryPromise({
						try: () => jwtVerify(t, jwks, { issuer, requiredClaims: ['exp'] }).then(({ payload }) => payload as T),
						catch: (cause) => new IdpClientError({ cause, message: cause instanceof Error ? cause.message : 'Access token verification failed' }),
					}),
				),
			).pipe(Effect.catchNoSuchElement);

		const generateAuthorizeUrl = () =>
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
			});

		/**
		 * End-to-end request authentication, driving the session cookies through the configured callbacks:
		 *   1–2. valid access token → `Result.succeed(user)`.
		 *   3–4. else refresh succeeds → write the new token cookies, `Result.succeed(user)` from the decoded refresh claims.
		 *   5.   else → clear the token cookies, plant a PKCE verifier, and return `Result.fail(authorizeUrl)` for the caller to redirect to.
		 * A present-but-invalid access token errors inside `verifyAccessToken`; we fold it to None so "no usable token" is one case.
		 */
		const authenticate = <T extends JWTPayload = JWTPayload>(accessToken: string | undefined, refreshToken: string | undefined) =>
			Effect.gen(function* () {
				const verified = yield* verifyAccessToken<T>(accessToken).pipe(Effect.orElseSucceed(() => Option.none<T>()));
				if (Option.isSome(verified)) return Result.succeed(verified.value);

				const refreshed = yield* refreshTokens<T>(refreshToken);
				if (Option.isSome(refreshed)) {
					opts.setAccessToken(refreshed.value.access_token);
					opts.setRefreshToken(refreshed.value.refresh_token);
					return Result.succeed(refreshed.value.claims);
				}

				const { url, codeVerifier } = yield* generateAuthorizeUrl();
				opts.deleteAccessToken();
				opts.deleteRefreshToken();
				opts.setPkceVerifier(codeVerifier);
				return Result.fail(url);
			});

		return {
			/** Startup probe: forces discovery once (warming the cache) so a misconfigured/unreachable IdP fails boot. Run from the consumer's `init` hook. */
			ready: Effect.asVoid(getResolved),
			exchangeCode,
			refreshTokens,
			revoke,
			decodeAccessToken,
			verifyAccessToken,
			generateAuthorizeUrl,
			authenticate,
		};
	}),
}) {
	/** Primary layer (v4 convention): the app supplies discovery params + the session-cookie callbacks; `scope` defaults. Discovery is lazy; consumers call `ready` at boot to fail-fast (see `make`). */
	static layer = (opts: Omit<IdpClientOptions, 'scope'> & { scope?: string }) =>
		Layer.provide(Layer.effect(IdpClient, IdpClient.make), Layer.succeed(IdpClientConfig, { ...opts, scope: opts.scope ?? 'profile email' }));
}

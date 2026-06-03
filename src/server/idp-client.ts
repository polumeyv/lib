import { Context, Data, Effect, Exit, Layer, Option, Result, Schedule, SynchronizedRef, Cause } from 'effect';
import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, decodeJwt, type JWTPayload } from 'jose';
import type { HttpStatusError } from '@polumeyv/lib/error';
import { NoSuchElementError } from 'effect/Cause';

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

		/**
		 * Exchange an authorization code for tokens, persist them through the session-cookie callbacks, and return the
		 * access token's decoded claims. `callbackUrl` is the IdP's redirect-back URL (carries `?code=…`). The token came
		 * straight from the IdP token endpoint over TLS, so we decode rather than re-verify — safe per RFC 6749 / OIDC
		 * Core §3.1.3.7 (TLS authenticates the issuer). Tokens that arrive any *other* way (e.g. a cookie) are verified
		 * against the JWKS inside `authenticate`.
		 */
		const exchangeCode = <T extends JWTPayload = JWTPayload>(callbackUrl: URL, codeVerifier: string) =>
			Effect.flatMap(getResolved, ({ as, client, clientAuth }) =>
				Effect.tryPromise({
					try: () =>
						((params) =>
							oauth
								.authorizationCodeGrantRequest(as, client, clientAuth, params, opts.redirectUri, codeVerifier, httpOpts)
								.then((res) => oauth.processAuthorizationCodeResponse(as, client, res))
								.then((tokens) => {
									// our IdP issues both tokens on every grant, so a missing refresh_token is a real fault, not a default-to-'' case
									if (!tokens.refresh_token) throw new Error('IdP token response is missing refresh_token');
									opts.setAccessToken(tokens.access_token);
									opts.setRefreshToken(tokens.refresh_token);
									return decodeJwt(tokens.access_token) as T;
								}))(oauth.validateAuthResponse(as, client, callbackUrl)),

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

						catch: () => new NoSuchElementError(),
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
		 * End-to-end request authentication, driving the session cookies through the configured callbacks:
		 *   1–2. valid access token → `Result.succeed(user)`.
		 *   3–4. else refresh succeeds → write the new token cookies, `Result.succeed(user)` from the decoded refresh claims.
		 *   5.   else → clear the token cookies, plant a PKCE verifier, and return `Result.fail(authorizeUrl)` for the caller to redirect to.
		 * A present-but-invalid access token errors inside `verifyAccessToken`; we fold it to None so "no usable token" is one case.
		 */
		const authenticate = <T extends JWTPayload = JWTPayload>(accessToken: string | undefined, refreshToken: string | undefined) =>
			Effect.gen(function* () {
				// `verifyAccessToken` already returns None for a missing/invalid token; a resolver (discovery) failure
				// stays in the error channel and propagates as a real 500 — it must NOT be folded to "no token" here.
				const verified = yield* Effect.andThen(Effect.fromNullishOr(accessToken), (t) =>
					Effect.flatMap(getResolved, ({ jwks, issuer }) =>
						Effect.tryPromise({
							try: () => jwtVerify(t, jwks, { issuer, requiredClaims: ['exp'] }).then(({ payload }) => payload as T),
							catch: (cause) => new NoSuchElementError(`Access token verification failed: ${cause}`),
						}),
					),
				).pipe(Effect.catchNoSuchElement);

				if (Option.isSome(verified)) return Result.succeed(verified.value);

				const refreshed = yield* refreshTokens<T>(refreshToken);
				if (Option.isSome(refreshed)) {
					opts.setAccessToken(refreshed.value.access_token);
					opts.setRefreshToken(refreshed.value.refresh_token);
					return Result.succeed(refreshed.value.claims);
				}

				// No usable token → build a fresh PKCE authorize URL, clear the token cookies, plant the verifier.
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
				opts.deleteAccessToken();
				opts.deleteRefreshToken();
				opts.setPkceVerifier(codeVerifier);
				return Result.fail(url.toString());
			});

		return {
			/** Startup probe: forces discovery once (warming the cache) so a misconfigured/unreachable IdP fails boot. Run from the consumer's `init` hook. */
			ready: Effect.asVoid(getResolved),
			exchangeCode,
			revoke,
			authenticate,
			opts,
		};
	}),
}) {
	/** Primary layer (v4 convention): the app supplies discovery params + the session-cookie callbacks; `scope` defaults. Discovery is lazy; consumers call `ready` at boot to fail-fast (see `make`). */
	static layer = (opts: Omit<IdpClientOptions, 'scope'> & { scope?: string }) =>
		Layer.provide(Layer.effect(IdpClient, IdpClient.make), Layer.succeed(IdpClientConfig, { ...opts, scope: opts.scope ?? 'profile email' }));
}

/**
 * Boot probe for a SvelteKit `init` hook: force IdP discovery once and HARD-CRASH the process if it fails,
 * so a misconfigured/unreachable IdP refuses startup (the supervisor restarts) instead of the server coming
 * up and 500'ing every request. A rejected `init` promise is only logged by SvelteKit — not fatal — so we
 * `process.exit(1)` explicitly. Runtime self-heal is unaffected: the lazy cache still retries per request.
 *
 * @example export const init: ServerInit = () => ensureIdpReady((e) => AppRuntime.runPromiseExit(e));
 */
export const ensureIdpReady = async (probe: Promise<Exit.Exit<unknown, unknown>>): Promise<void> => {
	const exit = await probe;
	if (Exit.isFailure(exit)) {
		console.error('[IdpClient] discovery probe failed at boot — refusing to start:\n' + Cause.pretty(exit.cause));
		process.exit(1);
	}
};

/** The boot probe effect — force IdP discovery once (warming the in-memory cache). Run it through the app runtime: `ensureIdpReady(AppRuntime.runPromiseExit(idpReadyProbe))`. */
export const idpReadyProbe = Effect.andThen(IdpClient, (idp) => idp.ready);

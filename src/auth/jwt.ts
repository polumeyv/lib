import { type JWTPayload, type JWK, SignJWT, jwtVerify, importJWK, decodeJwt } from 'jose';
import { Context, Data, Effect, Layer, Schema } from 'effect';
import { SessionService } from '@polumeyv/lib/server';
import type { HttpStatusError } from '@polumeyv/lib/error';

import { AuthPayload } from '../user/model';

/** Tagged error for JWT operations (sign, verify, revoke, key import). */
export class JwtError extends Data.TaggedError('JwtError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

const keyUtil = (key: JWK) =>
	Effect.tryPromise({
		try: () => importJWK(key, 'EdDSA') as Promise<CryptoKey>,
		catch: (e) => new JwtError({ cause: e, message: 'Failed to import jwk keys in JWT auth service' }),
	});

const extractOAuth2Sid = (payload: JWTPayload): Effect.Effect<string, JwtError> =>
	payload.type === 'refresh' && typeof payload.sid === 'string' ? Effect.succeed(payload.sid) : Effect.fail(new JwtError({ message: 'Invalid refresh token' }));

export class JwtConfig extends Context.Service<
	JwtConfig,
	{
		readonly privateJwk: JWK;
		readonly publicJwk: JWK;
		readonly issuer: string;
		/** Access token JWT lifetime in seconds (default: 900 — 15 min). */
		readonly accessTtl?: number;
		/** Refresh token JWT lifetime in seconds (default: 604 800 — 7 days). */
		readonly refreshTtl?: number;
	}
>()('JwtConfig') {}

/** JWT authentication service — issues, verifies, and revokes access/refresh token pairs. */
export class Jwt extends Context.Service<Jwt>()('Jwt', {
	make: Effect.gen(function* () {
		const { privateJwk, publicJwk, issuer, accessTtl = 900, refreshTtl = 604_800 } = yield* JwtConfig;
		const session = yield* SessionService;
		const privateKey = yield* keyUtil(privateJwk);
		const publicKey = yield* keyUtil(publicJwk);

		const andThenNonNull = <A, B, E, R>(value: A, f: (a: NonNullable<A>) => Effect.Effect<B, E, R>) => Effect.andThen(Effect.fromNullishOr(value), f);

		const sign = (payload: JWTPayload, ttl: number, opts?: { subject?: string; audience?: string }) =>
			Effect.tryPromise({
				try: () =>
					((jwt) => (opts?.subject && jwt.setSubject(opts.subject), opts?.audience && jwt.setAudience(opts.audience), jwt.sign(privateKey)))(
						new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA' }).setIssuer(issuer).setIssuedAt().setExpirationTime(`${ttl}s`),
					),
				catch: (e) => new JwtError({ cause: e }),
			});

		/** Verify a JWT's signature + issuer (and optional audience) with our public key; map any failure to JwtError. */
		const verifyJwt = (token: string, opts?: { audience?: string }) =>
			Effect.tryPromise({ try: () => jwtVerify(token, publicKey, { issuer, ...opts }), catch: (e) => new JwtError({ cause: e }) });

		const verifyAccess = (token: string | undefined) =>
			Effect.gen(function* () {
				const { payload } = yield* andThenNonNull(token, (t) => verifyJwt(t, { audience: `${issuer}/app` }));
				const auth = yield* Schema.decodeUnknownEffect(AuthPayload)(payload).pipe(Effect.mapError((e) => new JwtError({ cause: e, message: 'Invalid JWT payload' })));
				const merged: AuthPayload = { ...payload, ...auth };
				return merged;
			});

		const signOAuth2 = (payload: JWTPayload, ttl: number, opts?: { subject?: string; audience?: string }) => sign(payload, ttl, opts);
		const signAccess = (payload: AuthPayload) => sign(payload, accessTtl, { audience: `${issuer}/app` });

		// Refresh token = opaque UUIDv7. Redis is the sole source of truth for validity
		// and carries the full AuthPayload so we can mint a new access JWT without a DB hit.
		// Per OAuth 2.1 §1.3.2: "an identifier used to retrieve the authorization information".
		const mintTokenPair = (payload: AuthPayload) =>
			((refresh) => Effect.map(Effect.tap(signAccess(payload), session.set(`refresh:${refresh}`, refreshTtl, payload)), (access) => ({ access, refresh })))(
				Bun.randomUUIDv7(),
			);

		return {
			accessTtl,

			refreshTtl,

			verifyAccess,

			mintTokenPair,

			/**
			 * Rotation + passive reuse detection via atomic POP: replaying an already-used
			 * Pass in cookie value directly, method will handle if 'undefined' with `NoSuchElementError`
			 * token finds nothing in Redis and fails. No JWT decode, no signature check.
			 */
			verifyRefresh: (token: string | undefined) =>
				Effect.gen(function* () {
					const payload = yield* andThenNonNull(token, (t) => session.take<AuthPayload>(`refresh:${t}`));
					const tokens = yield* mintTokenPair(payload);
					return { tokens, payload };
				}),

			revokeRefresh: (token: string) => session.delete(`refresh:${token}`),

			/** Sign OAuth2 token pair for consumer apps (session-based refresh, no JTI rotation). TTLs supplied by caller (typically OAuth2Service).
			 *  The refresh token is bound to `clientId` via its `aud` claim so verifyOAuth2Refresh rejects a token replayed by
			 *  a different client at signature-verify time — before any session is read or deleted. */
			signOAuth2Tokens: (payload: AuthPayload, sid: string, clientId: string, extraClaims?: Record<string, unknown>) =>
				Effect.all({
					access_token: signOAuth2({ ...payload, ...extraClaims }, accessTtl, { subject: payload.sub }),
					refresh_token: signOAuth2({ type: 'refresh', sid }, refreshTtl, { audience: clientId }),
				}),

			verifyOAuth2Refresh: (token: string | null, clientId: string) =>
				Effect.andThen(
					andThenNonNull(token, (t) => verifyJwt(t, { audience: clientId })),
					({ payload }) => extractOAuth2Sid(payload),
				),

			decodeOAuth2RefreshSid: (token: string | null) =>
				Effect.fromNullishOr(token).pipe(
					Effect.andThen((t) => Effect.try({ try: () => decodeJwt(t), catch: (e: any) => new JwtError({ message: e ?? 'Invalid refresh token' }) })),
					Effect.andThen(extractOAuth2Sid),
				),
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make).pipe(Layer.provide(SessionService.layer));
}

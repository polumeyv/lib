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

		const verifyAccess = (token: string) =>
			Effect.andThen(
				verifyJwt(token, { audience: `${issuer}/app` }),
				({ payload }) =>
					Effect.mapError(
						Effect.map(Schema.decodeUnknownEffect(AuthPayload)(payload), (auth): AuthPayload => ({ ...payload, ...auth })),
						(e) => new JwtError({ cause: e, message: 'Invalid JWT payload' }),
					),
			);

		const signOAuth2 = (payload: JWTPayload, ttl: number, subject?: string) => sign(payload, ttl, { subject });
		const signAccess = (payload: AuthPayload) => sign(payload, accessTtl, { audience: `${issuer}/app` });

		// Refresh token = opaque UUIDv7. Redis is the sole source of truth for validity
		// and carries the full AuthPayload so we can mint a new access JWT without a DB hit.
		// Per OAuth 2.1 §1.3.2: "an identifier used to retrieve the authorization information".
		const mintTokenPair = (payload: AuthPayload) =>
			Effect.gen(function* () {
				const refresh = Bun.randomUUIDv7();
				const access = yield* signAccess(payload);
				yield* session.set(`refresh:${refresh}`, refreshTtl, payload);
				yield* Effect.logInfo(`tokens created for ${payload.sub} refresh=${refresh}`);
				return { access, refresh };
			});
		return {
			accessTtl,

			refreshTtl,

			verifyAccess,

			mintTokenPair,

			// Rotation + passive reuse detection via atomic POP: replaying an already-used
			// token finds nothing in Redis and fails. No JWT decode, no signature check.
			verifyRefresh: (token: string) => Effect.flatMap(session.take<AuthPayload>(`refresh:${token}`), mintTokenPair),

			revokeRefresh: (token: string) => session.delete(`refresh:${token}`),

			/** Sign OAuth2 token pair for consumer apps (session-based refresh, no JTI rotation). TTLs supplied by caller (typically OAuth2Service). */
			signOAuth2Tokens: (payload: AuthPayload, sid: string, extraClaims?: Record<string, unknown>) =>
				Effect.all({
					access_token: signOAuth2({ ...payload, ...extraClaims }, accessTtl, payload.sub),
					refresh_token: signOAuth2({ type: 'refresh', sid }, refreshTtl),
				}),

			verifyOAuth2Refresh: (token: string) =>
				Effect.andThen(verifyJwt(token), ({ payload }) => extractOAuth2Sid(payload)),

			decodeOAuth2RefreshSid: (token: string) =>
				Effect.andThen(Effect.try({ try: () => decodeJwt(token), catch: (e: any) => new JwtError({ message: e ?? 'Invalid refresh token' }) }), extractOAuth2Sid),
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make).pipe(Layer.provide(SessionService.layer));
}

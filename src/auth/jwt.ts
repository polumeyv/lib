import { type JWTPayload, type JWK, SignJWT, jwtVerify, importJWK, decodeJwt } from 'jose';
import { Context, Effect, Schema } from 'effect';
import { SessionService } from '@polumeyv/lib/server';

import { AuthPayload } from './model';
import { JwtError } from './errors';

const keyUtil = (key: JWK) =>
	Effect.tryPromise({
		try: () => importJWK(key, 'EdDSA') as Promise<CryptoKey>,
		catch: (e) => new JwtError({ cause: e, message: 'Failed to import jwk keys in JWT auth service' }),
	});

const extractOAuth2Sid = (payload: JWTPayload): Effect.Effect<string, JwtError> =>
	payload.type === 'refresh' && typeof payload.sid === 'string' ? Effect.succeed(payload.sid) : Effect.fail(new JwtError({ message: 'Invalid refresh token' }));

export class JwtConfig extends Context.Tag('JwtConfig')<
	JwtConfig,
	{
		readonly privateJwk: JWK;
		readonly publicJwk: JWK;
		readonly issuer: string;
		/** Access token JWT lifetime in seconds (default: 900 — 15 min). */
		readonly accessTtl: number;
		/** Refresh token JWT lifetime in seconds (default: 604 800 — 7 days). */
		readonly refreshTtl: number;
	}
>() {}

/** JWT authentication service — issues, verifies, and revokes access/refresh token pairs. */
export class Jwt extends Effect.Service<Jwt>()('Jwt', {
	effect: Effect.gen(function* () {
		const { privateJwk, publicJwk, issuer, accessTtl, refreshTtl } = yield* JwtConfig;
		const session = yield* SessionService;
		const privateKey = yield* keyUtil(privateJwk);
		const publicKey = yield* keyUtil(publicJwk);

		const signAccess = (payload: AuthPayload) =>
			Effect.tryPromise({
				try: () =>
					new SignJWT(payload)
						.setProtectedHeader({ alg: 'EdDSA' })
						.setIssuer(issuer)
						.setAudience(`${issuer}/app`)
						.setIssuedAt()
						.setExpirationTime(`${accessTtl}s`)
						.sign(privateKey),
				catch: (e) => new JwtError({ cause: e }),
			});

		const verifyAccess = (token: string | undefined) =>
			Effect.andThen(
				Effect.andThen(Effect.fromNullable(token), (t) =>
					Effect.tryPromise({ try: () => jwtVerify(t, publicKey, { issuer, audience: `${issuer}/app` }), catch: (e) => new JwtError({ cause: e }) }),
				),
				({ payload }) =>
					Effect.mapError(
						Effect.map(Schema.decodeUnknown(AuthPayload)(payload), (auth): AuthPayload => ({ ...payload, ...auth })),
						(e) => new JwtError({ cause: e, message: 'Invalid JWT payload' }),
					),
			);

		const signOAuth2 = (payload: JWTPayload, ttl: number, subject?: string) =>
			Effect.tryPromise({
				try: () => {
					const jwt = new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA' }).setIssuer(issuer).setIssuedAt().setExpirationTime(`${ttl}s`);
					if (subject) jwt.setSubject(subject);
					return jwt.sign(privateKey);
				},
				catch: (e) => new JwtError({ cause: e }),
			});

		// Refresh token = opaque UUIDv7. Redis is the sole source of truth for validity
		// and carries the full AuthPayload so we can mint a new access JWT without a DB hit.
		// Per OAuth 2.1 §1.3.2: "an identifier used to retrieve the authorization information".
		const mintTokenPair = (payload: AuthPayload) =>
			Effect.andThen(
				Effect.sync(() => Bun.randomUUIDv7()),
				(refresh) => Effect.map(Effect.zip(signAccess(payload), session.push(`refresh:${refresh}`, refreshTtl, payload)), ([access]) => ({ access, refresh })),
			);

		return {
			verifyAccess,

			createTokens: (payload: AuthPayload) =>
				Effect.tap(mintTokenPair(payload), ({ refresh }) => Effect.logInfo(`[jwt] tokens created for ${payload.sub} refresh=${refresh}`)),

			// Rotation + passive reuse detection via atomic POP: replaying an already-used
			// token finds nothing in Redis and fails. No JWT decode, no signature check.
			verifyRefresh: (token: string | undefined) =>
				Effect.andThen(Effect.fromNullable(token), (t) =>
					session.pop<AuthPayload>(`refresh:${t}`).pipe(
						Effect.tapError(() => Effect.logWarning(`[jwt] refresh token rejected (revoked/expired/replayed) token=${t}`)),
						Effect.andThen((payload) =>
							mintTokenPair(payload).pipe(
								Effect.tap(({ refresh }) => Effect.logInfo(`[jwt] tokens refreshed for ${payload.sub} new_refresh=${refresh}`)),
								Effect.map((pair) => ({ ...pair, payload })),
							),
						),
					),
				),

			revokeRefresh: (token: string) => Effect.tap(session.delete(`refresh:${token}`), () => Effect.logInfo(`[jwt] refresh token revoked (logout) token=${token}`)),

			/** Sign OAuth2 token pair for consumer apps (session-based refresh, no JTI rotation). TTLs supplied by caller (typically OAuth2Service). */
			signOAuth2Tokens: (payload: AuthPayload, sid: string, accessTtl: number, refreshTtl: number, extraClaims?: Record<string, unknown>) =>
				Effect.all({
					access_token: signOAuth2({ ...payload, ...extraClaims }, accessTtl, payload.sub),
					refresh_token: signOAuth2({ type: 'refresh', sid }, refreshTtl),
				}),

			verifyOAuth2Refresh: (token: string) =>
				Effect.andThen(Effect.tryPromise({ try: () => jwtVerify(token, publicKey, { issuer }), catch: (e) => new JwtError({ cause: e }) }), ({ payload }) =>
					extractOAuth2Sid(payload),
				),

			decodeOAuth2RefreshSid: (token: string) =>
				Effect.andThen(Effect.try({ try: () => decodeJwt(token), catch: (e: any) => new JwtError({ message: e ?? 'Invalid refresh token' }) }), extractOAuth2Sid),
		};
	}),
	dependencies: [SessionService.Default],
}) {}

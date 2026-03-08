/**
 * @module @polumeyv/clients/jose
 *
 * Effect-based Jose (JWT) client using the `jose` library.
 *
 * Exports:
 *  - `Jose`      — Context tag
 *  - `JoseError` — Tagged error
 *  - `makeJose`  — Factory: `(privateKeyPem, publicKeyPem) => Effect<Jose, JoseError>` (async key import)
 *
 * @example
 * ```ts
 * // App layer construction
 * Layer.effect(Jose, Effect.flatMap(
 *   Effect.all([Config.string('JWT_PRIVATE_KEY'), Config.string('JWT_PUBLIC_KEY')]),
 *   ([priv, pub]) => makeJose(priv, pub),
 * ))
 *
 * // Usage in a service
 * const jose = yield* Jose;
 * const token = yield* jose.sign({ sub: '123' }, { issuer: 'app', audience: 'app', expirationTime: '900s' });
 * const { payload } = yield* jose.verify(token, { issuer: 'app', audience: 'app' });
 * ```
 */
import { SignJWT, jwtVerify, importPKCS8, importSPKI, decodeJwt } from 'jose';
import { Context, Data, Effect } from 'effect';

export type { JWTPayload, JWTVerifyResult } from 'jose';

export class JoseError extends Data.TaggedError('JoseError')<{ cause?: unknown; message?: string }> {}

interface JoseImpl {
	sign: (payload: import('jose').JWTPayload, opts: { issuer: string; audience: string; expirationTime: string; jti?: string }) => Effect.Effect<string, JoseError>;
	verify: (token: string, opts: { issuer: string; audience: string }) => Effect.Effect<import('jose').JWTVerifyResult, JoseError>;
	decode: (token: string) => import('jose').JWTPayload;
}

export class Jose extends Context.Tag('Jose')<Jose, JoseImpl>() {}

export const makeJose = (privateKeyPem: string, publicKeyPem: string) =>
	Effect.map(
		Effect.all([
			Effect.tryPromise({ try: () => importPKCS8(privateKeyPem, 'EdDSA'), catch: (e) => new JoseError({ cause: e, message: 'Failed to import private key' }) }),
			Effect.tryPromise({ try: () => importSPKI(publicKeyPem, 'EdDSA'), catch: (e) => new JoseError({ cause: e, message: 'Failed to import public key' }) }),
		]),
		([privateKey, publicKey]) =>
			Jose.of({
				sign: (payload, opts) =>
					Effect.tryPromise({
						try: () => {
							const jwt = new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA' }).setIssuer(opts.issuer).setAudience(opts.audience).setIssuedAt().setExpirationTime(opts.expirationTime);
							if (opts.jti) jwt.setJti(opts.jti);
							return jwt.sign(privateKey);
						},
						catch: (e) => new JoseError({ cause: e }),
					}),
				verify: (token, opts) =>
					Effect.tryPromise({
						try: () => jwtVerify(token, publicKey, { issuer: opts.issuer, audience: opts.audience }),
						catch: (e) => new JoseError({ cause: e }),
					}),
				decode: (token) => decodeJwt(token),
			}),
	);

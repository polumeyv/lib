import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

/** Verify an OAuth2 access token against the IDP's JWKS endpoint. Call once per app to memoize the JWKS. */
export function makeAccessTokenVerifier(issuer: string) {
	const jwks = createRemoteJWKSet(new URL(`${issuer}/oauth2/jwks`));
	return async <T extends JWTPayload = JWTPayload>(token: string): Promise<T> => {
		const { payload } = await jwtVerify(token, jwks, { issuer });
		return payload as T;
	};
}

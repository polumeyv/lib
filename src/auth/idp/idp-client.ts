import { Effect } from 'effect';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { OAuthError } from '../errors';

export interface TokenResponse {
	access_token: string;
	refresh_token: string;
	expires_in: number;
	token_type: string;
	scope?: string;
}

/**
 * Builds a client for talking to *our* IdP (polumeyv-auth): token exchange, refresh, revoke, JWKS verify, authorize-URL.
 * This is the downstream-app side of the OAuth boundary — not to be confused with `OAuthProviderResolver`, which is the
 * auth app acting as a client of *external* IdPs like Google.
 */
export function makeIdpClient({
	publicAuthUrl,
	serverAuthUrl,
	clientId,
	clientSecret,
	redirectUri,
	pkceCookieMaxAge = 600,
	accessCookieMaxAge = 900,
	refreshCookieMaxAge = 7_776_000,
}: {
	publicAuthUrl: string;
	serverAuthUrl: string;
	clientId: string;
	clientSecret: string;
	redirectUri: string;
	/** Max-age in seconds for the tenant-side `pkce_ver` cookie (default: 600 — 10 min). */
	pkceCookieMaxAge?: number;
	/** Max-age in seconds for the tenant-side `access_token` cookie (default: 900 — 15 min, matches IdP access TTL). */
	accessCookieMaxAge?: number;
	/** Max-age in seconds for the tenant-side `refresh_token` cookie (default: 7 776 000 — 90 days, matches IdP OAuth2 refresh TTL). */
	refreshCookieMaxAge?: number;
}) {
	const jwks = createRemoteJWKSet(new URL(`${publicAuthUrl}/oauth2/jwks`));

	const tokenRequest = (fields: Record<string, string>, origin: string) =>
		Effect.tryPromise({
			try: () =>
				fetch(`${serverAuthUrl}/oauth2/token`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: origin },
					body: new URLSearchParams({ ...fields, client_id: clientId, client_secret: clientSecret }).toString(),
				}).then((res) => (res.ok ? (res.json() as Promise<TokenResponse>) : Promise.reject(new Error(`${fields.grant_type} failed: ${res.status}`)))),
			catch: (e) => new OAuthError({ cause: e, message: e instanceof Error ? e.message : 'Token request failed' }),
		});

	return {
		tokenRequest,
		redirectUri,
		pkceCookieMaxAge,
		accessCookieMaxAge,
		refreshCookieMaxAge,

		exchangeCode: (code: string, codeVerifier: string, origin: string) =>
			tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: codeVerifier }, origin),

		refreshTokens: (refreshToken: string | null | undefined, origin: string) =>
			refreshToken
				? tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken }, origin)
				: Effect.fail(new OAuthError({ message: 'Missing refresh token' })),

		/** RFC 7009 token revocation — deletes the OAuth2 session on the auth server. */
		revoke: (token: string) =>
			Effect.tryPromise({
				try: () =>
					fetch(`${serverAuthUrl}/oauth2/revoke`, {
						method: 'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: new URLSearchParams({ token, client_id: clientId, client_secret: clientSecret }).toString(),
					}),
				catch: (e) => new OAuthError({ cause: e, message: e instanceof Error ? e.message : 'Revoke request failed' }),
			}),

		/** Verify an OAuth2 access token against the IDP's JWKS endpoint. JWKS is memoized per client. Throws if missing, invalid, or within `bufferSeconds` of expiry (default 60s). */
		verifyAccessToken: <T extends JWTPayload = JWTPayload>(token: string | null | undefined, bufferSeconds = 60): Promise<T> => {
			if (!token) return Promise.reject(new OAuthError({ message: 'Missing access token' }));
			return jwtVerify(token, jwks, { issuer: publicAuthUrl }).then(({ payload }) => {
				if (!payload.exp || payload.exp - bufferSeconds <= Math.floor(Date.now() / 1000)) throw new OAuthError({ message: 'Access token expired' });
				return payload as T;
			});
		},

		generateAuthorizeUrl: () =>
			Effect.sync(() =>
				((codeVerifier) => ({
					url: `${publicAuthUrl}/oauth2/authorize?${new URLSearchParams({
						client_id: clientId,
						redirect_uri: redirectUri,
						response_type: 'code',
						// Must agree with `scopes_supported` advertised by the auth-server's `/.well-known/oauth-authorization-server` endpoint.
						scope: 'openid profile email',
						code_challenge: new Bun.CryptoHasher('sha256').update(codeVerifier).digest('base64url'),
						code_challenge_method: 'S256',
					})}`,
					codeVerifier,
				}))(crypto.getRandomValues(new Uint8Array(32)).toBase64({ alphabet: 'base64url' })),
			),
	};
}

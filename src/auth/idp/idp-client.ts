import { Data, Effect } from 'effect';
import {
	discovery,
	allowInsecureRequests,
	authorizationCodeGrant,
	refreshTokenGrant,
	tokenRevocation,
	buildAuthorizationUrl,
	calculatePKCECodeChallenge,
	randomPKCECodeVerifier,
} from 'openid-client';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { HttpStatusError } from '@polumeyv/lib/error';

/** Tagged error for downstream-app IdP client operations (discovery, token grant, refresh, revoke, access-token verify). */
export class IdpClientError extends Data.TaggedError('IdpClientError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

export interface TokenResponse {
	access_token: string;
	refresh_token: string;
	expires_in: number;
	token_type: string;
	scope?: string;
}

const asTokenResponse = (t: { access_token: string; refresh_token?: string; expires_in?: number; token_type?: string; scope?: string }): TokenResponse => ({
	access_token: t.access_token,
	refresh_token: t.refresh_token ?? '',
	expires_in: t.expires_in ?? 0,
	token_type: t.token_type ?? 'Bearer',
	scope: t.scope,
});

/**
 * Builds a client for talking to *our* IdP (polumeyv-auth): token exchange, refresh, revoke, JWKS verify, authorize-URL.
 * This is the downstream-app side of the OAuth boundary — not to be confused with `OAuthProviderResolver`, which is the
 * auth app acting as a client of *external* IdPs like Google.
 *
 * Discovery happens lazily on first call against `${publicAuthUrl}/.well-known/oauth-authorization-server`, then the
 * `Configuration` is cached as a resolved Promise for the lifetime of the process.
 */
export function makeIdpClient({
	publicAuthUrl,
	clientId,
	clientSecret,
	redirectUri,
	scope = 'openid profile email',
	pkceCookieMaxAge = 600,
	accessCookieMaxAge = 900,
	refreshCookieMaxAge = 7_776_000,
}: {
	publicAuthUrl: string;
	clientId: string;
	clientSecret: string;
	redirectUri: string;
	/** Space-separated OAuth scopes requested at /authorize (default: 'openid profile email'). */
	scope?: string;
	/** Max-age in seconds for the tenant-side `pkce_ver` cookie (default: 600 — 10 min). */
	pkceCookieMaxAge?: number;
	/** Max-age in seconds for the tenant-side `access_token` cookie (default: 900 — 15 min, matches IdP access TTL). */
	accessCookieMaxAge?: number;
	/** Max-age in seconds for the tenant-side `refresh_token` cookie (default: 7 776 000 — 90 days, matches IdP OAuth2 refresh TTL). */
	refreshCookieMaxAge?: number;
}) {
	// HTTPS is enforced by oauth4webapi; in local dev the IdP is plain http://localhost, so opt into insecure
	// requests for http URLs only. Prod URLs are https and stay strict.
	const discoveryUrl = new URL(`${publicAuthUrl}/.well-known/oauth-authorization-server`);
	const configPromise = discovery(
		discoveryUrl,
		clientId,
		clientSecret,
		undefined,
		discoveryUrl.protocol === 'http:' ? { execute: [allowInsecureRequests] } : undefined,
	);
	const jwksPromise = configPromise.then((cfg) => createRemoteJWKSet(new URL(cfg.serverMetadata().jwks_uri!)));
	const issuerPromise = configPromise.then((cfg) => cfg.serverMetadata().issuer);

	return {
		pkceCookieMaxAge,
		accessCookieMaxAge,
		refreshCookieMaxAge,

		/** Exchange an authorization code for tokens. `callbackUrl` is the IdP's redirect-back URL (carries `?code=…`). */
		exchangeCode: (callbackUrl: URL, codeVerifier: string) =>
			Effect.tryPromise({
				try: async () => asTokenResponse(await authorizationCodeGrant(await configPromise, callbackUrl, { pkceCodeVerifier: codeVerifier })),
				catch: (e) => new IdpClientError({ cause: e, message: e instanceof Error ? e.message : 'Token exchange failed' }),
			}),

		refreshTokens: (refreshToken: string | null | undefined) =>
			refreshToken
				? Effect.tryPromise({
						try: async () => asTokenResponse(await refreshTokenGrant(await configPromise, refreshToken)),
						catch: (e) => new IdpClientError({ cause: e, message: e instanceof Error ? e.message : 'Token refresh failed' }),
					})
				: Effect.fail(new IdpClientError({ message: 'Missing refresh token' })),

		/** RFC 7009 token revocation — deletes the OAuth2 session on the auth server. */
		revoke: (token: string) =>
			Effect.tryPromise({
				try: async () => {
					await tokenRevocation(await configPromise, token);
				},
				catch: (e) => new IdpClientError({ cause: e, message: e instanceof Error ? e.message : 'Revoke request failed' }),
			}),

		/** Verify an OAuth2 access token against the IdP's discovered JWKS endpoint. Fails if missing, invalid, or within `bufferSeconds` of expiry (default 60s). */
		verifyAccessToken: <T extends JWTPayload = JWTPayload>(token: string | null | undefined, bufferSeconds = 60) =>
			Effect.andThen(
				Effect.mapError(Effect.fromNullishOr(token), () => new IdpClientError({ message: 'Missing access token' })),
				(t) =>
					Effect.tryPromise({
						try: async (): Promise<T> => {
							const [jwks, issuer] = await Promise.all([jwksPromise, issuerPromise]);
							const { payload } = await jwtVerify(t, jwks, { issuer, requiredClaims: ['exp'], currentDate: new Date(Date.now() + bufferSeconds * 1000) });
							return payload as T;
						},
						catch: (e) => new IdpClientError({ cause: e, message: e instanceof Error ? e.message : 'Access token verification failed' }),
					}),
			),
		generateAuthorizeUrl: () =>
			((codeVerifier) =>
				Effect.zipWith(
					Effect.promise(() => configPromise),
					Effect.tryPromise(() => calculatePKCECodeChallenge(codeVerifier)),
					(config, code_challenge) => ({
						url: buildAuthorizationUrl(config, { redirect_uri: redirectUri, scope, code_challenge, code_challenge_method: 'S256', response_type: 'code' }).toString(),
						codeVerifier,
					}),
					{ concurrent: true },
				).pipe(Effect.mapError((cause) => new IdpClientError({ cause, message: cause instanceof Error ? cause.message : 'Failed to build authorize URL' }))))(
				randomPKCECodeVerifier(),
			),
	};
}

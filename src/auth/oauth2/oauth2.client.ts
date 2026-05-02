import { Effect } from 'effect';
import { OAUTH } from '../config';
import { OAuthError } from '../errors';

export interface TokenResponse {
	access_token: string;
	refresh_token: string;
	expires_in: number;
	token_type: string;
	scope?: string;
}

export function makeOAuthClient({
	publicAuthUrl,
	serverAuthUrl,
	clientId,
	clientSecret,
	redirectUri,
}: {
	publicAuthUrl: string;
	serverAuthUrl: string;
	clientId: string;
	clientSecret: string;
	redirectUri: string;
}) {
	const tokenRequest = (body: URLSearchParams, origin: string) => {
		body.set('client_id', clientId);
		body.set('client_secret', clientSecret);
		return Effect.tryPromise({
			try: () =>
				fetch(`${serverAuthUrl}/oauth2/token`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/x-www-form-urlencoded',
						Origin: origin,
					},
					body: body.toString(),
				}).then((res) => {
					if (!res.ok) throw new Error(`${body.get('grant_type')} failed: ${res.status}`);
					return res.json() as Promise<TokenResponse>;
				}),
			catch: (e) => new OAuthError({ cause: e, message: e instanceof Error ? e.message : 'Token request failed' }),
		});
	};

	return {
		tokenRequest,
		redirectUri,

		exchangeCode: (code: string, codeVerifier: string, origin: string) =>
			tokenRequest(new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: codeVerifier }), origin),

		refreshTokens: (refreshToken: string, origin: string) =>
			tokenRequest(new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken }), origin),

		/** RFC 7009 token revocation — deletes the OAuth2 session on the auth server. */
		revoke: (token: string) =>
			Effect.tryPromise({
				try: () =>
					fetch(`${serverAuthUrl}/oauth2/revoke`, {
						method: 'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: new URLSearchParams({ token, client_id: clientId, client_secret: clientSecret }).toString(),
					}).then((res) => {
						if (!res.ok) throw new Error(`revoke failed: ${res.status}`);
					}),
				catch: (e) => new OAuthError({ cause: e, message: e instanceof Error ? e.message : 'Revoke request failed' }),
			}),

		generateAuthorizeUrl: () =>
			Effect.sync(() => {
				const codeVerifier = crypto.getRandomValues(new Uint8Array(32)).toBase64({ alphabet: 'base64url' });
				return {
					url: `${publicAuthUrl}/oauth2/authorize?${new URLSearchParams({
						client_id: clientId,
						redirect_uri: redirectUri,
						response_type: 'code',
						scope: OAUTH.defaultScope,
						code_challenge: new Bun.CryptoHasher('sha256').update(codeVerifier).digest('base64url'),
						code_challenge_method: 'S256',
					})}`,
					codeVerifier,
				};
			}),
	};
}

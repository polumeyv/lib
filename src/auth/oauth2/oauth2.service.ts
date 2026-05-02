import { Effect, Option } from 'effect';
import { SessionService } from '@polumeyv/lib/server';
import { Jwt } from '../jwt';
import { AuthConfig } from '../config';
import { OAuth2RequestError } from '../errors';
import type { AuthPayload, UserSub } from '../model';

const AUTH_CODE_TTL = 300; // 5 minutes
const AUTH_CODE_KEY = (code: string) => `authcode:${code}`;
const OAUTH2_SESS_KEY = (sid: string) => `oauth2_sess:${sid}`;
const OAUTH2_SESS_TTL = 60 * 60 * 24 * 90; // 90 days
const OAUTH_REDIRECT_KEY = (authSid: string) => `red_url:${Bun.SHA256.hash(authSid, 'hex')}`;
const OAUTH_REDIRECT_TTL = 3600; // 1 hour

export interface OAuth2ExtraClaims {
	/** Claims merged into the access_token JWT payload. */
	readonly tokenClaims: Record<string, unknown>;
	/** Extra fields merged into the token HTTP response body. */
	readonly responseExtra?: Record<string, unknown>;
}

interface AuthCodeData {
	readonly sub: typeof UserSub.Type;
	readonly email: string;
	readonly client_id: string;
	readonly redirect_uri: string;
	readonly code_challenge: string;
	readonly scope: string;
	readonly nonce?: string;
}

export interface OAuth2SessionData {
	readonly sub: typeof UserSub.Type;
	readonly aud: string;
	readonly email: string;
}

export class OAuth2Service extends Effect.Service<OAuth2Service>()('OAuth2Service', {
	effect: Effect.gen(function* () {
		const session = yield* SessionService;
		const jwt = yield* Jwt;
		const { oauth2AccessTtl } = yield* AuthConfig;

		const buildTokenResponse = (
			sub: typeof UserSub.Type,
			email: string,
			clientId: string,
			tokenClaims: Record<string, unknown>,
			extra?: Record<string, unknown>,
		) =>
			Effect.andThen(Effect.sync(() => Bun.randomUUIDv7()), (sid) =>
				Effect.andThen(session.push(OAUTH2_SESS_KEY(sid), OAUTH2_SESS_TTL, { sub, aud: clientId, email } satisfies OAuth2SessionData), () =>
					Effect.map(jwt.signOAuth2Tokens({ sub, email } as AuthPayload, sid, tokenClaims), (tokens) => ({
						...tokens,
						token_type: 'Bearer' as const,
						expires_in: oauth2AccessTtl,
						...extra,
					})),
				),
			);

		const createAuthCode = (
			user: { sub: string; email: string },
			request: { client_id: string; redirect_uri: string; code_challenge: string; scope: string; state?: string; nonce?: string },
		) =>
			Effect.flatMap(Effect.sync(() => Bun.randomUUIDv7()), (code) =>
				Effect.as(
					session.push(AUTH_CODE_KEY(code), AUTH_CODE_TTL, {
						...user,
						client_id: request.client_id,
						redirect_uri: request.redirect_uri,
						code_challenge: request.code_challenge,
						scope: request.scope,
						nonce: request.nonce,
					}),
					((url) => (url.searchParams.set('code', code), request.state && url.searchParams.set('state', request.state), url.toString()))(
						new URL(request.redirect_uri),
					),
				),
			);

		return {
			createAuthCode,

			/** Pop and validate an authorization code, then create an OAuth2 session and sign tokens. */
			exchangeAuthCode: (
				req: { code: string; redirect_uri: string; code_verifier: string },
				clientId: string,
				getExtraClaims: (sub: typeof UserSub.Type) => Effect.Effect<OAuth2ExtraClaims, any, any>,
			) =>
				Effect.andThen(session.pop<AuthCodeData>(AUTH_CODE_KEY(req.code)), (storedCode) =>
					Effect.andThen(
						Effect.filterOrFail(
							Effect.succeed(storedCode),
							(c) =>
								c.client_id === clientId &&
								c.redirect_uri === req.redirect_uri &&
								new Bun.CryptoHasher('sha256').update(req.code_verifier).digest('base64url') === c.code_challenge,
							() => new OAuth2RequestError({ message: 'Code validation failed' }),
						),
						(code) =>
							Effect.andThen(getExtraClaims(code.sub), ({ tokenClaims, responseExtra }) =>
								Effect.map(buildTokenResponse(code.sub, code.email, clientId, tokenClaims, responseExtra), (res) => ({
									...res,
									scope: code.scope,
								})),
							),
					),
				),

			refreshTokens: (refreshToken: string, clientId: string, getExtraClaims: (sub: typeof UserSub.Type) => Effect.Effect<OAuth2ExtraClaims, any, any>) =>
				jwt.verifyOAuth2Refresh(refreshToken).pipe(
					Effect.andThen((sid) => session.pop<OAuth2SessionData>(OAUTH2_SESS_KEY(sid))),
					Effect.filterOrFail(
						(s) => s.aud === clientId,
						() => new OAuth2RequestError({ message: 'Audience mismatch' }),
					),
					Effect.andThen((sess) =>
						Effect.andThen(getExtraClaims(sess.sub), ({ tokenClaims, responseExtra }) =>
							Effect.map(buildTokenResponse(sess.sub, sess.email, clientId, tokenClaims, responseExtra), (res) => res),
						),
					),
				),

			/** Delete an OAuth2 session by refresh token (for logout). */
			revokeSession: (refreshToken: string) => jwt.decodeOAuth2RefreshSid(refreshToken).pipe(Effect.andThen((sid) => session.delete(OAUTH2_SESS_KEY(sid)))),

			/** Store OAuth request params in the session and return the authSid. */
			storeOAuthRedirect: (params: string) =>
				Effect.flatMap(Effect.sync(() => Bun.randomUUIDv7()), (authSid) => Effect.as(session.push(OAUTH_REDIRECT_KEY(authSid), OAUTH_REDIRECT_TTL, params), authSid)),

			/** Look up a pending OAuth redirect, create the auth code, and delete the redirect key. Returns Option<redirectUrl>. */
			consumeOAuthRedirect: (authSid: string | undefined, user: { sub: string; email: string }) => {
				if (!authSid) return Effect.succeed(Option.none<string>());
				const key = OAUTH_REDIRECT_KEY(authSid);
				return Effect.matchEffect(session.peek<string>(key), {
					onSuccess: (raw) =>
						((params) =>
							Effect.map(
								Effect.all([
									createAuthCode(user, {
										client_id: params.get('client_id')!,
										redirect_uri: params.get('redirect_uri')!,
										code_challenge: params.get('code_challenge')!,
										scope: params.get('scope')!,
										state: params.get('state') ?? undefined,
										nonce: params.get('nonce') ?? undefined,
									}),
									session.delete(key),
								]),
								([redirectUrl]) => Option.some(redirectUrl),
							))(new URLSearchParams(raw)),
					onFailure: () => Effect.succeed(Option.none<string>()),
				});
			},
		};
	}),
	dependencies: [SessionService.Default, Jwt.Default],
}) {}

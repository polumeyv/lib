import { Context, Data, Effect, Layer } from 'effect';
import * as oauth from 'oauth4webapi';
import type { HttpStatusError } from '@polumeyv/lib/error';
import type { UserSub } from '../../user/model';
import { OAuthAccountStore } from './account-store';
import { OAuthProviderResolver } from './provider-resolver';

/** Tagged error for OAuth refresh-token vault operations (missing refresh token, refresh grant failure). */
export class OAuthTokenError extends Data.TaggedError('OAuthTokenError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

const REFRESH_THRESHOLD_MS = 60_000;

/**
 * Hands out a valid access token for `(sub, provider)` — refreshes via
 * oauth4webapi's `refreshTokenGrantRequest`/`processRefreshTokenResponse` against
 * the resolved provider when the cached token is stale, and persists it back to
 * `OAuthAccountStore` so the next call hits the cache.
 *
 * Replaces the hand-rolled token-refresh logic that calendar-sync used to
 * maintain (loadTokens / refreshGoogleToken / saveAccessToken / ensureAccessToken).
 */
export class OAuthTokenVault extends Context.Service<OAuthTokenVault>()('OAuthTokenVault', {
	make: Effect.gen(function* () {
		const store = yield* OAuthAccountStore;
		const resolver = yield* OAuthProviderResolver;

		const getValidAccessToken = (sub: typeof UserSub.Type, provider: string) =>
			Effect.gen(function* () {
				const account = yield* Effect.flatMap(store.getBySub(sub, provider), Effect.fromOption);
				if (!account.refresh_token) return yield* Effect.fail(new OAuthTokenError({ message: `Missing refresh_token for ${sub}/${provider}` }));

				// Cached token still has more than the refresh threshold of life — return it.
				if (account.access_token && account.token_expires && account.token_expires.getTime() - Date.now() > REFRESH_THRESHOLD_MS) return account.access_token;

				// Refresh + persist.
				const { as, client, clientAuth } = yield* resolver.resolve(provider);
				const tokens = yield* Effect.tryPromise({
					try: async () => {
						const res = await oauth.refreshTokenGrantRequest(as, client, clientAuth, account.refresh_token!);
						return await oauth.processRefreshTokenResponse(as, client, res);
					},
					catch: (e) => new OAuthTokenError({ cause: e, message: `Token refresh failed for ${sub}/${provider}` }),
				});
				if (!tokens.access_token) return yield* Effect.fail(new OAuthTokenError({ message: `Provider returned no access_token on refresh for ${sub}/${provider}` }));
				yield* store.replaceAccessToken(
					sub,
					provider,
					tokens.access_token,
					tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : new Date(Date.now() + 3600_000),
				);
				return tokens.access_token;
			});

		return { getValidAccessToken };
	}),
}) {
	static readonly layer = Layer.effect(this, this.make).pipe(Layer.provide([OAuthAccountStore.layer, OAuthProviderResolver.layer]));
}

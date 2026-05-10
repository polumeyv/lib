import { Effect, Option } from 'effect';
import { refreshTokenGrant } from 'openid-client';
import type { UserSub } from '../model';
import { OAuthError } from '../errors';
import { OAuthAccountStore } from './account-store';
import { OAuthProviderResolver } from './provider-resolver';

const REFRESH_THRESHOLD_MS = 60_000;

/**
 * Hands out a valid access token for `(sub, provider)` — refreshes via
 * `openid-client.refreshTokenGrant` against the cached provider Configuration
 * when the cached token is stale, and persists the refreshed token back to
 * `OAuthAccountStore` so the next call hits the cache.
 *
 * Replaces the hand-rolled token-refresh logic that calendar-sync used to
 * maintain (loadTokens / refreshGoogleToken / saveAccessToken / ensureAccessToken).
 */
export class OAuthTokenVault extends Effect.Service<OAuthTokenVault>()('OAuthTokenVault', {
	effect: Effect.gen(function* () {
		const store = yield* OAuthAccountStore;
		const resolver = yield* OAuthProviderResolver;

		const getValidAccessToken = (sub: typeof UserSub.Type, provider: string) =>
			Effect.gen(function* () {
				const account = yield* Effect.flatMap(
					store.getActive(sub, provider),
					Option.match({
						onNone: () => Effect.fail(new OAuthError({ message: `No active ${provider} account for ${sub}` })),
						onSome: Effect.succeed,
					}),
				);
				if (!account.refresh_token) {
					return yield* Effect.fail(new OAuthError({ message: `Missing refresh_token for ${sub}/${provider}` }));
				}

				// Cached token still has more than the refresh threshold of life — return it.
				if (account.access_token && account.token_expires && account.token_expires.getTime() - Date.now() > REFRESH_THRESHOLD_MS) {
					return account.access_token;
				}

				// Refresh + persist.
				const { config } = yield* resolver.resolve(provider);
				const tokens = yield* Effect.tryPromise({
					try: () => refreshTokenGrant(config, account.refresh_token!),
					catch: (e) => new OAuthError({ cause: e, message: `Token refresh failed for ${sub}/${provider}` }),
				});
				if (!tokens.access_token) {
					return yield* Effect.fail(new OAuthError({ message: `Provider returned no access_token on refresh for ${sub}/${provider}` }));
				}
				const expiresAt = tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : new Date(Date.now() + 3600_000);
				yield* store.replaceAccessToken(sub, provider, tokens.access_token, expiresAt);
				return tokens.access_token;
			});

		return { getValidAccessToken };
	}),
	dependencies: [OAuthAccountStore.Default, OAuthProviderResolver.Default],
}) {}

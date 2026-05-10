import { Context, Effect } from 'effect';
import { discovery, type Configuration } from 'openid-client';
import { OAuthError } from '../errors';

/** Registered OAuth/OIDC providers keyed by provider name (e.g. 'google'). */
export class OAuthProviderRegistry extends Context.Tag('OAuthProviderRegistry')<
	OAuthProviderRegistry,
	ReadonlyMap<
		string,
		{
			readonly discoveryUrl: string;
			readonly clientId: string;
			readonly clientSecret: string;
			readonly redirectUri: string;
		}
	>
>() {}

/**
 * Resolves a provider name to its registered config + a cached `openid-client`
 * `Configuration` (fetched once via OIDC discovery, then memoised). Shared by
 * `OidcAuthFlow` (build URL, exchange code) and `OAuthTokenVault` (refresh).
 */
export class OAuthProviderResolver extends Effect.Service<OAuthProviderResolver>()('OAuthProviderResolver', {
	effect: Effect.gen(function* () {
		const registry = yield* OAuthProviderRegistry;
		const configs = new Map<string, Configuration>();

		const resolve = (provider: string) =>
			Effect.flatMap(
				Effect.mapError(Effect.fromNullable(registry.get(provider)), () => new OAuthError({ message: `Unknown OAuth provider: ${provider}` })),
				(entry) => {
					const cached = configs.get(provider);
					if (cached) return Effect.succeed({ config: cached, entry });
					return Effect.map(
						Effect.tap(
							Effect.tryPromise({
								try: () => discovery(new URL(entry.discoveryUrl), entry.clientId, entry.clientSecret),
								catch: (e) => new OAuthError({ cause: e, message: `OIDC discovery failed for ${provider}` }),
							}),
							(config) => Effect.sync(() => configs.set(provider, config)),
						),
						(config) => ({ config, entry }),
					);
				},
			);

		return { resolve };
	}),
}) {}

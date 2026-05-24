import { Context, Data, Effect, Layer } from 'effect';
import { discovery, type Configuration } from 'openid-client';
import type { HttpStatusError } from '@polumeyv/lib/error';

/** Tagged error for OAuth provider lookup + OIDC discovery failures. */
export class OAuthProviderError extends Data.TaggedError('OAuthProviderError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

export interface OAuthProviderEntry {
	readonly discoveryUrl: string;
	readonly clientId: string;
	readonly clientSecret: string;
	readonly redirectUri: string;
	config?: Configuration;
}

/** Registered OAuth/OIDC providers keyed by provider name (e.g. 'google'). Consumed by `OAuthProviderResolver`. */
export class OAuthProviderResolverConfig extends Context.Service<OAuthProviderResolverConfig, Map<string, OAuthProviderEntry>>()('OAuthProviderResolverConfig') {}

/**
 * Resolves a provider name to its registered config + a cached `openid-client`
 * `Configuration` (fetched once via OIDC discovery, then memoised on the entry). Shared by
 * `OidcAuthFlow` (build URL, exchange code) and `OAuthTokenVault` (refresh).
 */
export class OAuthProviderResolver extends Context.Service<OAuthProviderResolver>()('OAuthProviderResolver', {
	make: Effect.gen(function* () {
		const providers = yield* OAuthProviderResolverConfig;

		const resolve = (provider: string) =>
			Effect.flatMap(
				Effect.mapError(Effect.fromNullishOr(providers.get(provider)), () => new OAuthProviderError({ message: `Unknown OAuth provider: ${provider}` })),
				(entry) => {
					if (entry.config) return Effect.succeed({ config: entry.config, entry });
					return Effect.map(
						Effect.tap(
							Effect.tryPromise({
								try: () => discovery(new URL(entry.discoveryUrl), entry.clientId, entry.clientSecret),
								catch: (e) => new OAuthProviderError({ cause: e, message: `OIDC discovery failed for ${provider}` }),
							}),
							(config) => Effect.sync(() => (entry.config = config)),
						),
						(config) => ({ config, entry }),
					);
				},
			);

		return { resolve };
	}),
}) {
	static readonly layer = Layer.effect(this, this.make);
}

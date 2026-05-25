import { Context, Data, Effect, Layer } from 'effect';
import * as oauth from 'oauth4webapi';
import type { HttpStatusError } from '@polumeyv/lib/error';

/** Tagged error for OAuth provider lookup + OIDC discovery failures. */
export class OAuthProviderError extends Data.TaggedError('OAuthProviderError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

/**
 * Resolved oauth4webapi handles for a provider: the discovered Authorization Server metadata plus the
 * client identity + token-endpoint auth method threaded into every grant/refresh/revoke call.
 */
export interface OAuthClient {
	readonly as: oauth.AuthorizationServer;
	readonly client: oauth.Client;
	readonly clientAuth: oauth.ClientAuth;
	readonly redirectUri: string;
}

export interface OAuthProviderEntry {
	/** Issuer identifier; the well-known metadata URL is derived from it per `algorithm`. */
	readonly issuer: string;
	/** Discovery transform: 'oidc' → `/.well-known/openid-configuration` (default), 'oauth2' → `/.well-known/oauth-authorization-server`. */
	readonly algorithm?: 'oidc' | 'oauth2';
	readonly clientId: string;
	readonly clientSecret: string;
	readonly redirectUri: string;
	/** Memoised resolution — discovery runs once per entry, then this is returned on subsequent calls. */
	resolved?: OAuthClient;
}

/** Registered OAuth/OIDC providers keyed by provider name (e.g. 'google'). Consumed by `OAuthProviderResolver`. */
export class OAuthProviderResolverConfig extends Context.Service<OAuthProviderResolverConfig, Map<string, OAuthProviderEntry>>()('OAuthProviderResolverConfig') {}

/**
 * Resolves a provider name to its discovered oauth4webapi handles (`{ as, client, clientAuth, redirectUri }`),
 * fetched once via OIDC/RFC-8414 discovery and memoised on the entry. `processDiscoveryResponse` binds the
 * response to the expected issuer. Shared by `OidcAuthFlow` (build URL, exchange code) and `OAuthTokenVault` (refresh).
 */
export class OAuthProviderResolver extends Context.Service<OAuthProviderResolver>()('OAuthProviderResolver', {
	make: Effect.gen(function* () {
		const providers = yield* OAuthProviderResolverConfig;

		const resolve = (provider: string): Effect.Effect<OAuthClient, OAuthProviderError> =>
			Effect.flatMap(
				Effect.mapError(Effect.fromNullishOr(providers.get(provider)), () => new OAuthProviderError({ message: `Unknown OAuth provider: ${provider}` })),
				(entry) => {
					if (entry.resolved) return Effect.succeed(entry.resolved);
					const issuerUrl = new URL(entry.issuer);
					return Effect.tryPromise({
						try: async () => {
							const res = await oauth.discoveryRequest(issuerUrl, { algorithm: entry.algorithm });
							const as = await oauth.processDiscoveryResponse(issuerUrl, res);
							return (entry.resolved = {
								as,
								client: { client_id: entry.clientId },
								clientAuth: oauth.ClientSecretPost(entry.clientSecret),
								redirectUri: entry.redirectUri,
							});
						},
						catch: (e) => new OAuthProviderError({ cause: e, message: `OIDC discovery failed for ${provider}` }),
					});
				},
			);

		return { resolve };
	}),
}) {
	static readonly layer = Layer.effect(this, this.make);
}

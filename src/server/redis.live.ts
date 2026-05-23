/**
 * @module @polumeyv/utils/server/redis.live
 *
 * The Bun-runtime half of the Redis service: the `makeRedis` factory that constructs a live
 * `RedisClient`. Kept separate from `./redis` (which holds the bun-free `Redis` tag, `RedisError`,
 * and cache types) so the tag can be imported from client-reachable graphs without dragging the
 * `bun` builtin into the client bundle. Only server-only layer construction imports this entry.
 */
import { RedisClient, type RedisOptions } from 'bun';
import { Effect, Schema } from 'effect';
import { Redis, RedisError, type Cache, type CacheOptions } from './redis';
import { makeUse } from './use';

export const makeRedis = (url?: string, options?: RedisOptions) =>
	Effect.map(
		Effect.acquireRelease(
			Effect.try({
				try: () => new RedisClient(url, options),
				catch: (e) => new RedisError({ cause: e, message: 'Error Connecting' }),
			}),
			(client) => Effect.sync(() => client.close()),
		),
		(client) => {
			const use = makeUse(client, RedisError, 'Redis');

			const cache = <Id, A, LE, LR, SA, SE, SR>({ key, codec, ttl, load, save }: CacheOptions<Id, A, LE, LR, SA, SE, SR>): Cache<Id, A, LE, LR, SE, SR> => {
				const populate = (id: Id, value: A) => Effect.andThen(Schema.encode(codec)(value), (json) => use((c) => c.setex(key(id), ttl, json)));
				const loadThrough = (id: Id): Effect.Effect<A, LE, LR> => Effect.tap(load(id), (value) => Effect.ignore(populate(id, value)));
				return {
					get: (id) =>
						use((c) => c.get(key(id))).pipe(
							Effect.catchAll(() => Effect.succeed(null)),
							Effect.flatMap((json) => (json ? Effect.catchAll(Schema.decode(codec)(json), () => loadThrough(id)) : loadThrough(id))),
						),
					set: (id, value) => Effect.andThen(save(id, value), () => Effect.ignore(populate(id, value))),
				};
			};

			return Redis.of({ use, cache });
		},
	);

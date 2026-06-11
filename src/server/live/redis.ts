import { Effect } from 'effect';
import * as S from 'effect/Schema';
import { Redis, RedisError, type Cache, type CacheOptions } from '../redis';
import { makeUse } from '../use';

export const makeRedis = (url?: string, options?: Bun.RedisOptions) =>
	Effect.map(
		Effect.acquireRelease(
			Effect.try({
				try: () => new Bun.RedisClient(url, options),
				catch: (e) => new RedisError({ cause: e, message: 'Error Connecting' }),
			}),
			(client) => Effect.sync(() => client.close()),
		),
		(client) => {
			const use = makeUse(client, RedisError, 'Redis');

			const cache = <Id, A, LE, LR, SA, SE, SR>({ key, codec, ttl, load, save }: CacheOptions<Id, A, LE, LR, SA, SE, SR>): Cache<Id, A, LE, LR, SE, SR> => {
				const populate = (id: Id, value: A) => Effect.andThen(S.encodeEffect(codec)(value), (json) => use((c) => c.setex(key(id), ttl, json)));
				const loadThrough = (id: Id): Effect.Effect<A, LE, LR> => Effect.tap(load(id), (value) => Effect.ignore(populate(id, value)));
				return {
					get: (id) =>
						use((c) => c.get(key(id))).pipe(
							Effect.catch(() => Effect.succeed(null)),
							Effect.flatMap((json) => (json ? Effect.catch(S.decodeEffect(codec)(json), () => loadThrough(id)) : loadThrough(id))),
						),
					set: (id, value) => Effect.andThen(save(id, value), () => Effect.ignore(populate(id, value))),
				};
			};

			return Redis.of({ use, cache });
		},
	);

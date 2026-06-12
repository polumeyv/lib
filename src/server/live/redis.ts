import { Effect } from 'effect';
import { Redis, RedisError } from '../redis';

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
			// Sync throw (bad call) and async reject (connection/server error) both map to `RedisError`.
			const use = <T>(fn: (c: Bun.RedisClient) => T): Effect.Effect<Awaited<T>, RedisError> =>
				Effect.flatMap(
					Effect.try({ try: () => fn(client), catch: (e) => new RedisError({ cause: e, message: 'Synchronous Error in Redis.use' }) }),
					(r) =>
						r instanceof Promise
							? Effect.tryPromise({ try: () => r, catch: (e) => new RedisError({ cause: e, message: 'Asynchronous Error in Redis.use' }) })
							: Effect.succeed(r as Awaited<T>),
				);
			return Redis.of({ use });
		},
	);

/**
 * @module @polumeyv/utils/server/redis
 *
 * Effect-based Redis client using Bun's native `RedisClient`.
 *
 * Exports:
 *  - `Redis`      — Context tag
 *  - `RedisError` — Tagged error
 *  - `makeRedis`  — Factory: `(url?, options?) => Effect<Redis>` (scoped — acquires connection, closes on scope end)
 *
 * @example
 * ```ts
 * // App layer construction
 * Layer.scoped(Redis, Effect.flatMap(Config.string('REDIS_URL'), makeRedis))
 *
 * // Usage in a service
 * const redis = yield* Redis;
 * const value = yield* redis.use((c) => c.get('key'));
 * yield* redis.use((c) => c.set('key', 'value'));
 * ```
 */
import { RedisClient, type RedisOptions } from 'bun';
import { Context, Data, Effect } from 'effect';
import type { HttpStatusError } from './error';
import { makeUse } from './use';

export class RedisError extends Data.TaggedError('RedisError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 503 as const;
	}
}

interface RedisImpl {
	use: <T>(fn: (client: InstanceType<typeof RedisClient>) => T) => Effect.Effect<Awaited<T>, RedisError, never>;
}

export class Redis extends Context.Tag('Redis')<Redis, RedisImpl>() {}

export const makeRedis = (url?: string, options?: RedisOptions) =>
	Effect.map(
		Effect.acquireRelease(
			Effect.try({
				try: () => new RedisClient(url, options),
				catch: (e) => new RedisError({ cause: e, message: 'Error Connecting' }),
			}),
			(client) => Effect.sync(() => client.close()),
		),
		(client) => Redis.of({ use: makeUse(client, RedisError, 'Redis') }),
	);

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
 * The `Redis` service exposes:
 *  - `use`   — run any command against the raw client.
 *  - `cache` — build a typed cache-aside `{ get, set }` over Redis + an injected backing store.
 *
 * @example
 * ```ts
 * const redis = yield* Redis;
 * const value = yield* redis.use((c) => c.get('key'));
 *
 * const names = redis.cache({
 *   key: (sub: typeof UserSub.Type) => `name:${sub}`,
 *   codec: NameJson,
 *   ttl: NAME_CACHE_TTL,
 *   load: (sub) => pg.first<[typeof UserName.Type]>((sql) => sql`SELECT f_name, l_name FROM users WHERE sub = ${sub}`, { onNull: 'fail' }),
 *   save: (sub, data) => pg.use((sql) => sql`UPDATE users SET ${sql(data, 'f_name', 'l_name')} WHERE sub = ${sub}`),
 * });
 * const name = yield* names.get(sub);
 * ```
 *
 * `cache` is store-agnostic — it coordinates Redis with whatever `load`/`save` you inject.
 * Redis failures and corrupt entries degrade to `load`; a failed cache write never fails the operation.
 */
import type { RedisClient } from 'bun';
import { Context, Data, Effect } from 'effect';
import * as S from 'effect/Schema';
import type { HttpStatusError } from '@polumeyv/lib/error';

export class RedisError extends Data.TaggedError('RedisError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 503 as const;
	}
}

export interface CacheOptions<Id, A, LE, LR, SA, SE, SR> {
	key: (id: Id) => string;
	codec: S.Codec<A, string>; // Type A ↔ Encoded string, e.g. S.fromJsonString(Inner)
	ttl: number;
	load: (id: Id) => Effect.Effect<A, LE, LR>;
	save: (id: Id, value: A) => Effect.Effect<SA, SE, SR>;
}

export interface Cache<Id, A, LE, LR, SE, SR> {
	get: (id: Id) => Effect.Effect<A, LE, LR>;
	set: (id: Id, value: A) => Effect.Effect<void, SE, SR>;
}

export interface RedisImpl {
	use: <T>(fn: (client: RedisClient) => T) => Effect.Effect<Awaited<T>, RedisError, never>;
	cache: <Id, A, LE, LR, SA, SE, SR>(opts: CacheOptions<Id, A, LE, LR, SA, SE, SR>) => Cache<Id, A, LE, LR, SE, SR>;
}

export class Redis extends Context.Service<Redis, RedisImpl>()('Redis') {}

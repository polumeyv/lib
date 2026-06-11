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
	use: <T>(fn: (client: Bun.RedisClient) => T) => Effect.Effect<Awaited<T>, RedisError, never>;
	cache: <Id, A, LE, LR, SA, SE, SR>(opts: CacheOptions<Id, A, LE, LR, SA, SE, SR>) => Cache<Id, A, LE, LR, SE, SR>;
}

export class Redis extends Context.Service<Redis, RedisImpl>()('Redis') {}

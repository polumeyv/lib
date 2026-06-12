import { Context, Data, Effect } from 'effect';
import type { HttpStatusError } from '@polumeyv/lib/error';

export class RedisError extends Data.TaggedError('RedisError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 503 as const;
	}
}

export interface RedisImpl {
	use: <T>(fn: (client: Bun.RedisClient) => T) => Effect.Effect<Awaited<T>, RedisError, never>;
}

export class Redis extends Context.Service<Redis, RedisImpl>()('Redis') {}

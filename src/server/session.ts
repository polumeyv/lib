import { Data, Effect } from 'effect';
import { Redis } from './redis';
import type { HttpStatusError } from './error';

/** Tagged error for expired or invalid sessions. */
export class SessionExpiredError extends Data.TaggedError('SessionExpiredError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

const parseOrExpired = <T>(v: string | null) => (v ? Effect.succeed(JSON.parse(v) as T) : Effect.fail(new SessionExpiredError({ message: 'Your session has expired, please try again' })));

export class SessionService extends Effect.Service<SessionService>()('SessionService', {
	effect: Effect.gen(function* () {
		const redis = yield* Redis;

		return {
			/** Store session data under a key with TTL. */
			push: <T>(key: string, ttl: number, data: T) => redis.use((c) => c.setex(key, ttl, JSON.stringify(data))),

			/** Read session without removing. Fails if missing. */
			peek: <T = unknown>(key: string) =>
				Effect.flatMap(
					redis.use((c) => c.get(key)),
					parseOrExpired<T>,
				),

			/** Read and remove session atomically. Fails if missing. */
			pop: <T = unknown>(key: string) =>
				Effect.flatMap(
					redis.use((c) => c.getdel(key)),
					parseOrExpired<T>,
				),

			/** Remove session without reading. */
			delete: (key: string) => redis.use((c) => c.unlink(key)),
		};
	}),
	dependencies: [],
}) {}

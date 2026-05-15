import { Data, Effect } from 'effect';
import { Redis } from './redis';
import type { HttpStatusError } from '@polumeyv/lib/error';

/** Tagged error for expired or invalid sessions. */
export class SessionExpiredError extends Data.TaggedError('SessionExpiredError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

/** Fail an Effect with a 401 session-expired error. */
export const sessionExpired = (message: string = 'Your session has expired') => Effect.fail(new SessionExpiredError({ message }));

export class SessionService extends Effect.Service<SessionService>()('SessionService', {
	effect: Effect.gen(function* () {
		const redis = yield* Redis;

		return {
			/** Store session data under a key with TTL. */
			push: <T>(key: string, ttl: number, data: T) => redis.use((c) => c.setex(key, ttl, JSON.stringify(data))),

			/** Mint a fresh UUIDv7, push the data under `keyFn(id)` with TTL, return the id. */
			pushFresh: <T>(keyFn: (id: string) => string, ttl: number, data: T) =>
				((id) =>
					Effect.as(
						redis.use((c) => c.setex(keyFn(id), ttl, JSON.stringify(data))),
						id,
					))(Bun.randomUUIDv7()),

			/** Read session without removing. Fails if missing. */
			peek: <T = unknown>(key: string) =>
				Effect.flatMap(
					redis.use((c) => c.get(key)),
					(v) => (v ? Effect.succeed(JSON.parse(v) as T) : sessionExpired('Your session has expired, please try again')),
				),

			/** Read and remove session atomically. Fails if missing. */
			pop: <T = unknown>(key: string) =>
				Effect.flatMap(
					redis.use((c) => c.getdel(key)),
					(v) => (v ? Effect.succeed(JSON.parse(v) as T) : sessionExpired('Your session has expired, please try again')),
				),

			/** Remove session without reading. */
			delete: (key: string) => redis.use((c) => c.unlink(key)),
		};
	}),
	dependencies: [],
}) {}

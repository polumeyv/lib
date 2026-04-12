/**
 * @module @polumeyv/utils/server/postgres
 *
 * Effect-based Postgres client using Bun's native `SQL` driver.
 *
 * Exports:
 *  - `Postgres`       — Context tag
 *  - `PostgresError`  — Tagged error
 *  - `makePostgres`   — Factory: `(url: string) => Effect<Postgres>` (scoped — acquires connection pool, releases on scope close)
 *
 * @example
 * ```ts
 * // App layer construction
 * Layer.scoped(Postgres, Effect.flatMap(Config.string('DATABASE_URL'), makePostgres))
 *
 * // Usage in a service
 * const pg = yield* Postgres;
 * const rows = yield* pg.use((sql) => sql`SELECT * FROM users WHERE id = ${id}`);
 * const user = yield* pg.first((sql) => sql`SELECT * FROM users WHERE id = ${id}`);
 * ```
 */
import { SQL } from 'bun';
import { Context, Data, Effect } from 'effect';
import type { HttpStatusError } from './error';

export class PostgresError extends Data.TaggedError('PostgresError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() { return 500 as const; }
}

interface PostgresImpl {
	use: <T>(fn: (sql: InstanceType<typeof SQL>) => T) => Effect.Effect<Awaited<T>, PostgresError, never>;
	first: <T extends any[]>(fn: (sql: InstanceType<typeof SQL>) => PromiseLike<T>) => Effect.Effect<T[number], PostgresError, never>;
}

export class Postgres extends Context.Tag('Postgres')<Postgres, PostgresImpl>() {}

export const makePostgres = (url: string) =>
	Effect.map(
		Effect.acquireRelease(
			Effect.try({
				try: () => new SQL(url, { idleTimeout: 10, max: 20 }),
				catch: (e) => new PostgresError({ message: String(e), cause: e }),
			}),
			(sql) => Effect.promise(() => sql.close()),
		),
		(sql) => {
			const impl: PostgresImpl = {
				use: (fn) =>
					Effect.flatMap(
						Effect.try({
							try: () => fn(sql),
							catch: (e) => new PostgresError({ cause: e, message: 'Asynchronous Error in Postgres.use' }),
						}),
						(result) =>
							result instanceof Promise
								? Effect.tryPromise({
										try: () => result,
										catch: (e) => new PostgresError({ cause: e, message: 'Asynchronous Error in Postgres.use' }),
									})
								: Effect.succeed(result),
					),
				first: (fn) => Effect.map(impl.use(fn), (rows) => rows[0]),
			};
			return Postgres.of(impl);
		},
	);

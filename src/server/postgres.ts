/**
 * @module @polumeyv/utils/server/postgres
 *
 * Effect-based Postgres client using Bun's native `SQL` driver.
 *
 * Exports:
 *  - `Postgres`       — Context tag
 *  - `makePostgres`   — Factory: `(url: string) => Effect<Postgres>` (scoped — acquires connection pool, releases on scope close)
 *
 * `PostgresError` is intentionally internal: it derives `statusCode` / `message` from
 * the underlying SQLSTATE code, so callers never need to catch or translate it.
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
 *
 * ## Returning collections: prefer `jsonb_agg` over `array_agg`
 *
 * Bun's SQL driver decodes Postgres `int[]`/`smallint[]` columns (under the
 * default binary protocol + named prepared statements) as *typed arrays*
 * (`Int32Array` etc.) for performance. `JSON.stringify` on a typed array
 * produces `{"0":1,"1":2,…}` instead of `[1,2,…]`, which silently breaks
 * client parsers expecting a JSON array.
 *
 * Return aggregates via `jsonb_agg` / `jsonb_build_object` so values arrive
 * as real JS `Array` / `object` instances with no client-side conversion:
 *
 * ```sql
 * -- ✗ avoid: client receives Int32Array
 * SELECT array_agg(day_num ORDER BY day_num) AS days FROM ...;
 *
 * -- ✓ prefer: client receives real number[]
 * SELECT COALESCE(jsonb_agg(day_num ORDER BY day_num), '[]'::jsonb) AS days FROM ...;
 * ```
 *
 * This keeps Postgres → Bun → HTTP → client all speaking JSON end-to-end.
 */
import { SQL } from 'bun';
import { Context, Data, Effect, Option } from 'effect';
import type { NoSuchElementException } from 'effect/Cause';
import type { HttpStatusError } from '@polumeyv/lib/error';
import { makeUse } from './use';

// Postgres SQLSTATE → HTTP status mapping. Specific codes override class-level defaults.
// See https://www.postgresql.org/docs/current/errcodes-appendix.html.
const SQLSTATE_TO_STATUS: Record<string, number> = {
	'23502': 400, // not_null_violation — caller sent NULL into a NOT NULL column
	'23514': 400, // check_violation — caller violated a CHECK constraint
	'42501': 403, // insufficient_privilege
	'57014': 408, // query_canceled
};

const SQLSTATE_CLASS_TO_STATUS: Record<string, number> = {
	'08': 503, // connection_exception
	'22': 400, // data_exception (overflow, invalid format, bad cast)
	'23': 409, // integrity_constraint_violation (unique, fkey, exclusion)
	'40': 409, // transaction_rollback (serialization failure, deadlock)
	'53': 503, // insufficient_resources
	'57': 503, // operator_intervention (admin_shutdown, cannot_connect_now)
};

const SQLSTATE_TO_MESSAGE: Record<string, string> = {
	'23502': 'Required field is missing',
	'23503': 'Referenced record does not exist',
	'23505': 'A record with that value already exists',
	'23514': 'Value violates a database constraint',
	'23P01': 'Conflicts with an existing record',
	'22001': 'Input is too long',
	'22003': 'Numeric value out of range',
	'22007': 'Invalid date or time format',
	'22P02': 'Invalid input format',
	'40001': 'Concurrent update — please retry',
	'40P01': 'Deadlock detected — please retry',
	'42501': 'Insufficient privilege',
	'57014': 'Query was canceled',
};

const sqlStateOf = (cause: unknown): string | undefined => {
	const c = cause as { code?: unknown } | null | undefined;
	return typeof c?.code === 'string' ? c.code : undefined;
};

const statusFromSqlState = (code: string | undefined): number => (code ? (SQLSTATE_TO_STATUS[code] ?? SQLSTATE_CLASS_TO_STATUS[code.slice(0, 2)] ?? 500) : 500);

const messageFromSqlState = (code: string | undefined): string => (code ? (SQLSTATE_TO_MESSAGE[code] ?? `Database error (${code})`) : 'Database error');

class PostgresError extends Data.TaggedError('PostgresError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	constructor(args: { cause?: unknown; message?: string } = {}) {
		super({ cause: args.cause, message: messageFromSqlState(sqlStateOf(args.cause)) });
	}
	get code(): string | undefined {
		return sqlStateOf(this.cause);
	}
	get statusCode(): number {
		return statusFromSqlState(this.code);
	}
}

/**
 * Controls how `null`/`undefined` results from a single-row query are surfaced.
 * Omit the option to keep the raw nullable result (default).
 *  - `'fail'`   → unwraps to `NonNullable<T>`, failing with `NoSuchElementException` when missing.
 *  - `'option'` → wraps the result in `Option<NonNullable<T>>`.
 *
 * `applyOnNull` is the shared helper; any future single-row method on `Postgres`
 * should accept `{ onNull }` and route through it so the option behaves identically everywhere.
 */
type OnNullMode = 'fail' | 'option';

const applyOnNull = (eff: Effect.Effect<any, any, any>, mode: OnNullMode | undefined): Effect.Effect<any, any, any> => {
	if (mode === 'fail') return Effect.flatMap(eff, Effect.fromNullable);
	if (mode === 'option') return Effect.map(eff, Option.fromNullable);
	return eff;
};

interface PostgresImpl {
	use: <T>(fn: (sql: InstanceType<typeof SQL>) => T) => Effect.Effect<Awaited<T>, PostgresError, never>;

	first<T extends any[]>(fn: (sql: InstanceType<typeof SQL>) => PromiseLike<T>): Effect.Effect<T[number], PostgresError, never>;
	first<T extends any[]>(fn: (sql: InstanceType<typeof SQL>) => PromiseLike<T>, opts: { onNull: 'fail' }): Effect.Effect<NonNullable<T[number]>, PostgresError | NoSuchElementException, never>;
	first<T extends any[]>(fn: (sql: InstanceType<typeof SQL>) => PromiseLike<T>, opts: { onNull: 'option' }): Effect.Effect<Option.Option<NonNullable<T[number]>>, PostgresError, never>;
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
				use: makeUse(sql, PostgresError, 'Postgres'),
				first: ((fn: (sql: InstanceType<typeof SQL>) => PromiseLike<any>, opts?: { onNull?: OnNullMode }) =>
					applyOnNull(
						Effect.map(impl.use(fn), (rows) => rows[0]),
						opts?.onNull,
					)) as PostgresImpl['first'],
			};
			return Postgres.of(impl);
		},
	);

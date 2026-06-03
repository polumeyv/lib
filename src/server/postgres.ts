/**
 * @module @polumeyv/utils/server/postgres
 *
 * Effect-based Postgres client using Bun's native `SQL` driver.
 *
 * Exports:
 *  - `Postgres`       — Context tag
 *  - `makePostgres`   — Factory: `(config: PostgresConfig) => Effect<Postgres>` (scoped — acquires connection pool, releases on scope close)
 *
 * `PostgresError` wraps Bun's `SQL.PostgresError` (mapped in `./live/postgres`): it carries that
 * error's `code` (SQLSTATE) and `message` verbatim and derives `statusCode` from the SQLSTATE — the
 * one thing Bun doesn't give us — so callers never need to catch or translate it.
 *
 * @example
 * ```ts
 * // App layer construction
 * Layer.effect(Postgres, makePostgres({ hostname, port, database, username, password, searchPath: 'public' }))
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
import type { SQL } from 'bun';
import { Context, Data, Effect, Option } from 'effect';
import type { NoSuchElementError } from 'effect/Cause';
import type { HttpStatusError } from '@polumeyv/lib/error';

// Postgres SQLSTATE → HTTP status. Specific codes override class-level defaults. This is the *only*
// thing we derive ourselves — Bun's `SQL.PostgresError` already carries `code`, `message`, `detail`,
// `hint`, `constraint`, … so there's nothing else worth remapping.
// See https://www.postgresql.org/docs/current/errcodes-appendix.html.
const SQLSTATE_STATUS: Record<string, number> = {
	'23502': 400, // not_null_violation — caller sent NULL into a NOT NULL column
	'23514': 400, // check_violation — caller violated a CHECK constraint
	'42501': 403, // insufficient_privilege
	'57014': 408, // query_canceled
};

const SQLSTATE_CLASS_STATUS: Record<string, number> = {
	'08': 503, // connection_exception
	'22': 400, // data_exception (overflow, invalid format, bad cast)
	'23': 409, // integrity_constraint_violation (unique, fkey, exclusion)
	'40': 409, // transaction_rollback (serialization failure, deadlock)
	'53': 503, // insufficient_resources
	'57': 503, // operator_intervention (admin_shutdown, cannot_connect_now)
};

/** SQLSTATE → HTTP status; 500 when there's no recognizable code (e.g. a dropped connection). */
const statusFromSqlState = (code: string | undefined): number => (code ? (SQLSTATE_STATUS[code] ?? SQLSTATE_CLASS_STATUS[code.slice(0, 2)] ?? 500) : 500);

/**
 * Effect-channel wrapper over a Bun `SQL.PostgresError` (built in `./live/postgres` via
 * `instanceof SQL.PostgresError`). The Bun error is retained as `cause` — keeping `detail`/`hint`/
 * `constraint`/`table`/… available for logs — while its SQLSTATE `code` and server `message` ride
 * along directly. `statusCode` is the lone derived field.
 */
export class PostgresError extends Data.TaggedError('PostgresError')<{ cause?: unknown; code?: string; message?: string }> implements HttpStatusError {
	get statusCode(): number {
		return statusFromSqlState(this.code);
	}
}

export interface PostgresImpl {
	use: <T>(fn: (sql: SQL) => T) => Effect.Effect<Awaited<T>, PostgresError, never>;

	first<T extends any[]>(fn: (sql: SQL) => PromiseLike<T>): Effect.Effect<T[number], PostgresError, never>;
	first<T extends any[]>(fn: (sql: SQL) => PromiseLike<T>, opts: { onNull: 'fail' }): Effect.Effect<NonNullable<T[number]>, PostgresError | NoSuchElementError, never>;
	first<T extends any[]>(fn: (sql: SQL) => PromiseLike<T>, opts: { onNull: 'option' }): Effect.Effect<Option.Option<NonNullable<T[number]>>, PostgresError, never>;
}

export class Postgres extends Context.Service<Postgres, PostgresImpl>()('Postgres') {}

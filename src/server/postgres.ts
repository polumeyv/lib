import { Array as Arr, Context, Data, Effect } from 'effect';
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
const statusFromSqlState = (code: string | undefined): number =>
	code ? (SQLSTATE_STATUS[code] ?? SQLSTATE_CLASS_STATUS[code.slice(0, 2)] ?? 500) : 500;

/**
 * Effect-channel wrapper over a Bun `SQL.PostgresError` (built in `./live/postgres` via
 * `instanceof SQL.PostgresError`). The Bun error is retained as `cause` — keeping `detail`/`hint`/
 * `constraint`/`table`/… available for logs — while its SQLSTATE `code` and server `message` ride
 * along directly. `statusCode` is the lone derived field.
 */
export class PostgresError
	extends Data.TaggedError('PostgresError')<{ cause?: unknown; code?: string; message?: string }>
	implements HttpStatusError
{
	get statusCode(): number {
		return statusFromSqlState(this.code);
	}
}

export interface PostgresImpl {
	/** Run a query and get the **row set** back, as Postgres returns it. For a single row, destructure `const [row] = …`,
	 *  or take the head explicitly: `.pipe(Effect.flatMap((rows) => Effect.fromOption(Arr.head(rows))))` (fails `NoSuchElementError`). */
	use: <T>(fn: (sql: Bun.SQL) => T) => Effect.Effect<Awaited<T>, PostgresError, never>;
}

export class Postgres extends Context.Service<Postgres, PostgresImpl>()('Postgres') {}

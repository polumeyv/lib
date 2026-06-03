/**
 * @module @polumeyv/utils/server/live/postgres
 *
 * The Bun-runtime half of the Postgres service: the `makePostgres` factory that opens a live `SQL`
 * connection pool. Kept separate from `../postgres` (which holds the bun-free `Postgres` tag,
 * `PostgresError`, and impl types) so the tag can be imported from client-reachable graphs without
 * dragging the `bun` builtin into the client bundle. Only server-only layer construction imports this.
 */
import { SQL } from 'bun';
import { Effect, Option } from 'effect';
import { Postgres, PostgresError, type PostgresImpl } from '../postgres';

/**
 * Normalize any throwable into `PostgresError`. A Bun `SQL.PostgresError` hands us its SQLSTATE `code`
 * and server `message` directly (the full error stays as `cause`, keeping `detail`/`hint`/`constraint`/…
 * for logs); anything else (connection drop, sync misuse) becomes a code-less `PostgresError` → status 500.
 */
const toPgError = (cause: unknown): PostgresError =>
	cause instanceof SQL.PostgresError
		? new PostgresError({ cause, code: cause.code, message: cause.message })
		: new PostgresError({ cause, message: cause instanceof Error ? cause.message : String(cause) });

/**
 * Controls how `null`/`undefined` results from a single-row query are surfaced.
 * Omit the option to keep the raw nullable result (default).
 *  - `'fail'`   → unwraps to `NonNullable<T>`, failing with `NoSuchElementError` when missing.
 *  - `'option'` → wraps the result in `Option<NonNullable<T>>`.
 *
 * `applyOnNull` is the shared helper; any future single-row method on `Postgres`
 * should accept `{ onNull }` and route through it so the option behaves identically everywhere.
 */
type OnNullMode = 'fail' | 'option';

const applyOnNull = (eff: Effect.Effect<any, any, any>, mode: OnNullMode | undefined): Effect.Effect<any, any, any> => {
	if (mode === 'fail') return Effect.flatMap(eff, Effect.fromNullishOr);
	if (mode === 'option') return Effect.map(eff, Option.fromNullishOr);
	return eff;
};

/**
 * Discrete connection parameters for the pool — passed directly instead of a single URL so each field is
 * obvious and debuggable. `searchPath` sets the Postgres `search_path` via the startup packet (replacing the
 * old `?options=-csearch_path=…` URL hack); omit it to use the server default (`public`).
 */
export type PostgresConfig = {
	hostname: string;
	port: number | string;
	database: string;
	username: string;
	password: string;
	searchPath?: string;
};

export const makePostgres = (config: PostgresConfig) =>
	Effect.map(
		Effect.acquireRelease(
			Effect.try({
				try: () =>
					new SQL({
						hostname: config.hostname,
						port: Number(config.port),
						database: config.database,
						username: config.username,
						password: config.password,
						idleTimeout: 10,
						max: 20,
						...(config.searchPath ? { connection: { search_path: config.searchPath } } : {}),
					}),
				catch: toPgError,
			}),
			(sql) => Effect.promise(() => sql.close()),
		),
		(sql) => {
			// Sync throw (bad call) and async reject (server/connection error) both funnel through `toPgError`.
			const use = <T>(fn: (sql: SQL) => T): Effect.Effect<Awaited<T>, PostgresError> =>
				Effect.flatMap(
					Effect.try({ try: () => fn(sql), catch: toPgError }),
					(r) => (r instanceof Promise ? Effect.tryPromise({ try: () => r, catch: toPgError }) : Effect.succeed(r as Awaited<T>)),
				);
			const impl: PostgresImpl = {
				use,
				first: ((fn: (sql: SQL) => PromiseLike<any>, opts?: { onNull?: OnNullMode }) =>
					applyOnNull(
						Effect.map(use(fn), (rows) => rows[0]),
						opts?.onNull,
					)) as PostgresImpl['first'],
			};
			return Postgres.of(impl);
		},
	);

/**
 * @module @polumeyv/utils/server/live/postgres
 *
 * The Bun-runtime half of the Postgres service: the `makePostgres` factory that opens a live `SQL`
 * connection pool. Kept separate from `../postgres` (which holds the bun-free `Postgres` tag,
 * `PostgresError`, and impl types) so the tag can be imported from client-reachable graphs without
 * dragging the `bun` builtin into the client bundle. Only server-only layer construction imports this.
 */
import { Array as Arr, Effect } from 'effect';
import { Postgres, PostgresError, type PostgresImpl } from '../postgres';

/**
 * Normalize any throwable into `PostgresError`. A Bun `SQL.PostgresError` carries the **SQLSTATE** (e.g. `'23P01'`) on
 * `.sqlState` (newer, typed `string`, purpose-built) or `.errno` (older — typed `number` but holds the SQLSTATE *string*
 * at runtime; the type-lie tracked in oven-sh/bun#21969). `.code` is Bun's generic tag (`'ERR_POSTGRES_SERVER_ERROR'`),
 * NOT the SQLSTATE. We read `sqlState ?? errno` — forward-compatible: verified that Bun 1.3.14 populates `errno`, not
 * `sqlState`, so this picks up `sqlState` once Bun emits it without behaving differently today. The full error stays as
 * `cause` (keeping `detail`/`constraint`/… for logs); anything else (connection drop, sync misuse) → code-less → 500.
 */
const toPgError = (cause: unknown): PostgresError =>
	cause instanceof Bun.SQL.PostgresError
		? new PostgresError({
				cause,
				code: (cause as { sqlState?: string; errno?: string }).sqlState ?? (cause as { errno?: string }).errno ?? cause.code,
				message: cause.message,
			})
		: new PostgresError({ cause, message: Error.isError(cause) ? cause.message : String(cause) });

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
					new Bun.SQL({
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
			const use = <T>(fn: (sql: Bun.SQL) => T): Effect.Effect<Awaited<T>, PostgresError> =>
				Effect.flatMap(Effect.try({ try: () => fn(sql), catch: toPgError }), (r) =>
					r instanceof Promise ? Effect.tryPromise({ try: () => r, catch: toPgError }) : Effect.succeed(r as Awaited<T>),
				);
			const one = <T>(fn: (sql: Bun.SQL) => T[] | Promise<T[]>) => use(fn).pipe(Effect.flatMap((rows) => Effect.fromOption(Arr.head(rows))));
			const impl: PostgresImpl = { use, one };
			return Postgres.of(impl);
		},
	);

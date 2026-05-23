/**
 * @module @polumeyv/utils/server/postgres.live
 *
 * The Bun-runtime half of the Postgres service: the `makePostgres` factory that opens a live `SQL`
 * connection pool. Kept separate from `./postgres` (which holds the bun-free `Postgres` tag,
 * `PostgresError`, and impl types) so the tag can be imported from client-reachable graphs without
 * dragging the `bun` builtin into the client bundle. Only server-only layer construction imports this.
 */
import { SQL } from 'bun';
import { Effect, Option } from 'effect';
import { Postgres, PostgresError, type PostgresImpl } from './postgres';
import { makeUse } from './use';

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
				first: ((fn: (sql: SQL) => PromiseLike<any>, opts?: { onNull?: OnNullMode }) =>
					applyOnNull(
						Effect.map(impl.use(fn), (rows) => rows[0]),
						opts?.onNull,
					)) as PostgresImpl['first'],
			};
			return Postgres.of(impl);
		},
	);

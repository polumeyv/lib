import { Effect } from 'effect';

/**
 * Builds a `.use(fn)` that wraps a sync-or-async client call in an Effect,
 * mapping any thrown/rejected value to a tagged error of type `E`. Used
 * uniformly across `Postgres`, `Redis`, and `S3` so each wrapper file only
 * declares its tag, error class, and lifecycle.
 */
export const makeUse =
	<C, E>(client: C, Err: new (args: { cause?: unknown; message?: string }) => E, name: string) =>
	<T>(fn: (c: C) => T): Effect.Effect<Awaited<T>, E, never> =>
		Effect.flatMap(Effect.try({ try: () => fn(client), catch: (e) => new Err({ cause: e, message: `Synchronous Error in ${name}.use` }) }), (r) =>
			r instanceof Promise ? Effect.tryPromise({ try: () => r, catch: (e) => new Err({ cause: e, message: `Asynchronous Error in ${name}.use` }) }) : Effect.succeed(r as Awaited<T>),
		);

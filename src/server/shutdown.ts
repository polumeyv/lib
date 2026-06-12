/**
 * @module @polumeyv/lib/server/shutdown
 *
 * Graceful-shutdown hook for a `ManagedRuntime`. Without it the runtime is never disposed: the layer
 * finalizers registered via `Effect.acquireRelease` (Postgres pool close, Redis client close) are dead
 * code and the sockets are torn down by the OS when the process dies. `dispose` interrupts in-flight
 * `run*` fibers (their own finalizers/rollbacks still run), then closes the layer scope in reverse
 * dependency order — dependents before the pools they use.
 */
import type { ManagedRuntime } from 'effect';

/** Dispose the runtime on SIGTERM/SIGINT, then exit. Register once per process, production only — in dev Vite owns the signals and re-imports the runtime module on HMR. */
export const disposeOnShutdown = <R, ER>(runtime: ManagedRuntime.ManagedRuntime<R, ER>): void => {
	let disposing: Promise<void> | undefined;
	for (const signal of ['SIGTERM', 'SIGINT'] as const) {
		process.once(signal, () => {
			// Explicit exit: registering a signal listener suppresses the default terminate-on-signal behavior.
			disposing ??= runtime.dispose().finally(() => process.exit(0));
		});
	}
};

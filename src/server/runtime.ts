/**
 * @module @polumeyv/lib/server/runtime
 *
 * Build a long-lived `ManagedRuntime` for a server app from its service `Layer`, applying the logging + shutdown
 * policy every app shares. Dev: single-line JSON logs (`Logger.consoleJson`) merged in ambiently via the runtime's
 * `CurrentLoggers` reference — no service imports a logger, and terminal output stays machine-legible and pastable.
 * Prod: keep the default logger and register shutdown disposal so the `acquireRelease` finalizers (Postgres pool,
 * Redis client) actually run on SIGTERM/SIGINT. Dev skips disposal on purpose — Vite owns the signals and re-imports
 * this module on HMR, which would stack handlers onto stale runtimes.
 */
import { Layer, Logger, ManagedRuntime } from 'effect';
import { disposeOnShutdown } from './shutdown';

export const makeManagedRuntime = <R, ER>(layer: Layer.Layer<R, ER>, dev: boolean): ManagedRuntime.ManagedRuntime<R, ER> => {
	const runtime = ManagedRuntime.make(Layer.provideMerge(layer, dev ? Logger.layer([Logger.consoleJson]) : Layer.empty));
	if (!dev) disposeOnShutdown(runtime);
	return runtime;
};

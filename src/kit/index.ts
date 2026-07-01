/**
 * @module @polumeyv/lib/kit
 *
 * The one place `@polumeyv/lib` signals meet SvelteKit. The rest of the lib stays purely Effect logic and never
 * imports `@sveltejs/kit`: `@polumeyv/lib/error` defines the tagged signals (`ValidationError`, `Redirect`, the
 * `HttpStatusError` classes) and this entrypoint translates them, once, for every app. Kept on its own subpath so
 * pure-Bun consumers (api servers, utils packages) import `./server`/`./schemas` without dragging in a web
 * framework — `@sveltejs/kit` is an optional peer, required only by importers of `@polumeyv/lib/kit`.
 */
import { Cause, Effect, Exit, Result, type ManagedRuntime } from 'effect';
import { error, invalid, redirect, type RequestEvent } from '@sveltejs/kit';
import type { JWTPayload } from 'jose';
import { ValidationError, Redirect, resolveError } from '../error';
import { IdpClient } from '../server/idp-client';

export interface RunOptions {
	/** Shape the `error()` body from the resolved failure; default is the bare message. Pro returns `{ code, message }`. */
	errorBody?: (resolved: ReturnType<typeof resolveError>) => string | { message: string };
	/** Also log non-5xx failures (dev); server faults always log through the runtime so entries render via the app's loggers. */
	logAll?: boolean;
}

/**
 * Build an app's request boundary over its runtime: accepts a bare Effect or a lazy thunk, returns the success,
 * and translates any failure to a SvelteKit throwable. Lib signals map straight across (`ValidationError` →
 * `invalid`, `Redirect` → `redirect`); everything else (the `HttpStatusError` classes, Effect/framework tags, and
 * infra errors like `PostgresError`) is resolved to `{ status, message, code }` by `resolveError` and thrown via
 * `error`. A 5xx is logged here because SvelteKit's `error()` is an *expected* throw and never reaches the
 * `handleError` hook. `R` is pinned to the runtime's services, so a handler that forgets a service (or
 * accidentally requires `Scope`) is a compile error instead of a runtime defect.
 */
export const makeRun =
	<R, ER>(
		runtime: ManagedRuntime.ManagedRuntime<R, ER>,
		{ errorBody = ({ message }: { message: string }) => message, logAll = false }: RunOptions = {},
	) =>
	<A>(input: RunInput<A, R>): Promise<A> =>
		runtime.runPromiseExit(typeof input === 'function' ? Effect.suspend(input) : input).then((exit) => {
			if (Exit.isSuccess(exit)) return exit.value;

			const err = Cause.squash(exit.cause);
			if (err instanceof ValidationError) return invalid(err.message);
			if (err instanceof Redirect) return redirect(err.status, err.location);

			const resolved = resolveError(err);
			if (logAll || resolved.status >= 500)
				runtime.runFork(Effect.annotateLogs(Effect.logError(resolved.tag, exit.cause), { status: resolved.status }));

			return error(resolved.status, errorBody(resolved) as App.Error);
		});

type RunInput<A, R> = Effect.Effect<A, unknown, R> | (() => Effect.Effect<A, unknown, R>);

/**
 * Event-binding variant of `makeRun`. The returned `run` accepts a bare Effect *or* a thunk that receives the
 * current SvelteKit `RequestEvent`, so handlers read cookies / locals / url without an `$app/server` import per
 * call. The app passes its own `getEvent` (`getRequestEvent` from `$app/server`) — the SvelteKit virtual module
 * stays in the app's build instead of this shared package. `E` is inferred from `getEvent`, so an app that narrows
 * `locals` (e.g. a guaranteed `user`) gets that event type in its handlers with no per-call cast.
 */
export const makeRunner =
	<R, ER, E extends RequestEvent>(runtime: ManagedRuntime.ManagedRuntime<R, ER>, getEvent: () => E, options?: RunOptions) => {
		const boundary = makeRun(runtime, options);
		return <A>(input: Effect.Effect<A, any, R> | ((event: E) => Effect.Effect<A, any, R>)): Promise<A> =>
			boundary(typeof input === 'function' ? () => input(getEvent()) : input);
	};

/**
 * The shared `handle` choreography for IdP-consuming apps: verify-or-refresh the session via
 * `IdpClient.authenticate` (which drives the session cookies itself — fixed policy, jar wired in the app's
 * layer), then either set `locals.user` and return `null`, or short-circuit. An expired session must never
 * dead-end on the gray error page:
 *
 * - navigations and data requests follow the 302 to the authorize URL (kit resolves data-request redirects
 *   client-side, with a native navigation for cross-origin) — a still-alive IdP session re-auths silently;
 * - remote functions can't `goto` a cross-origin URL, so they're bounced back through their own (same-origin)
 *   page, which re-enters this gate as a navigation and takes that same 302. Kit serializes the thrown redirect
 *   into the remote `{type:'redirect'}` envelope, so the client redirects with no session-handling code of its own.
 *
 * Usage: `const gate = await idpSessionGate<UserIdentity>(Runtime, event); if (gate) return gate;`
 */
export const idpSessionGate = async <T extends JWTPayload>(
	runtime: ManagedRuntime.ManagedRuntime<IdpClient, unknown>,
	event: RequestEvent,
): Promise<Response | null> => {
	const auth = await runtime.runPromise(
		Effect.andThen(IdpClient, (idp) => idp.authenticate<T>(event.cookies.get('access_token'), event.cookies.get('refresh_token'))).pipe(
			Effect.tap((r) =>
				Result.isFailure(r)
					? Effect.annotateLogs(Effect.logInfo('idp no usable session → redirect to IdP'), {
							fromHost: event.url.host,
							to: new URL(r.failure).origin,
						})
					: Effect.void,
			),
		),
	);
	if (Result.isFailure(auth)) {
		// Navigations and data-loads follow the cross-origin 302 to the IdP natively. Remote functions can't: kit's
		// remote client follows a redirect via same-origin `goto`, which rejects the cross-origin IdP URL. So bounce
		// the remote call back through its own page — that navigation re-enters this gate and takes the 302 to the IdP
		// (a still-alive IdP session re-auths silently). `?reauth` keeps the URL distinct so `goto` can't no-op on the
		// current page. SvelteKit serializes this thrown redirect into the remote `{type:'redirect'}` envelope
		// automatically (runtime/server/respond.js → redirect_json_response), so no client-side session code is needed.
		if (event.isRemoteRequest) {
			const path = event.request.headers.get('x-sveltekit-pathname') ?? '/';
			const query = event.request.headers.get('x-sveltekit-search') ?? '';
			redirect(302, `${path}${query}${query ? '&' : '?'}reauth`);
		}
		redirect(302, auth.failure);
	}
	// Each app's `App.Locals` declares its own `user` shape; this is the one deliberate write across that seam.
	(event.locals as unknown as { user: T }).user = auth.success;
	return null;
};

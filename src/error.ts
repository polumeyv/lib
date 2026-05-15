import { Cause, Data, Effect } from 'effect';

export interface HttpStatusError {
	readonly statusCode: number;
}

type RedirectStatus = 301 | 302 | 303 | 307 | 308;
/**
 * Lib-side signals translated to SvelteKit's `invalid` / `error` / `redirect` at the
 * route boundary (each app's `db.ts run()`). Keeping these tagged classes here means
 * the lib never imports `@sveltejs/kit`, and route code never calls those framework
 * helpers inline — `Effect.fail(new HttpError(...))` instead of `error(...)`.
 */
export class ValidationError extends Data.TaggedError('ValidationError')<{ readonly message: string }> {}
export class HttpError extends Data.TaggedError('HttpError')<{ readonly status: number; readonly message: string }> {}
export class Unauthorized extends Data.TaggedError('Unauthorized')<{ readonly message: string }> implements HttpStatusError {
	readonly statusCode = 401 as const;
	constructor(message = 'Unauthorized') {
		super({ message });
	}
}
export class Redirect extends Data.TaggedError('Redirect')<{ readonly status: RedirectStatus; readonly location: string }> {
	constructor(arg?: string | { readonly status?: RedirectStatus; readonly location?: string }) {
		const args = typeof arg === 'string' ? { location: arg } : (arg ?? {});
		super({ status: args.status ?? 303, location: args.location ?? '/' });
	}
}

/** Fail an Effect with a redirect. Defaults to `303 /`. */
export const redirect = (location?: string, status?: RedirectStatus) => Effect.fail(new Redirect({ status, location }));

/** Fail an Effect with a 400 validation error. */
export const invalid = (message: string) => Effect.fail(new ValidationError({ message }));

const EFFECT_TAG_STATUS: Record<string, number> = {
	NoSuchElementException: 404,
	IllegalArgumentException: 400,
	ParseError: 400,
	TimeoutException: 408,
	ValidationError: 400,
	HttpError: 500,
	Redirect: 302,
};

export function resolveError(err: unknown): { status: number; message: string; tag: string } {
	const e = err as any;
	return {
		status: typeof e?.statusCode === 'number' ? e.statusCode : typeof e?.status === 'number' ? e.status : typeof e?._tag === 'string' ? (EFFECT_TAG_STATUS[e._tag] ?? 500) : 500,
		message: e?.message || (e?.cause instanceof Error ? e.cause.message : '') || 'Something went wrong. Please try again later.',
		tag: e?._tag ?? 'Defect',
	};
}

/**
 * Catch-all-cause handler: squashes the cause, calls `build` with the squashed
 * value + resolved {status, message}, dies with the result, and logs to
 * `Effect.logError` when status >= 500. The `build` callback owns the
 * framework-specific decision (e.g. pass through SvelteKit HttpError/Redirect,
 * otherwise wrap with `error(status, message)`).
 */
export const handleCause = (cause: Cause.Cause<unknown>, build: (squashed: unknown, info: { status: number; message: string }) => unknown) =>
	((squashed = Cause.squash(cause), info = resolveError(squashed), die = Effect.die(build(squashed, info))) => (info.status < 500 ? die : Effect.zipRight(Effect.logError(info.tag, cause), die)))();

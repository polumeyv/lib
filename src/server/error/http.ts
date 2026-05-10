export interface HttpStatusError {
	readonly statusCode: number;
}

const EFFECT_TAG_STATUS: Record<string, number> = {
	NoSuchElementException: 404,
	IllegalArgumentException: 400,
	ParseError: 400,
	TimeoutException: 408,
};

export function resolveError(err: unknown): { status: number; message: string; tag: string } {
	const e = err as any;
	return {
		status: typeof e?.statusCode === 'number' ? e.statusCode : typeof e?.status === 'number' ? e.status : typeof e?._tag === 'string' ? (EFFECT_TAG_STATUS[e._tag] ?? 500) : 500,
		message: e?.message || (e?.cause instanceof Error ? e.cause.message : '') || 'Something went wrong. Please try again later.',
		tag: e?._tag ?? 'Defect',
	};
}

import { Cause, Effect } from 'effect';

/**
 * Catch-all-cause handler: squashes the cause, calls `build` with the squashed
 * value + resolved {status, message}, dies with the result, and logs to
 * `Effect.logError` when status >= 500. The `build` callback owns the
 * framework-specific decision (e.g. pass through SvelteKit HttpError/Redirect,
 * otherwise wrap with `error(status, message)`).
 */
export const handleCause = (cause: Cause.Cause<unknown>, build: (squashed: unknown, info: { status: number; message: string }) => unknown) =>
	((squashed = Cause.squash(cause), info = resolveError(squashed), die = Effect.die(build(squashed, info))) => (info.status < 500 ? die : Effect.zipRight(Effect.logError(info.tag, cause), die)))();

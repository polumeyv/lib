import { Data } from 'effect';
import * as S from 'effect/Schema';

export interface HttpStatusError {
	readonly statusCode: number;
}
// A class may additionally declare `readonly code: ErrorCode` to pin its wire code (e.g. `SessionExpiredError`). It's NOT on
// the interface on purpose — `PostgresError`/`StripeError` already carry an unrelated `code` (SQLSTATE / Stripe code), so
// `resolveError` duck-types it through `isErrorCode` (which rejects those) rather than forcing every error to declare one.

/**
 * The closed set of client-facing error codes — the single source of truth both apps share (server emits one, client maps
 * it to copy + behavior). Postgres-style stable strings; never leak internal tag names like `NoSuchElementError` over the
 * wire. `BAD_RESPONSE` is client-only (a 2xx whose body failed to decode); `INTERNAL` is the catch-all.
 */
export const ERROR_CODES = [
	'SESSION_EXPIRED',
	'SLOT_TAKEN',
	'PAYMENT_REQUIRED',
	'INVALID_REQUEST',
	'NOT_FOUND',
	'UNAUTHORIZED',
	'BAD_RESPONSE',
	'INTERNAL',
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];
/** Narrow an unknown wire value to a known `ErrorCode` (e.g. a `body.code` from an error response). */
export const isErrorCode = (v: unknown): v is ErrorCode => typeof v === 'string' && (ERROR_CODES as readonly string[]).includes(v);

/** The non-2xx wire body: the stable {@link ErrorCode} plus SvelteKit's `message`. The decode-side twin of
 *  {@link resolveError}'s output — the one schema a cross-app client (`@crescuts/main`'s `pro` transport) decodes an
 *  error response with, so the server's `message` survives the hop instead of being cast away and dropped. */
export const ErrorBody = S.Struct({ code: S.Literals(ERROR_CODES), message: S.optional(S.String) });
export type ErrorBody = typeof ErrorBody.Type;

type RedirectStatus = 301 | 302 | 303 | 307 | 308;
/**
 * Lib-side signals translated to SvelteKit's `invalid` / `error` / `redirect` once, in
 * `@polumeyv/lib/kit`'s `makeRun` (each app's `run()` is built from it). Keeping the tagged
 * classes here keeps the rest of the lib purely Effect logic — `@polumeyv/lib/kit` is the one
 * subpath where they meet the framework — and route code never calls those framework helpers inline:
 * `Effect.fail(new HttpError(...))` instead of `error(...)`.
 */
export class ValidationError extends Data.TaggedError('ValidationError')<{ readonly message: string }> {}
export class HttpError extends Data.TaggedError('HttpError')<{ readonly status: number; readonly message: string }> {}
export class Unauthorized extends Data.TaggedError('Unauthorized')<{ readonly message: string }> implements HttpStatusError {
	readonly statusCode = 401 as const;
	readonly code = 'UNAUTHORIZED' as const;
	constructor(message = 'Unauthorized') {
		super({ message });
	}
}
/** Expired or missing session (Redis key gone). Surfaces as 401; route boundaries catch it to bounce to sign-in / `invalid_grant`. */
export class SessionExpiredError
	extends Data.TaggedError('SessionExpiredError')<{ cause?: unknown; message?: string }>
	implements HttpStatusError
{
	readonly statusCode = 401 as const;
	readonly code = 'SESSION_EXPIRED' as const;
	constructor(args: { cause?: unknown; message?: string } = {}) {
		super({ message: 'Your session has expired, please try again', ...args });
	}
}
export class Redirect extends Data.TaggedError('Redirect')<{ readonly status: RedirectStatus; readonly location: string | URL }> {}

/** Framework/Effect tags that carry no `code` of their own → their `{ status, code }`. The one place tag→status lives. */
const EFFECT_TAG: Record<string, { status: number; code: ErrorCode }> = {
	NoSuchElementError: { status: 404, code: 'NOT_FOUND' },
	IllegalArgumentError: { status: 400, code: 'INVALID_REQUEST' },
	SchemaError: { status: 400, code: 'INVALID_REQUEST' },
	TimeoutError: { status: 408, code: 'INTERNAL' },
	ValidationError: { status: 400, code: 'INVALID_REQUEST' },
	HttpError: { status: 500, code: 'INTERNAL' },
	Redirect: { status: 302, code: 'INTERNAL' },
};

/** Last-resort code from a bare status, for errors with neither an explicit `code` nor a known tag (e.g. a raw `PostgresError`:
 *  a 23xx exclusion/constraint violation arrives as 409 → `SLOT_TAKEN`; that's the only 409 the booking endpoints produce). */
const codeFromStatus = (status: number): ErrorCode =>
	status >= 500
		? 'INTERNAL'
		: status === 404
			? 'NOT_FOUND'
			: status === 401
				? 'UNAUTHORIZED'
				: status === 402
					? 'PAYMENT_REQUIRED'
					: status === 409
						? 'SLOT_TAKEN'
						: 'INVALID_REQUEST';

export function resolveError(err: unknown): { status: number; message: string; tag: string; code: ErrorCode } {
	const e = err as any;
	const tagInfo = typeof e?._tag === 'string' ? EFFECT_TAG[e._tag] : undefined;
	const status = typeof e?.statusCode === 'number' ? e.statusCode : typeof e?.status === 'number' ? e.status : (tagInfo?.status ?? 500);
	// Precedence: the error's own declared `code` (HttpStatusError classes) → its tag's code → derived from the status. A
	// `PostgresError`'s `code` is a SQLSTATE, not an `ErrorCode`, so `isErrorCode` rejects it and it falls through to status.
	const code: ErrorCode = isErrorCode(e?.code) ? e.code : (tagInfo?.code ?? codeFromStatus(status));
	return {
		status,
		message: e?.message || (Error.isError(e?.cause) ? e.cause.message : '') || 'Something went wrong. Please try again later.',
		tag: e?._tag ?? 'Defect',
		code,
	};
}

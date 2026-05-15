import { Data, Schema } from 'effect';
import { BOOKING_STATUS, type BookingStatus } from '../public/types/db/pro.types';
import type { HttpStatusError } from '@polumeyv/lib/error';
import { UserSub } from '../auth';

export { BOOKING_STATUS, type BookingStatus };

// ═══ DOMAIN ERRORS ════════════════════════════════════════════════════════
// Tagged errors for booking-specific HTTP statuses not covered by Effect's
// built-in Cause exceptions or lib's existing per-domain errors.

export class BookingSessionExpiredError extends Data.TaggedError('BookingSessionExpiredError')<{ message: string }> implements HttpStatusError {
	get statusCode() {
		return 410 as const;
	}
}

export class PaymentNotCompletedError extends Data.TaggedError('PaymentNotCompletedError')<{ message: string }> implements HttpStatusError {
	get statusCode() {
		return 402 as const;
	}
}

export class WebhookSignatureError extends Data.TaggedError('WebhookSignatureError')<{ message: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

// ═══ RESPONSE TYPES (raw Postgres shapes) ══════════════════════════════════

export interface BookingListItem {
	id: string;
	status: BookingStatus;
	start_ts: Date;
	end_ts: Date;
	customer_email: string | null;
	customer_phone: string | null;
	amount: number | null;
	notes: string | null;
	sub: typeof UserSub.Type | null;
	dur: number | null;
	service_name: string | null;
	customer_name: string;
}

export interface Booking {
	id: string;
	sub: typeof UserSub.Type | null;
	customer_name: string;
	customer_email: string | null;
	customer_phone: string | null;
	service_name: string | null;
	start_ts: Date;
	end_ts: Date;
	dur: number | null;
	amount: number | null;
	status: BookingStatus;
	notes: string | null;
}

// ═══ SETTINGS ══════════════════════════════════════════════════════════════

export const BookingSettings = Schema.Struct({
	allow_online: Schema.Boolean,
	require_deposit: Schema.Boolean,
	auto_confirm: Schema.Boolean,
	require_payment: Schema.Boolean,
	allow_walkins: Schema.Boolean,
	send_reminders: Schema.Boolean,
	allow_cancel: Schema.Boolean,
	allow_reschedule: Schema.Boolean,
	deposit_amount: Schema.Number,
	deposit_is_fixed: Schema.Boolean,
	cancellation_deadline_hours: Schema.Number,
	max_advance_value: Schema.Number,
	max_advance_in_hours: Schema.Boolean,
	min_advance_value: Schema.Number,
	min_advance_in_hours: Schema.Boolean,
	buf: Schema.Number,
	reminder_hours: Schema.Number,
	cancellation_policy: Schema.optional(Schema.String),
});
export type BookingSettings = typeof BookingSettings.Type;

export const UpdateBookingSettingsS = Schema.partial(BookingSettings);
export type UpdateBookingSettings = typeof UpdateBookingSettingsS.Type;

export const UpdateOnlineBookingS = Schema.partial(
	BookingSettings.pipe(
		Schema.pick('allow_online', 'max_advance_value', 'max_advance_in_hours', 'min_advance_value', 'min_advance_in_hours', 'buf', 'allow_walkins', 'auto_confirm', 'allow_reschedule'),
	),
);

export const UpdateRemindersS = Schema.partial(BookingSettings.pipe(Schema.pick('send_reminders', 'reminder_hours')));

export const UpdateDepositsS = Schema.partial(BookingSettings.pipe(Schema.pick('require_payment', 'require_deposit', 'deposit_amount', 'deposit_is_fixed')));

export const UpdateCancellationS = Schema.partial(BookingSettings.pipe(Schema.pick('allow_cancel', 'cancellation_deadline_hours', 'cancellation_policy')));

// ═══ API CLIENT ════════════════════════════════════════════════════════════

export interface BookingRoutes {
	'GET /bookings': BookingListItem[];
	'GET /bookings/:id': Booking;
	'POST /bookings': { id: string; start_ts: Date; end_ts: Date };
	'PATCH /bookings/:id': { ok: true };
	'GET /settings': BookingSettings;
	'PATCH /settings': { ok: true };
}

type ResolveRoute<M extends string, P extends string> = {
	[K in keyof BookingRoutes]: K extends `${M} ${infer Pattern}`
		? Pattern extends P
			? BookingRoutes[K]
			: Pattern extends `${infer Prefix}/:${string}`
				? P extends `${Prefix}/${string}`
					? BookingRoutes[K]
					: never
				: never
		: never;
}[keyof BookingRoutes];

export function makeBookingApi(opts: { baseUrl: string; getIdentityPath: () => string }) {
	return async function bookingApi<P extends string, M extends 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' = 'GET', R = ResolveRoute<M, P extends `${infer Path}?${string}` ? Path : P>>(
		path: P,
		fetchOpts?: { method?: M; body?: unknown },
	): Promise<R> {
		const identityPath = opts.getIdentityPath();

		const res = await fetch(`${opts.baseUrl}${identityPath}${path}`, {
			method: fetchOpts?.method ?? (fetchOpts?.body ? 'POST' : 'GET'),
			headers: { 'Content-Type': 'application/json' },
			...(fetchOpts?.body ? { body: JSON.stringify(fetchOpts.body) } : {}),
		});

		if (!res.ok) {
			const body = (await res.json().catch(() => ({}))) as { error?: string };
			throw Object.assign(new Error(body.error ?? `API error (${res.status})`), { statusCode: res.status });
		}

		return res.json() as Promise<R>;
	};
}

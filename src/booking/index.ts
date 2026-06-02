import { Data, Struct } from 'effect';
import * as S from 'effect/Schema';
import { BOOKING_STATUS, type BookingStatus } from '../public/types/db/pro.types';
import type { HttpStatusError } from '@polumeyv/lib/error';
import { UserSub } from '../auth';

export { BOOKING_STATUS, type BookingStatus };

export * from './schema';

export * from './utils'

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

export const BookingSettings = S.Struct({
	allow_online: S.Boolean,
	require_deposit: S.Boolean,
	auto_confirm: S.Boolean,
	require_payment: S.Boolean,
	allow_walkins: S.Boolean,
	send_reminders: S.Boolean,
	allow_cancel: S.Boolean,
	allow_reschedule: S.Boolean,
	deposit_amount: S.Number,
	deposit_is_fixed: S.Boolean,
	cancellation_deadline_hours: S.Number,
	max_advance_value: S.Number,
	max_advance_in_hours: S.Boolean,
	min_advance_value: S.Number,
	min_advance_in_hours: S.Boolean,
	buf: S.Number,
	reminder_hours: S.Number,
	cancellation_policy: S.optional(S.String),
});
export type BookingSettings = typeof BookingSettings.Type;

export const UpdateBookingSettingsS = BookingSettings.mapFields(Struct.map(S.optional));
export type UpdateBookingSettings = typeof UpdateBookingSettingsS.Type;

export const UpdateOnlineBookingS = BookingSettings.mapFields(
	Struct.pick([
		'allow_online',
		'max_advance_value',
		'max_advance_in_hours',
		'min_advance_value',
		'min_advance_in_hours',
		'buf',
		'allow_walkins',
		'auto_confirm',
		'allow_reschedule',
	]),
).mapFields(Struct.map(S.optional));

export const UpdateRemindersS = BookingSettings.mapFields(Struct.pick(['send_reminders', 'reminder_hours'])).mapFields(Struct.map(S.optional));

export const UpdateDepositsS = BookingSettings.mapFields(Struct.pick(['require_payment', 'require_deposit', 'deposit_amount', 'deposit_is_fixed'])).mapFields(
	Struct.map(S.optional),
);

export const UpdateCancellationS = BookingSettings.mapFields(Struct.pick(['allow_cancel', 'cancellation_deadline_hours', 'cancellation_policy'])).mapFields(
	Struct.map(S.optional),
);

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
	return async function bookingApi<
		P extends string,
		M extends 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' = 'GET',
		R = ResolveRoute<M, P extends `${infer Path}?${string}` ? Path : P>,
	>(path: P, fetchOpts?: { method?: M; body?: unknown }): Promise<R> {
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

/**
 * Shared booking utilities — wire-format helpers for the booking flow.
 *
 * Wire conventions:
 * - Wall-clock dates/times use ISO strings (`YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`) and are
 *   resolved against the business's timezone server-side via `AT TIME ZONE biz.tz`.
 * - Instants (booking records) use full ISO with `Z`.
 * - Slot responses are `{ start, end }` objects with ISO 8601 `HH:MM` wall-clock times.
 */
import * as S from 'effect/Schema';
import {
	parseTime,
	parseDate,
	CalendarDate,
	CalendarDateTime,
	toCalendarDateTime,
	DateFormatter,
	type TimeDuration,
	Time,
	type DateTimeDuration,
} from '@internationalized/date';
import { BOOKING_STATUS, type ProServicesType } from '../public/types/db/pro.types';

/** Shape returned by GET /book/services/:b_id for each service — the public projection of a `ProServices` row. */
export type Service = Pick<ProServicesType, 'id' | 'type' | 'name' | 'amount' | 'dur'>;

/** ISO 8601 "HH:MM" wall-clock → a UTC instant on the reference day, ready for TIME_FMT.
 *  (DateFormatter renders JS Dates; pinning the instant and the formatter to UTC keeps the
 *   displayed hour/minute identical to the input on any runtime.) */
const timeToDate = (time: string) => toCalendarDateTime(new CalendarDate(1970, 1, 1), parseTime(time)).toDate('UTC');

/** ISO "HH:MM" → "9:30 AM". */
export const formatTimeDisplay = (time: string) => new DateFormatter('en-US', { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' }).format(timeToDate(time));

/** ISO "HH:MM" pair → "9:30 – 10:15 AM" (locale-aware range). */
export const formatTimeRange = (start: string, end: string) =>
	new DateFormatter('en-US', { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' }).formatRange(timeToDate(start), timeToDate(end));

/** Wall-clock components in `tz` → "Monday, January 1, 2024 at 9:30 AM EST".
 *  `CalendarDateTime(...).toDate(tz)` interprets the components as wall-clock time in `tz`. */
export const formatBookingDateTime = (year: number, month: number, day: number, h: number, m: number, tz: string) =>
	new DateFormatter('en-US', {
		weekday: 'long',
		year: 'numeric',
		month: 'long',
		day: 'numeric',
		hour: 'numeric',
		minute: '2-digit',
		timeZone: tz,
		timeZoneName: 'short',
	}).format(new CalendarDateTime(year, month, day, h, m).toDate(tz));

// ═══ Booking DB table schemas ══════════════════════════════════════════════
export type TimeSlot = {
	startsAt: ReturnType<typeof Time.toString>; // Time.toString() → "14:00:00"
	dur: ReturnType<typeof minutesToIso>;
};

const minutesToIso = (m: number) => `PT${m}M`;

// Enums
export const DISCOUNT_TYPE = S.Literals(['percent', 'fixed']);
export type DiscountType = typeof DISCOUNT_TYPE.Type;

export const BOOKING_STEP = S.Literals(['service', 'time', 'details', 'confirm']);
export type BookingStep = typeof BOOKING_STEP.Type;

// Table schemas
export const BookSessions = S.Struct({
	session_id: S.String,
	b_id: S.String,
	service_id: S.NullOr(S.String),
	pro_id: S.NullOr(S.String),
	selected_time: S.NullOr(S.Date),
	duration_mins: S.NullOr(S.Number),
	amount: S.NullOr(S.Number), // cents
	customer_email: S.NullOr(S.String),
	customer_phone: S.NullOr(S.String),
	customer_name: S.NullOr(S.String),
	notes: S.NullOr(S.String),
	step: S.String,
	expires: S.Date,
	updated: S.Date,
});
export type BookSessionsType = typeof BookSessions.Type;

export const BookSlotHolds = S.Struct({
	hold_id: S.String,
	session_id: S.String,
	b_id: S.String,
	pro_id: S.NullOr(S.String),
	time_slot: S.String,
	expires: S.Date,
});
export type BookSlotHoldsType = typeof BookSlotHolds.Type;

export const BookPromoCodes = S.Struct({
	code_id: S.String,
	b_id: S.String,
	code: S.String.pipe(S.check(S.isMinLength(1), S.isMaxLength(50))),
	descr: S.optional(S.String),
	discount_type: DISCOUNT_TYPE,
	discount_value: S.Number, // cents (or percent if discount_type='percent')
	min_purchase: S.optional(S.Number), // cents
	max_discount: S.optional(S.Number), // cents
	usage_limit: S.optional(S.Number),
	usage_count: S.Number,
	valid_from: S.optional(S.Date),
	valid_until: S.optional(S.Date),
	service_ids: S.optional(S.Array(S.String)),
	is_active: S.Boolean,
	updated: S.Date,
});
export type BookPromoCodesType = typeof BookPromoCodes.Type;

export const BookPromoRedemptions = S.Struct({
	id: S.String,
	code_id: S.String,
	customer_email: S.NullOr(S.String),
	discount_applied: S.Number, // cents
	redeemed: S.Date,
});
export type BookPromoRedemptionsType = typeof BookPromoRedemptions.Type;

export const BookGuests = S.Struct({
	guest_id: S.String,
	email: S.String,
	phone: S.NullOr(S.String),
	f_name: S.NullOr(S.String),
	l_name: S.NullOr(S.String),
	booking_count: S.Number,
	last_booking: S.NullOr(S.Date),
	updated: S.Date,
});
export type BookGuestsType = typeof BookGuests.Type;

export const UserBookingRow = S.Struct({
	id: S.String,
	b_id: S.String,
	start_ts: S.Date,
	end_ts: S.Date,
	dur: S.NullOr(S.Number),
	status: BOOKING_STATUS,
	amount: S.NullOr(S.Number),
	notes: S.NullOr(S.String),
	service_name: S.NullOr(S.String),
	business_name: S.String,
	business_address: S.String,
});
export type UserBookingRow = typeof UserBookingRow.Type;

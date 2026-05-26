/**
 * Shared booking utilities — wire-format helpers for the booking flow.
 *
 * Wire conventions:
 * - Wall-clock dates/times use ISO strings (`YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`) and are
 *   resolved against the business's timezone server-side via `AT TIME ZONE biz.tz`.
 * - Instants (booking records) use full ISO with `Z`.
 * - Slot responses are `{ start, end }` objects with ISO 8601 `HH:MM` wall-clock times.
 */
import { Schema } from 'effect';
import { parseTime, parseDate, CalendarDate, CalendarDateTime, toCalendarDateTime, DateFormatter } from '@internationalized/date';
import { BOOKING_STATUS, type ProServicesType } from '../public/types/db/pro.types';

/** Shape returned by GET /book/services/:b_id for each service — the public projection of a `ProServices` row. */
export type Service = Pick<ProServicesType, 'id' | 'type' | 'name' | 'amount' | 'dur'>;

/** An available booking slot — ISO 8601 "HH:MM" wall-clock start/end, as returned by /book/day and /book/month. */
export type Slot = { start: string; end: string };

/** ISO 8601 "HH:MM" wall-clock → a UTC instant on the reference day, ready for TIME_FMT.
 *  (DateFormatter renders JS Dates; pinning the instant and the formatter to UTC keeps the
 *   displayed hour/minute identical to the input on any runtime.) */
const timeToDate = (time: string) => toCalendarDateTime(new CalendarDate(1970, 1, 1), parseTime(time)).toDate('UTC');

/** ISO "HH:MM" → "9:30 AM". */
export const formatTimeDisplay = (time: string) => new DateFormatter('en-US', { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' }).format(timeToDate(time));

/** ISO "HH:MM" pair → "9:30 – 10:15 AM" (locale-aware range). */
export const formatTimeRange = (start: string, end: string) =>
	new DateFormatter('en-US', { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' }).formatRange(timeToDate(start), timeToDate(end));

/** ISO "YYYY-MM-DD" → "Monday, January 1, 2024". */
export const formatBookingDate = (dateStr: string) =>
	new DateFormatter('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' }).format(parseDate(dateStr).toDate('UTC'));

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

// Enums
export const DISCOUNT_TYPE = Schema.Literals(['percent', 'fixed']);
export type DiscountType = typeof DISCOUNT_TYPE.Type;

export const BOOKING_STEP = Schema.Literals(['service', 'time', 'details', 'confirm']);
export type BookingStep = typeof BOOKING_STEP.Type;

// Table schemas
export const BookSessions = Schema.Struct({
	session_id: Schema.String,
	b_id: Schema.String,
	service_id: Schema.NullOr(Schema.String),
	pro_id: Schema.NullOr(Schema.String),
	selected_time: Schema.NullOr(Schema.Date),
	duration_mins: Schema.NullOr(Schema.Number),
	amount: Schema.NullOr(Schema.Number), // cents
	customer_email: Schema.NullOr(Schema.String),
	customer_phone: Schema.NullOr(Schema.String),
	customer_name: Schema.NullOr(Schema.String),
	notes: Schema.NullOr(Schema.String),
	step: Schema.String,
	expires: Schema.Date,
	updated: Schema.Date,
});
export type BookSessionsType = typeof BookSessions.Type;

export const BookSlotHolds = Schema.Struct({
	hold_id: Schema.String,
	session_id: Schema.String,
	b_id: Schema.String,
	pro_id: Schema.NullOr(Schema.String),
	time_slot: Schema.String,
	expires: Schema.Date,
});
export type BookSlotHoldsType = typeof BookSlotHolds.Type;

export const BookPromoCodes = Schema.Struct({
	code_id: Schema.String,
	b_id: Schema.String,
	code: Schema.String.pipe(Schema.check(Schema.isMinLength(1), Schema.isMaxLength(50))),
	descr: Schema.optional(Schema.String),
	discount_type: DISCOUNT_TYPE,
	discount_value: Schema.Number, // cents (or percent if discount_type='percent')
	min_purchase: Schema.optional(Schema.Number), // cents
	max_discount: Schema.optional(Schema.Number), // cents
	usage_limit: Schema.optional(Schema.Number),
	usage_count: Schema.Number,
	valid_from: Schema.optional(Schema.Date),
	valid_until: Schema.optional(Schema.Date),
	service_ids: Schema.optional(Schema.Array(Schema.String)),
	is_active: Schema.Boolean,
	updated: Schema.Date,
});
export type BookPromoCodesType = typeof BookPromoCodes.Type;

export const BookPromoRedemptions = Schema.Struct({
	id: Schema.String,
	code_id: Schema.String,
	customer_email: Schema.NullOr(Schema.String),
	discount_applied: Schema.Number, // cents
	redeemed: Schema.Date,
});
export type BookPromoRedemptionsType = typeof BookPromoRedemptions.Type;

export const BookGuests = Schema.Struct({
	guest_id: Schema.String,
	email: Schema.String,
	phone: Schema.NullOr(Schema.String),
	f_name: Schema.NullOr(Schema.String),
	l_name: Schema.NullOr(Schema.String),
	booking_count: Schema.Number,
	last_booking: Schema.NullOr(Schema.Date),
	updated: Schema.Date,
});
export type BookGuestsType = typeof BookGuests.Type;

export const UserBookingRow = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	start_ts: Schema.Date,
	end_ts: Schema.Date,
	dur: Schema.NullOr(Schema.Number),
	status: BOOKING_STATUS,
	amount: Schema.NullOr(Schema.Number),
	notes: Schema.NullOr(Schema.String),
	service_name: Schema.NullOr(Schema.String),
	business_name: Schema.String,
	business_address: Schema.String,
});
export type UserBookingRow = typeof UserBookingRow.Type;

/**
 * @module @polumeyv/lib/schemas/projections
 *
 * ## Tier 3 — groupings
 *
 * Schemas composed for a specific use: API payloads, form inputs, cross-table shapes, name-mapped views.
 *
 * **Import rule:** build these from `./tables` wherever possible, so a grouping tracks the canonical row
 * automatically (pick/omit/extend a table's fields — never re-declare a column that already lives on a
 * table). Fall back to `./primitives` only for shapes with no table backing (e.g. a Stripe-derived blob).
 *
 * The `UserName` lineage is the reference pattern: `primitives.Name` defines the field shape →
 * `tables.Users` assigns it to `f_name`/`l_name` → here we `pick` those two back out as a reusable group.
 */
import * as S from 'effect/Schema';
import { Struct, SchemaTransformation } from 'effect';
import * as Tables from './tables';
import { Cents } from './primitives';

/** `users(sub, email)` — the minimal identity slice. */
export const UserIdentity = Tables.Users.mapFields(Struct.pick(['sub', 'email']));
export type UserIdentity = typeof UserIdentity.Type;

/** First/last name pulled straight from the users table — the canonical name shape. */
export const UserName = Tables.Users.mapFields(Struct.pick(['f_name', 'l_name']));
export type UserName = typeof UserName.Type;

/** Card summary surfaced to clients — not a table column, a Stripe-derived shape. */
export const PaymentMethod = S.NullOr(S.Struct({ brand: S.String, last4: S.String }));
export type PaymentMethod = typeof PaymentMethod.Type;

// ── Pro-app DB projections ───────────────────────────────────────────────────
// App-contract views of the canonical tables: lookup-id columns surfaced as their
// names (`b_type`/`status`/`type` → the literal), and form-friendly strictness
// (non-null amounts, mutable arrays) the app guarantees beyond the raw DDL.

/** businesses row with lookup ids surfaced as names + form-mutable `tip_percentages`. */
export const ProBusinesses = S.Struct({
	...Tables.Businesses.fields,
	b_type: Tables.B_TYPE,
	payout_schedule: Tables.PAYOUT_SCHEDULE,
	tip_percentages: S.mutable(S.Array(S.Number)),
});
export type ProBusinesses = typeof ProBusinesses.Type;

/** Booking-settings subset of the merged businesses row (UI groups these on /settings/booking). */
export const ProBookingSettings = ProBusinesses.mapFields(
	Struct.pick([
		'b_id',
		'allow_online',
		'require_deposit',
		'auto_confirm',
		'require_payment',
		'allow_walkins',
		'send_reminders',
		'allow_cancel',
		'allow_reschedule',
		'deposit_amount',
		'deposit_is_fixed',
		'cancellation_deadline_hours',
		'max_advance_value',
		'max_advance_in_hours',
		'min_advance_value',
		'min_advance_in_hours',
		'buf',
		'reminder_hours',
		'cancellation_policy',
		'updated',
	]),
);
export type ProBookingSettings = typeof ProBookingSettings.Type;

/** Financial-settings subset of the merged businesses row (UI groups these on /settings/financials). */
export const ProFinancialSettings = ProBusinesses.mapFields(
	Struct.pick([
		'b_id',
		'tax_enabled',
		'tax_included',
		'tips_enabled',
		'tips_custom',
		'refunds_enabled',
		'refunds_partial',
		'tax_rate',
		'tip_percentages',
		'refund_deadline_days',
		'refund_percentage',
		'payout_schedule',
		'minimum_payout',
		'updated',
	]),
);
export type ProFinancialSettings = typeof ProFinancialSettings.Type;

/** Hours read straight from the canonical table (week_day + ranges checks already match). */
export const ProHours = Tables.Hours;
export type ProHours = typeof ProHours.Type;

/** services row: `type` as its name, and `amount`/`dur` asserted non-null (the app only reads priced, timed services). */
export const ProServices = S.Struct({
	...Tables.Services.fields,
	type: Tables.SERVICE_TYPE,
	amount: Cents,
	dur: S.Number,
	buf: S.NullOr(S.Number),
});
export type ProServices = typeof ProServices.Type;

/** products row with `price` asserted non-null. */
export const ProProducts = S.Struct({
	...Tables.Products.fields,
	price: Cents,
});
export type ProProducts = typeof ProProducts.Type;

/** clients row: `status` as its name, `f_name` required. */
export const ProClients = S.Struct({
	...Tables.Clients.fields,
	f_name: S.String,
	status: Tables.CLIENT_STATUS,
});
export type ProClients = typeof ProClients.Type;

/** bookings row with `status` as its name (drops the write-only `reminder_sent_at`). */
export const ProBookings = S.Struct({
	...Tables.Bookings.fields,
	status: Tables.BOOKING_STATUS,
}).mapFields(Struct.omit(['reminder_sent_at']));
export type ProBookings = typeof ProBookings.Type;

/** bookings_v shape — a booking plus the joined range bounds + service duration. */
export const ProBookingsView = ProBookings.pipe(S.fieldsAssign({ start_time: S.String, dur: S.NullOr(S.Number) }));
export type ProBookingsView = typeof ProBookingsView.Type;

export const ProStripeCustomers = Tables.StripeCustomers;
export type ProStripeCustomers = typeof ProStripeCustomers.Type;

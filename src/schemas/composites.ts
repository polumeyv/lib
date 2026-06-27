/**
 * @module @polumeyv/lib/schemas/composites
 *
 * ## Tier 4 — composites
 *
 * Fully-composed, standalone schemas built for an app I/O contract (a form, a request/response payload)
 * that is NOT derived from a single table — there is no DB row behind it. A composite reuses
 * `./primitives` (and may reference `./projections` / `./tables`), but it originates here.
 *
 * **Import rule:** this is the top tier. It may import from primitives, tables, and projections; nothing
 * in those lower tiers imports from here. Litmus test: if a schema is just a reshaped table row it's a
 * *projection*; a composite is the one with no canonical table behind it (e.g. a contact form — there is
 * no `contacts` table).
 */
import { Struct, Effect, SchemaTransformation } from 'effect';
import * as S from 'effect/Schema';
import { Email, PhoneNA } from './primitives';
import { UserName, ProBookings } from './projections';

// ── Booking domain ───────────────────────────────────────────────────────────

/** Customer details collected on the booking info step. */
export const BookingUserInfo = S.Struct({
	...UserName.fields,
	email: Email,
	phone: PhoneNA,
});
export type BookingUserInfo = typeof BookingUserInfo.Type;

// The public booking *API contract* (`Service`, `BookingFinancials`, the request/response schemas) is owned by
// polumeyv-pro and lives in `@polumeyv/pro-api` — not here, since `shared/lib` is for cross-product primitives, not one
// product's endpoints. `BookingUserInfo` stays: it's a reusable contact-info shape, and `@polumeyv/pro-api` composes it.

/** Pro-side bookings list/detail: the `bookings` columns (via `ProBookings`) plus the join-only fields —
 *  range bounds as instants, joined service name, resolved customer name. */
export const Booking = ProBookings.mapFields(
	Struct.pick(['id', 'sub', 'status', 'amount', 'notes', 'customer_email', 'customer_phone']),
).pipe(
	S.fieldsAssign({
		start_ts: S.Date, // lower(time_slot)
		end_ts: S.Date, // upper(time_slot)
		dur: S.NullOr(S.Number), // services.dur (LEFT JOIN)
		service_name: S.NullOr(S.String), // services.name (LEFT JOIN)
		customer_name: S.String, // COALESCE(client/guest name, fallback)
	}),
);
export type Booking = typeof Booking.Type;

/** A user's booking as read for the appointments list: the `bookings` columns (via `ProBookings`) plus the
 *  join-only fields — range bounds, joined service name, business name + address. */
export const UserBookingRow = ProBookings.mapFields(Struct.pick(['id', 'b_id', 'status', 'amount', 'notes'])).pipe(
	S.fieldsAssign({
		start_ts: S.Date,
		end_ts: S.Date,
		dur: S.NullOr(S.Number), // services.dur (LEFT JOIN)
		service_name: S.NullOr(S.String), // services.name (LEFT JOIN)
		business_name: S.String,
		business_address: S.String,
	}),
);
export type UserBookingRow = typeof UserBookingRow.Type;

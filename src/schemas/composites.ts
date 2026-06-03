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
import { Struct } from 'effect';
import * as S from 'effect/Schema';
import { Email, Phone } from './primitives';
import { UserName, ProBookings, type ProServices } from './projections';

/**
 * Contact form. The `subject`/`social_platform` value sets are inlined as `S.Literals` — consumers that
 * need the raw arrays read them back off the schema (`ContactS.fields.subject.literals`,
 * `ContactS.fields.social_platform.literals`) rather than importing a separate const.
 */
export const ContactS = S.Struct({
	...UserName.fields,
	email: S.optional(Email),
	phone: S.optional(Phone),
	message: S.String.pipe(
		S.check(S.isMinLength(2, { message: 'Message must be at least 2 characters' }), S.isMaxLength(300, { message: 'Message must be at most 300 characters' })),
	),
	subject: S.Literals(['General Inquiry', 'Appointment Question', 'Feedback']),
	social_platform: S.Literals(['instagram', 'x', 'linkedin', 'other']),
	social: S.optional(S.String),
})
	.mapFields(Struct.map(S.mutableKey))
	.pipe(
		S.check(
			S.makeFilter((d) => !!(d.email || d.phone), {
				message: 'Please provide an email or phone number so we can reach you.',
			}),
		),
	);
export type ContactData = typeof ContactS.Type;

// ── Booking domain ───────────────────────────────────────────────────────────

/** Customer details collected on the booking info step. */
export const BookingUserInfo = S.Struct({
	...UserName.fields,
	email: Email,
	phone: Phone,
});
export type BookingUserInfo = typeof BookingUserInfo.Type;

/** Public projection of a `ProServices` row — the shape returned by GET /book/services/:b_id. */
export type Service = Pick<ProServices, 'id' | 'type' | 'name' | 'amount' | 'dur'>;

/** A chosen slot on the wire: `startsAt` as `HH:MM:SS`, `dur` as an ISO 8601 duration (`PT{minutes}M`). No table backs it. */
export type TimeSlot = { startsAt: string; dur: string };

/** Pro-side bookings list/detail: the `bookings` columns (via `ProBookings`) plus the join-only fields —
 *  range bounds as instants, joined service name, resolved customer name. */
export const Booking = ProBookings.mapFields(Struct.pick(['id', 'sub', 'status', 'amount', 'notes', 'customer_email', 'customer_phone'])).pipe(
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

import { Struct } from 'effect';
import * as S from 'effect/Schema';

// Enums
export const B_TYPE = S.Literals(['salon', 'barbershop', 'spa', 'nails', 'esthetics', 'makeup', 'tattoo', 'other']);
export type BType = typeof B_TYPE.Type;

export const CLIENT_STATUS = S.Literals(['active', 'inactive', 'vip', 'new', 'at_risk']);
export type ClientStatus = typeof CLIENT_STATUS.Type;

export const SERVICE_TYPE = S.Literals(['service', 'addon']);
export type ServiceType = typeof SERVICE_TYPE.Type;

export const AVAILABILITY_TYPE = S.Literals(['recurring', 'specific_date', 'flexible', 'blocked']);
export type AvailabilityType = typeof AVAILABILITY_TYPE.Type;

export const BOOKING_STATUS = S.Literals(['pending', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show']);
export type BookingStatus = typeof BOOKING_STATUS.Type;

export const PAYOUT_SCHEDULE = S.Literals(['daily', 'weekly', 'biweekly', 'monthly']);
export type PayoutSchedule = typeof PAYOUT_SCHEDULE.Type;

export const SERVICE_CATEGORY = S.Literals(['haircut', 'color', 'styling', 'treatment', 'extension', 'nails', 'wax', 'facial', 'makeup', 'massage', 'other']);
export type ServiceCategory = typeof SERVICE_CATEGORY.Type;

// Business: identity + booking settings + financial settings (1:1 collapsed into one row)
export const ProBusinesses = S.Struct({
	b_id: S.String,
	owner_sub: S.String,
	legal_name: S.String,
	dba: S.NullOr(S.String),
	tax_id: S.NullOr(S.String),
	license_number: S.NullOr(S.String),
	b_type: B_TYPE,
	website: S.NullOr(S.String),
	phone: S.NullOr(S.String),
	email: S.NullOr(S.String),
	status: S.Number,
	tz: S.String, // us_timezone, e.g. "America/New_York"
	source: S.String,
	listing_id: S.NullOr(S.String),
	verified_at: S.NullOr(S.Date),
	stripe_account_id: S.NullOr(S.String), // Stripe Connect account ID (acct_xxx)
	platform_fee_bps: S.Number, // basis points withheld via application_fee_amount on destination charges
	charges_enabled: S.Boolean, // cached from Stripe account.updated webhook
	onboarding_complete: S.Boolean, // cached from Stripe account.updated webhook
	payouts_enabled: S.Boolean, // cached from Stripe account.updated webhook
	// Booking settings
	allow_online: S.Boolean,
	require_deposit: S.Boolean,
	auto_confirm: S.Boolean,
	require_payment: S.Boolean,
	allow_walkins: S.Boolean,
	send_reminders: S.Boolean,
	allow_cancel: S.Boolean,
	allow_reschedule: S.Boolean,
	deposit_amount: S.Number, // cents
	deposit_is_fixed: S.Boolean,
	cancellation_deadline_hours: S.Number,
	max_advance_value: S.Number,
	max_advance_in_hours: S.Boolean,
	min_advance_value: S.Number,
	min_advance_in_hours: S.Boolean,
	buf: S.Number,
	reminder_hours: S.Number,
	cancellation_policy: S.NullOr(S.String),
	// Financial settings
	tax_enabled: S.Boolean,
	tax_included: S.Boolean,
	tips_enabled: S.Boolean,
	tips_custom: S.Boolean,
	refunds_enabled: S.Boolean,
	refunds_partial: S.Boolean,
	tax_rate: S.Number, // DECIMAL(5,3); read sites cast `::float8` → number, and the `n:tax_rate` form field arrives pre-coerced to number
	tip_percentages: S.mutable(S.Array(S.Number)),
	refund_deadline_days: S.Number,
	refund_percentage: S.Number,
	payout_schedule: PAYOUT_SCHEDULE,
	minimum_payout: S.Number, // cents
	updated: S.Date,
});


export type ProBusinessesType = typeof ProBusinesses.Type;

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
export type ProBookingSettingsType = typeof ProBookingSettings.Type;

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
export type ProFinancialSettingsType = typeof ProFinancialSettings.Type;

export const ProAddresses = S.Struct({
	id: S.String.check(S.isUUID()),
	owner_id: S.String,
	address_type: S.String,
	street: S.String,
	unit: S.NullOr(S.String),
	city: S.NullOr(S.String),
	state: S.NullOr(S.String),
	zip: S.NullOr(S.String),
	country: S.NullOr(S.String),
	name: S.NullOr(S.String),
	icon: S.String,
	is_default: S.Boolean,
	coord: S.NullOr(S.Tuple([S.Number, S.Number])), // [lat, lng]
	updated: S.Date,
});
export type ProAddressesType = typeof ProAddresses.Type;

export const ProHours = S.Struct({
	id: S.String,
	b_id: S.String,
	week_day: S.Number,
	// Open ranges for the day as `{ start, end }` (`HH:MM`); empty array = closed. The gaps between ranges are the
	// day's breaks. Stored as a JSONB array (Bun decodes it straight to a JS array), so no single-break columns.
	ranges: S.Array(S.Struct({ start: S.String, end: S.String })),
	updated: S.Date,
});
export type ProHoursType = typeof ProHours.Type;

// Services / Catalog
export const ProServices = S.Struct({
	id: S.String,
	b_id: S.String,
	category_id: S.NullOr(S.Number),
	type: SERVICE_TYPE,
	name: S.String,
	descr: S.NullOr(S.String),
	amount: S.Number, // cents
	dur: S.Number,
	buf: S.NullOr(S.Number),
	active: S.Boolean,
	updated: S.Date,
});
export type ProServicesType = typeof ProServices.Type;

// Retail products (catalog, sold to clients during appointments)
export const ProProducts = S.Struct({
	id: S.String,
	b_id: S.String,
	name: S.String,
	descr: S.NullOr(S.String),
	price: S.Number, // cents
	stock: S.NullOr(S.Number), // null = stock not tracked
	active: S.Boolean,
	updated: S.Date,
});
export type ProProductsType = typeof ProProducts.Type;

// Clients
export const ProClients = S.Struct({
	client_id: S.String,
	b_id: S.String,
	sub: S.NullOr(S.String),
	f_name: S.String,
	l_name: S.NullOr(S.String),
	email: S.NullOr(S.String),
	phone: S.NullOr(S.String),
	company: S.NullOr(S.String),
	status: CLIENT_STATUS,
	notes: S.NullOr(S.String),
	tags: S.NullOr(S.Array(S.String)),
	updated: S.Date,
});
export type ProClientsType = typeof ProClients.Type;

// Bookings
export const ProBookings = S.Struct({
	id: S.String,
	b_id: S.String,
	sub: S.String,
	service_id: S.String,
	pro_id: S.NullOr(S.String),
	customer_email: S.NullOr(S.String),
	customer_phone: S.NullOr(S.String),
	time_slot: S.String,
	status: BOOKING_STATUS,
	amount: S.Number, // cents
	notes: S.NullOr(S.String),
	cancellation_reason: S.NullOr(S.String),
	cancelled_by: S.NullOr(S.String),
	cancelled: S.NullOr(S.Date),
	completed: S.NullOr(S.Date),
	payment_intent_id: S.NullOr(S.String),
	payment_status: S.String, // 'none' | Stripe PI status | 'refunded' | 'disputed'
	platform_fee_amount: S.NullOr(S.Number), // cents
	transfer_id: S.NullOr(S.String),
	updated: S.Date,
});
export type ProBookingsType = typeof ProBookings.Type;

export const ProBookingsView = ProBookings.pipe(
	S.fieldsAssign({
		start_time: S.String,
		dur: S.NullOr(S.Number),
	}),
);
export type ProBookingsViewType = typeof ProBookingsView.Type;

export const ProStripeCustomers = S.Struct({
	sub: S.String,
	stripe_customer_id: S.String,
});
export type ProStripeCustomersType = typeof ProStripeCustomers.Type;

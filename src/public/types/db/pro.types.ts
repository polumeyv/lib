import { Schema } from 'effect';

// Enums
export const B_TYPE = Schema.Literal('salon', 'barbershop', 'spa', 'nails', 'esthetics', 'makeup', 'tattoo', 'other');
export type BType = typeof B_TYPE.Type;

export const CLIENT_STATUS = Schema.Literal('active', 'inactive', 'vip', 'new', 'at_risk');
export type ClientStatus = typeof CLIENT_STATUS.Type;

export const SERVICE_TYPE = Schema.Literal('service', 'addon');
export type ServiceType = typeof SERVICE_TYPE.Type;

export const AVAILABILITY_TYPE = Schema.Literal('recurring', 'specific_date', 'flexible', 'blocked');
export type AvailabilityType = typeof AVAILABILITY_TYPE.Type;

export const BOOKING_STATUS = Schema.Literal('pending', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show');
export type BookingStatus = typeof BOOKING_STATUS.Type;

export const PAYOUT_SCHEDULE = Schema.Literal('daily', 'weekly', 'biweekly', 'monthly');
export type PayoutSchedule = typeof PAYOUT_SCHEDULE.Type;

export const SERVICE_CATEGORY = Schema.Literal('haircut', 'color', 'styling', 'treatment', 'extension', 'nails', 'wax', 'facial', 'makeup', 'massage', 'other');
export type ServiceCategory = typeof SERVICE_CATEGORY.Type;

// Business: identity + booking settings + financial settings (1:1 collapsed into one row)
export const ProBusinesses = Schema.Struct({
	b_id: Schema.String,
	owner_sub: Schema.String,
	legal_name: Schema.String,
	dba: Schema.optional(Schema.String),
	tax_id: Schema.NullOr(Schema.String),
	license_number: Schema.NullOr(Schema.String),
	b_type: B_TYPE,
	website: Schema.optional(Schema.String),
	phone: Schema.optional(Schema.String),
	email: Schema.optional(Schema.String),
	status: Schema.Number,
	verified_at: Schema.NullOr(Schema.DateFromSelf),
	stripe_account_id: Schema.NullOr(Schema.String), // Stripe Connect account ID (acct_xxx)
	// Booking settings
	allow_online: Schema.Boolean,
	require_deposit: Schema.Boolean,
	auto_confirm: Schema.Boolean,
	require_payment: Schema.Boolean,
	allow_walkins: Schema.Boolean,
	send_reminders: Schema.Boolean,
	allow_cancel: Schema.Boolean,
	allow_reschedule: Schema.Boolean,
	deposit_amount: Schema.Number, // cents
	deposit_is_fixed: Schema.Boolean,
	cancellation_deadline_hours: Schema.Number,
	max_advance_value: Schema.Number,
	max_advance_in_hours: Schema.Boolean,
	min_advance_value: Schema.Number,
	min_advance_in_hours: Schema.Boolean,
	buf: Schema.Number,
	reminder_hours: Schema.Number,
	cancellation_policy: Schema.optional(Schema.String),
	// Financial settings
	tax_enabled: Schema.Boolean,
	tax_included: Schema.Boolean,
	tips_enabled: Schema.Boolean,
	tips_custom: Schema.Boolean,
	refunds_enabled: Schema.Boolean,
	refunds_partial: Schema.Boolean,
	currency: Schema.String,
	tax_rate: Schema.Number,
	tip_percentages: Schema.mutable(Schema.Array(Schema.Number)),
	refund_deadline_days: Schema.Number,
	refund_percentage: Schema.Number,
	payout_schedule: PAYOUT_SCHEDULE,
	minimum_payout: Schema.Number, // cents
	updated: Schema.DateFromSelf,
});
export type ProBusinessesType = typeof ProBusinesses.Type;

/** Booking-settings subset of the merged businesses row (UI groups these on /settings/booking). */
export const ProBookingSettings = ProBusinesses.pipe(
	Schema.pick(
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
	),
);
export type ProBookingSettingsType = typeof ProBookingSettings.Type;

/** Financial-settings subset of the merged businesses row (UI groups these on /settings/financials). */
export const ProFinancialSettings = ProBusinesses.pipe(
	Schema.pick(
		'b_id',
		'tax_enabled',
		'tax_included',
		'tips_enabled',
		'tips_custom',
		'refunds_enabled',
		'refunds_partial',
		'currency',
		'tax_rate',
		'tip_percentages',
		'refund_deadline_days',
		'refund_percentage',
		'payout_schedule',
		'minimum_payout',
		'updated',
	),
);
export type ProFinancialSettingsType = typeof ProFinancialSettings.Type;

export const ProAddresses = Schema.Struct({
	id: Schema.UUID,
	owner_id: Schema.String,
	address_type: Schema.String,
	street: Schema.String,
	unit: Schema.NullOr(Schema.String),
	city: Schema.NullOr(Schema.String),
	state: Schema.NullOr(Schema.String),
	zip: Schema.NullOr(Schema.String),
	country: Schema.NullOr(Schema.String),
	name: Schema.NullOr(Schema.String),
	icon: Schema.String,
	is_default: Schema.Boolean,
	coord: Schema.NullOr(Schema.Tuple(Schema.Number, Schema.Number)), // [lat, lng]
	updated: Schema.DateFromSelf,
});
export type ProAddressesType = typeof ProAddresses.Type;

export const ProHours = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	week_day: Schema.Number,
	open_time: Schema.NullOr(Schema.String),
	close_time: Schema.NullOr(Schema.String),
	closed: Schema.Boolean,
	break_start: Schema.NullOr(Schema.String),
	break_end: Schema.NullOr(Schema.String),
	updated: Schema.DateFromSelf,
});
export type ProHoursType = typeof ProHours.Type;

// Services / Catalog
export const ProServices = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	category_id: Schema.NullOr(Schema.Number),
	type: SERVICE_TYPE,
	name: Schema.String,
	descr: Schema.NullOr(Schema.String),
	amount: Schema.Number, // cents
	dur: Schema.Number,
	buf: Schema.NullOr(Schema.Number),
	active: Schema.Boolean,
	updated: Schema.DateFromSelf,
});
export type ProServicesType = typeof ProServices.Type;

// Clients
export const ProClients = Schema.Struct({
	client_id: Schema.String,
	b_id: Schema.String,
	sub: Schema.NullOr(Schema.String),
	f_name: Schema.String,
	l_name: Schema.optional(Schema.String),
	email: Schema.optional(Schema.String),
	phone: Schema.optional(Schema.String),
	company: Schema.optional(Schema.String),
	status: CLIENT_STATUS,
	notes: Schema.optional(Schema.String),
	tags: Schema.optional(Schema.Array(Schema.String)),
	updated: Schema.DateFromSelf,
});
export type ProClientsType = typeof ProClients.Type;

// Bookings
export const ProBookings = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	sub: Schema.String,
	service_id: Schema.String,
	pro_id: Schema.NullOr(Schema.String),
	customer_email: Schema.NullOr(Schema.String),
	customer_phone: Schema.NullOr(Schema.String),
	time_slot: Schema.String,
	status: BOOKING_STATUS,
	amount: Schema.NullOr(Schema.Number), // cents
	notes: Schema.NullOr(Schema.String),
	cancellation_reason: Schema.NullOr(Schema.String),
	cancelled_by: Schema.NullOr(Schema.String),
	cancelled: Schema.NullOr(Schema.DateFromSelf),
	completed: Schema.NullOr(Schema.DateFromSelf),
	updated: Schema.DateFromSelf,
});
export type ProBookingsType = typeof ProBookings.Type;

export const ProBookingsView = Schema.extend(ProBookings, Schema.Struct({
	start_time: Schema.String,
	dur: Schema.NullOr(Schema.Number),
}));
export type ProBookingsViewType = typeof ProBookingsView.Type;

export const ProStripeCustomers = Schema.Struct({
	sub: Schema.String,
	stripe_customer_id: Schema.String,
});
export type ProStripeCustomersType = typeof ProStripeCustomers.Type;


import { Schema } from 'effect';
import { BOOKING_STATUS } from './pro.types';

// Enums
export const DISCOUNT_TYPE = Schema.Literal('percent', 'fixed');
export type DiscountType = typeof DISCOUNT_TYPE.Type;

export const BOOKING_STEP = Schema.Literal('service', 'time', 'details', 'confirm');
export type BookingStep = typeof BOOKING_STEP.Type;

// Table schemas
export const BookSessions = Schema.Struct({
	session_id: Schema.String,
	b_id: Schema.String,
	service_id: Schema.NullOr(Schema.String),
	pro_id: Schema.NullOr(Schema.String),
	selected_time: Schema.NullOr(Schema.DateFromSelf),
	duration_mins: Schema.NullOr(Schema.Number),
	amount: Schema.NullOr(Schema.Number), // cents
	customer_email: Schema.NullOr(Schema.String),
	customer_phone: Schema.NullOr(Schema.String),
	customer_name: Schema.NullOr(Schema.String),
	notes: Schema.NullOr(Schema.String),
	step: Schema.String,
	expires: Schema.DateFromSelf,
	updated: Schema.DateFromSelf,
});
export type BookSessionsType = typeof BookSessions.Type;

export const BookSlotHolds = Schema.Struct({
	hold_id: Schema.String,
	session_id: Schema.String,
	b_id: Schema.String,
	pro_id: Schema.NullOr(Schema.String),
	time_slot: Schema.String,
	expires: Schema.DateFromSelf,
});
export type BookSlotHoldsType = typeof BookSlotHolds.Type;

export const BookPromoCodes = Schema.Struct({
	code_id: Schema.String,
	b_id: Schema.String,
	code: Schema.String.pipe(Schema.minLength(1), Schema.maxLength(50)),
	descr: Schema.optional(Schema.String),
	discount_type: DISCOUNT_TYPE,
	discount_value: Schema.Number, // cents (or percent if discount_type='percent')
	min_purchase: Schema.optional(Schema.Number), // cents
	max_discount: Schema.optional(Schema.Number), // cents
	usage_limit: Schema.optional(Schema.Number),
	usage_count: Schema.Number,
	valid_from: Schema.optional(Schema.DateFromSelf),
	valid_until: Schema.optional(Schema.DateFromSelf),
	service_ids: Schema.optional(Schema.Array(Schema.String)),
	is_active: Schema.Boolean,
	updated: Schema.DateFromSelf,
});
export type BookPromoCodesType = typeof BookPromoCodes.Type;

export const BookPromoRedemptions = Schema.Struct({
	id: Schema.String,
	code_id: Schema.String,
	customer_email: Schema.NullOr(Schema.String),
	discount_applied: Schema.Number, // cents
	redeemed: Schema.DateFromSelf,
});
export type BookPromoRedemptionsType = typeof BookPromoRedemptions.Type;

export const BookGuests = Schema.Struct({
	guest_id: Schema.String,
	email: Schema.String,
	phone: Schema.NullOr(Schema.String),
	f_name: Schema.NullOr(Schema.String),
	l_name: Schema.NullOr(Schema.String),
	booking_count: Schema.Number,
	last_booking: Schema.NullOr(Schema.DateFromSelf),
	updated: Schema.DateFromSelf,
});
export type BookGuestsType = typeof BookGuests.Type;

export const UserBookingRow = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	start_ts: Schema.DateFromSelf,
	end_ts: Schema.DateFromSelf,
	dur: Schema.NullOr(Schema.Number),
	status: BOOKING_STATUS,
	amount: Schema.NullOr(Schema.Number),
	notes: Schema.NullOr(Schema.String),
	service_name: Schema.NullOr(Schema.String),
	business_name: Schema.NullOr(Schema.String),
	business_address: Schema.NullOr(Schema.String),
});
export type UserBookingRow = typeof UserBookingRow.Type;

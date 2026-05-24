import { Schema } from 'effect';

// Enums (match lookup table values)
export const ADDRESS_TYPE = Schema.Literals(['current', 'user_home', 'user_billing', 'user_shipping', 'pro_home', 'pro_billing', 'pro_shipping', 'business']);
export type AddressType = typeof ADDRESS_TYPE.Type;

export const TIMEZONE = Schema.Literals([
	'America/New_York',
	'America/Chicago',
	'America/Denver',
	'America/Los_Angeles',
	'America/Phoenix',
	'America/Anchorage',
	'Pacific/Honolulu',
	'America/Puerto_Rico',
]);

// Per-app user extension tables. Each app keeps its own prefs/state keyed by users(sub).

export const CrescutsUsers = Schema.Struct({
	sub: Schema.String,
	pref_email: Schema.Boolean,
	pref_sms: Schema.Boolean,
	tz: TIMEZONE,
	military: Schema.Boolean,
	start_of_week: Schema.Boolean,
	membership_interval: Schema.NullOr(Schema.Literals(['month', 'year'])),
	membership_period_end: Schema.NullOr(Schema.Date),
	membership_will_renew: Schema.Boolean,
	is_uga_student: Schema.Boolean,
	dob: Schema.NullOr(Schema.Date),
	grad_date: Schema.NullOr(Schema.Date),
	updated: Schema.Date,
});
export type CrescutsUsersType = typeof CrescutsUsers.Type;

export const PolumeyvPros = Schema.Struct({
	sub: Schema.String,
	pref_email: Schema.Boolean,
	pref_sms: Schema.Boolean,
	tz: TIMEZONE,
	military: Schema.Boolean,
	start_of_week: Schema.Boolean,
	updated: Schema.Date,
});
export type PolumeyvProsType = typeof PolumeyvPros.Type;

export const AccountAddresses = Schema.Struct({
	owner_id: Schema.String,
	address_type: ADDRESS_TYPE,
	street: Schema.String,
	unit: Schema.optional(Schema.String),
	city: Schema.String,
	state: Schema.String,
	zip: Schema.String.pipe(Schema.check(Schema.isPattern(/^\d{5}(-\d{4})?$/))),
	country: Schema.optional(Schema.String),
	name: Schema.optional(Schema.String),
	is_default: Schema.Boolean,
	coord: Schema.NullOr(Schema.Tuple([Schema.Number, Schema.Number])), // [lat, lng]
	updated: Schema.Date,
});
export type AccountAddressesType = typeof AccountAddresses.Type;

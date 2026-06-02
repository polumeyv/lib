import * as S from 'effect/Schema';

// Enums (match lookup table values)
export const ADDRESS_TYPE = S.Literals(['current', 'user_home', 'user_billing', 'user_shipping', 'pro_home', 'pro_billing', 'pro_shipping', 'business']);
export type AddressType = typeof ADDRESS_TYPE.Type;

export const TIMEZONE = S.Literals([
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

export const CrescutsUsers = S.Struct({
	sub: S.String,
	pref_email: S.Boolean,
	pref_sms: S.Boolean,
	tz: TIMEZONE,
	military: S.Boolean,
	start_of_week: S.Boolean,
	membership_interval: S.NullOr(S.Literals(['month', 'year'])),
	membership_period_end: S.NullOr(S.Date),
	membership_will_renew: S.Boolean,
	is_uga_student: S.Boolean,
	dob: S.NullOr(S.Date),
	grad_date: S.NullOr(S.Date),
	updated: S.Date,
});
export type CrescutsUsersType = typeof CrescutsUsers.Type;

export const PolumeyvPros = S.Struct({
	sub: S.String,
	pref_email: S.Boolean,
	pref_sms: S.Boolean,
	tz: TIMEZONE,
	military: S.Boolean,
	start_of_week: S.Boolean,
	updated: S.Date,
});
export type PolumeyvProsType = typeof PolumeyvPros.Type;

export const AccountAddresses = S.Struct({
	owner_id: S.String,
	address_type: ADDRESS_TYPE,
	street: S.String,
	unit: S.optional(S.String),
	city: S.String,
	state: S.String,
	zip: S.String.pipe(S.check(S.isPattern(/^\d{5}(-\d{4})?$/))),
	country: S.optional(S.String),
	name: S.optional(S.String),
	is_default: S.Boolean,
	coord: S.NullOr(S.Tuple([S.Number, S.Number])), // [lat, lng]
	updated: S.Date,
});
export type AccountAddressesType = typeof AccountAddresses.Type;

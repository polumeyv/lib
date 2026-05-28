import { Schema } from 'effect';

export const Slug = Schema.String.pipe(Schema.check(Schema.isPattern(/^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/)));

export const Domain = Schema.String.pipe(Schema.check(Schema.isPattern(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/)));

export const getHostname = (url: string) => new URL(url.includes('://') ? url : `https://${url}`).hostname;

export const Email = Schema.String.pipe(Schema.check(Schema.isPattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, { message: 'Please enter a valid email address' })));
export type Email = typeof Email.Type;

export const Phone = Schema.String.pipe(
	Schema.check(
		Schema.isPattern(/^\+[1-9]\d{1,14}$/, {
			message: 'Please enter a valid phone number',
		}),
	),
);
export type Phone = typeof Phone.Type;

export const Name = (field: string) =>
	Schema.String.pipe(
		Schema.check(Schema.isMinLength(1, { message: `${field} is required` }), Schema.isMaxLength(60, { message: `${field} must be less than 60 characters` })),
	);

export const UserName = Schema.Struct({ f_name: Name('First name'), l_name: Name('Last name') });
export type UserName = typeof UserName.Type;

export const PaymentMethod = Schema.NullOr(
	Schema.Struct({
		brand: Schema.String,
		last4: Schema.String,
	}),
);

/** Calendar date, `YYYY-MM-DD`. */
export const DateString = Schema.String.pipe(Schema.check(Schema.isPattern(/^\d{4}-\d{2}-\d{2}$/, { message: 'Invalid date (expected YYYY-MM-DD)' })));

/** Calendar month, `YYYY-MM`. */
export const MonthString = Schema.String.pipe(Schema.check(Schema.isPattern(/^\d{4}-\d{2}$/, { message: 'Invalid month (expected YYYY-MM)' })));

/** Wall-clock time, `HH:MM` (24-hour). */
export const TimeString = Schema.String.pipe(Schema.check(Schema.isPattern(/^\d{2}:\d{2}$/, { message: 'Invalid time (expected HH:MM)' })));

/** ISO 8601 wall-clock date-time without zone, `YYYY-MM-DDTHH:MM`. */
export const DateTimeString = Schema.String.pipe(
	Schema.check(Schema.isPattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/, { message: 'Invalid date-time (expected YYYY-MM-DDTHH:MM)' })),
);

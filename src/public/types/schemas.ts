import * as S from 'effect/Schema';

export const Slug = S.String.pipe(S.check(S.isPattern(/^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/)));

export const Domain = S.String.pipe(S.check(S.isPattern(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/)));

export const getHostname = (url: string) => new URL(url.includes('://') ? url : `https://${url}`).hostname;

export const Email = S.String.pipe(S.check(S.isPattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, { message: 'Please enter a valid email address' })));
export type Email = typeof Email.Type;

export const Phone = S.String.pipe(
	S.check(
		S.isPattern(/^\+[1-9]\d{1,14}$/, {
			message: 'Please enter a valid phone number',
		}),
	),
);
export type Phone = typeof Phone.Type;

export const Name = (field: string) =>
	S.String.pipe(
		S.check(S.isMinLength(1, { message: `${field} is required` }), S.isMaxLength(60, { message: `${field} must be less than 60 characters` })),
	);

export const UserName = S.Struct({ f_name: Name('First name'), l_name: Name('Last name') });
export type UserName = typeof UserName.Type;

/** Join a name's first + last into a display name, dropping blank/missing parts (no stray spaces).
 *  Takes the whole name object (e.g. `fullName(user.current.name)`); accepts any record with `f_name`/`l_name`. */
export const fullName = (name?: { f_name?: string | null; l_name?: string | null } | null) => [name?.f_name, name?.l_name].filter(Boolean).join(' ');

export const PaymentMethod = S.NullOr(
	S.Struct({
		brand: S.String,
		last4: S.String,
	}),
);

/** Calendar date, `YYYY-MM-DD`. */
export const DateString = S.String.pipe(S.check(S.isPattern(/^\d{4}-\d{2}-\d{2}$/, { message: 'Invalid date (expected YYYY-MM-DD)' })));

/** Calendar month, `YYYY-MM`. */
export const MonthString = S.String.pipe(S.check(S.isPattern(/^\d{4}-\d{2}$/, { message: 'Invalid month (expected YYYY-MM)' })));

/** Wall-clock time, `HH:MM` (24-hour). */
export const TimeString = S.String.pipe(S.check(S.isPattern(/^\d{2}:\d{2}$/, { message: 'Invalid time (expected HH:MM)' })));

/** ISO 8601 wall-clock date-time without zone, `YYYY-MM-DDTHH:MM`. */
export const DateTimeString = S.String.pipe(
	S.check(S.isPattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/, { message: 'Invalid date-time (expected YYYY-MM-DDTHH:MM)' })),
);

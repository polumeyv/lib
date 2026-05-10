import { Schema } from 'effect';

export const Slug = Schema.String.pipe(Schema.pattern(/^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/));

export const Domain = Schema.String.pipe(Schema.pattern(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/));

export const getHostname = (url: string) => new URL(url.includes('://') ? url : `https://${url}`).hostname;

export const Email = Schema.String.pipe(Schema.pattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, { message: () => 'Please enter a valid email address' }));

export const Phone = Schema.String.pipe(
	Schema.minLength(7, { message: () => 'Please enter a valid phone number' }),
	Schema.maxLength(30, { message: () => 'Please enter a valid phone number' }),
);

export const Name = (field: string) =>
	Schema.String.pipe(
		Schema.minLength(1, { message: () => `${field} is required` }),
		Schema.maxLength(60, { message: () => `${field} must be less than 60 characters` }),
	);

export const UserName = Schema.Struct({
	f_name: Name('First name'),
	l_name: Name('Last name'),
});

export const PaymentMethod = Schema.NullOr(
	Schema.Struct({
		brand: Schema.String,
		last4: Schema.String,
	}),
);

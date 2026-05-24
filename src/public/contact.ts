import { Schema, Struct } from 'effect';
import { Email, Name, Phone } from './types';

export const CONTACT_SUBJECTS = ['General Inquiry', 'Appointment Question', 'Feedback'] as const;
export const SOCIAL_PLATFORMS = ['instagram', 'x', 'linkedin', 'other'] as const;
export type SocialPlatform = (typeof SOCIAL_PLATFORMS)[number];

export const ContactS = Schema.Struct({
	fn: Name('First name'),
	ln: Name('Last name'),
	email: Schema.Union([Schema.Literal(''), Email]),
	phone: Schema.Union([Schema.Literal(''), Phone]),
	message: Schema.String.pipe(
		Schema.check(
			Schema.isMinLength(2, { message: 'Message must be at least 2 characters' }),
			Schema.isMaxLength(300, { message: 'Message must be at most 300 characters' }),
		),
	),
	subject: Schema.Literals(CONTACT_SUBJECTS),
	social_platform: Schema.Literals(SOCIAL_PLATFORMS),
	social: Schema.optional(Schema.String),
})
	.mapFields(Struct.map(Schema.mutableKey))
	.pipe(
		Schema.check(
			Schema.makeFilter((d) => !!(d.email || d.phone), {
				message: 'Please provide an email or phone number so we can reach you.',
			}),
		),
	);
export type ContactData = typeof ContactS.Type;

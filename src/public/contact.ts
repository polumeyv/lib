import { Schema } from 'effect';
import { Email, Name, Phone } from './types';

export const CONTACT_SUBJECTS = ['General Inquiry', 'Appointment Question', 'Feedback'] as const;
export const SOCIAL_PLATFORMS = ['instagram', 'x', 'linkedin', 'other'] as const;
export type SocialPlatform = (typeof SOCIAL_PLATFORMS)[number];

export const ContactS = Schema.mutable(
	Schema.Struct({
		fn: Name('First name'),
		ln: Name('Last name'),
		email: Schema.Union(Schema.Literal(''), Email),
		phone: Schema.Union(Schema.Literal(''), Phone),
		message: Schema.String.pipe(
			Schema.minLength(2, { message: () => 'Message must be at least 2 characters' }),
			Schema.maxLength(300, { message: () => 'Message must be at most 300 characters' }),
		),
		subject: Schema.Literal(...CONTACT_SUBJECTS),
		social_platform: Schema.Literal(...SOCIAL_PLATFORMS),
		social: Schema.optional(Schema.String),
	}),
);
export type ContactData = typeof ContactS.Type;

import { Struct } from 'effect';
import * as S from 'effect/Schema';
import { Email, Name, Phone } from './types';

export const CONTACT_SUBJECTS = ['General Inquiry', 'Appointment Question', 'Feedback'] as const;
export const SOCIAL_PLATFORMS = ['instagram', 'x', 'linkedin', 'other'] as const;
export type SocialPlatform = (typeof SOCIAL_PLATFORMS)[number];

export const ContactS = S.Struct({
	f_name: Name('First name'),
	l_name: Name('Last name'),
	email: S.Union([S.Literal(''), Email]),
	phone: S.Union([S.Literal(''), Phone]),
	message: S.String.pipe(
		S.check(
			S.isMinLength(2, { message: 'Message must be at least 2 characters' }),
			S.isMaxLength(300, { message: 'Message must be at most 300 characters' }),
		),
	),
	subject: S.Literals(CONTACT_SUBJECTS),
	social_platform: S.Literals(SOCIAL_PLATFORMS),
	social: S.optional(S.String),
})
	.mapFields(Struct.map(S.mutableKey))
	.pipe(
		S.check(
			S.makeFilter((d) => !!(d.email || d.phone), {
				message: 'Please provide an email or phone number so we can reach you.',
			}),
		),
	);
export type ContactData = typeof ContactS.Type;

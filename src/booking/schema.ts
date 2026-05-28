import { Name, Email, Phone } from '../public/types';
import { Schema } from 'effect';

export const BookingUserInfo = Schema.Struct({
	f_name: Name('First name'),
	l_name: Name('Last name'),
	email: Email,
	phone: Phone,
});

export type BookingUserInfo = typeof BookingUserInfo.Type;

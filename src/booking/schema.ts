import { Name, Email, Phone } from '../public/types';
import * as S from 'effect/Schema';

export const BookingUserInfo = S.Struct({
	f_name: Name('First name'),
	l_name: Name('Last name'),
	email: Email,
	phone: Phone,
});

export type BookingUserInfo = typeof BookingUserInfo.Type;

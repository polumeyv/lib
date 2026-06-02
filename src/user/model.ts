/**
 * User schemas and branded types — safe for both server and client.
 *
 * Import via `@polumeyv/lib/auth`.
 */

/**
 * ### Required table
 *
 * ```sql
 * CREATE TABLE users (
 *   sub          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
 *   email        TEXT        NOT NULL UNIQUE,
 *   locked       BOOLEAN     NOT NULL DEFAULT FALSE,
 *   terms_acc TIMESTAMPTZ
 * );
 * ```
 *
 * | Column   | Type      | Description                                                        |
 * |----------|-----------|--------------------------------------------------------------------|
 * | `sub`          | `UUID`        | Unique user identifier (maps to `UserSub` branded type).           |
 * | `email`        | `TEXT`        | User's email address, stored lowercase. Must be unique.            |
 * | `locked`       | `BOOLEAN`     | When `true`, the account is locked and OTP verification is denied. |
 * | `terms_acc` | `TIMESTAMPTZ` | When non-null, the user has accepted the terms of service.         |
 */
import { Effect, Struct } from 'effect';
import * as S from 'effect/Schema';
import { type JWTPayload } from 'jose';
import { Email, Name, Phone } from '@polumeyv/lib/public/types';

const Uuid = S.String.check(S.isUUID());

//DB table -- users
export const UserTable = S.Struct({
	sub: Uuid.pipe(S.brand('UserSub')),
	email: Email,
	phone: Phone,
	f_name: Name('First name'),
	l_name: Name('Last name'),
	stripe_cus_id: S.NullOr(S.String.check(S.isMaxLength(255))),
	stripe_sub_id: S.NullOr(S.String.check(S.isMaxLength(255))),
	stripe_acct_id: S.NullOr(S.String.check(S.isMaxLength(255))),
	locked: S.Boolean.pipe(S.withDecodingDefaultType(Effect.succeed(false))),
	terms_acc: S.NullOr(S.Date),
	roles: S.Array(S.String),
});

export { UserName } from '@polumeyv/lib/public/types';

export const UserIdentity = UserTable.mapFields(Struct.pick(['sub', 'email']));

export const AuthPayload = S.Struct({
	...UserIdentity.fields,
	terms_acc: S.Boolean,
});

export type AuthPayload = typeof AuthPayload.Type;

export const UserSub = Uuid.pipe(S.brand('UserSub'));
export type UserSub = typeof UserSub.Type;

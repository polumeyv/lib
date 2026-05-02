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
import { Schema } from 'effect';
import { type JWTPayload } from 'jose';
import { Email } from '@polumeyv/lib/public/types';

/** Branded UUID identifying a user. */
export const UserSub = Schema.UUID.pipe(Schema.brand('UserSub'));

const UserIdentity = Schema.Struct({ sub: UserSub, email: Email });

export const BaseUser = Schema.Struct({
	...UserIdentity.fields,
	locked: Schema.Boolean,
	terms_acc: Schema.NullOr(Schema.DateFromSelf),
});

export const AuthPayload = Schema.Struct({
	...UserIdentity.fields,
	terms_acc: Schema.Boolean,
});

export type AuthPayload = typeof AuthPayload.Type & JWTPayload;

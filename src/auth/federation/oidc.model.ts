/**
 * OIDC account schema — maps a user to their federated identity provider account.
 *
 * ### Required table
 *
 * ```sql
 * CREATE TABLE IF NOT EXISTS oidc_accounts (
 *   sub           UUID          PRIMARY KEY REFERENCES users(sub) ON DELETE CASCADE,
 *   provider      VARCHAR(20)   NOT NULL DEFAULT 'google',
 *   subject       VARCHAR(255)  NOT NULL UNIQUE,
 *   email         VARCHAR(255),
 *   locale        VARCHAR(10),
 *   access_token  TEXT,
 *   refresh_token TEXT,
 *   scopes        TEXT
 * );
 * ```
 *
 * | Column          | Type           | Description                                                       |
 * |-----------------|----------------|-------------------------------------------------------------------|
 * | `sub`           | `UUID`         | Foreign key to `users.sub` (1:1 with the local account).          |
 * | `provider`      | `VARCHAR(20)`  | Identity provider name (e.g. `'google'`).                         |
 * | `subject`       | `VARCHAR(255)` | Provider's unique subject identifier (Google `sub` claim).        |
 * | `email`         | `VARCHAR(255)` | Email from the provider's ID token.                               |
 * | `locale`        | `VARCHAR(10)`  | User's locale from the provider.                                  |
 * | `access_token`  | `TEXT`         | Provider access token (for API calls like Google Calendar).       |
 * | `refresh_token` | `TEXT`         | Provider refresh token (for offline access).                      |
 * | `scopes`        | `TEXT`         | Space-separated scopes granted by the provider.                   |
 */
import { Schema } from 'effect';
import { UserSub } from '../model';
import { Email } from '@polumeyv/lib/public/types';

export class OAuthClaims extends Schema.Class<OAuthClaims>('OAuthClaims')({
	sub: Schema.String,
	email: Email,
	given_name: Schema.NullOr(Schema.String),
	family_name: Schema.NullOr(Schema.String),
	picture: Schema.NullOr(Schema.String),
	locale: Schema.NullOr(Schema.String),
}) {}

export const OAuthResult = Schema.Struct({
	provider: Schema.String,
	access_token: Schema.String,
	refresh_token: Schema.NullOr(Schema.String),
	/** Absolute access-token expiry (derived from the provider's `expires_in`). */
	expires_at: Schema.NullOr(Schema.DateFromSelf),
	scopes: Schema.String,
	claims: OAuthClaims,
});

export type OAuthResult = typeof OAuthResult.Type;


export const OidcAccount = Schema.Struct({
	sub: UserSub,
	provider: Schema.String,
	subject: Schema.String,
	email: Schema.NullOr(Schema.String),
	locale: Schema.NullOr(Schema.String),
	access_token: Schema.NullOr(Schema.String),
	refresh_token: Schema.NullOr(Schema.String),
	scopes: Schema.NullOr(Schema.String),
});
export type OidcAccount = typeof OidcAccount.Type;

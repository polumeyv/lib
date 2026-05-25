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
import { Schema, Struct } from 'effect';
import { Email } from '@polumeyv/lib/public/types';

const OidcAddressClaim = Schema.Struct({
	formatted: Schema.optional(Schema.String),
	street_address: Schema.optional(Schema.String),
	locality: Schema.optional(Schema.String),
	region: Schema.optional(Schema.String),
	postal_code: Schema.optional(Schema.String),
	country: Schema.optional(Schema.String),
});

export const OidcStandardClaims = Schema.Struct({
	address: Schema.optional(OidcAddressClaim),
	birthdate: Schema.optional(Schema.String),
	email: Schema.optional(Schema.String),
	email_verified: Schema.optional(Schema.Boolean),
	family_name: Schema.optional(Schema.String),
	gender: Schema.optional(Schema.String),
	given_name: Schema.optional(Schema.String),
	locale: Schema.optional(Schema.String),
	middle_name: Schema.optional(Schema.String),
	name: Schema.optional(Schema.String),
	nickname: Schema.optional(Schema.String),
	phone_number: Schema.optional(Schema.String),
	phone_number_verified: Schema.optional(Schema.Boolean),
	picture: Schema.optional(Schema.String),
	preferred_username: Schema.optional(Schema.String),
	profile: Schema.optional(Schema.String),
	sub: Schema.optional(Schema.String),
	updated_at: Schema.optional(Schema.Number),
	website: Schema.optional(Schema.String),
	zoneinfo: Schema.optional(Schema.String),
});

export const GoogleClaims = Schema.Struct({
	// `always` — Google's provider subject (≤255 ASCII chars), NOT your internal user UUID. → `subject` column.
	sub: Schema.String,
	// Guaranteed whenever the `email` scope is requested (your default includes it).
	email: Email,
	email_verified: Schema.Boolean,
	// "Might be provided… never guaranteed to be present" per Google, even with the `profile` scope.
	name: Schema.optional(Schema.String),
	given_name: Schema.optional(Schema.String),
	family_name: Schema.optional(Schema.String),
	picture: Schema.optional(Schema.String),
	locale: Schema.optional(Schema.String),
});
export const OAuthResult = Schema.Struct({
	provider: Schema.String,
	access_token: Schema.String,
	refresh_token: Schema.NullOr(Schema.String),
	/** Absolute access-token expiry (derived from the provider's `expires_in`). */
	expires_at: Schema.NullOr(Schema.Date),
	scopes: Schema.String,
	claims: GoogleClaims,
});

export type OAuthResult = typeof OAuthResult.Type;

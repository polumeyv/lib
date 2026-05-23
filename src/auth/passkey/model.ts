import { Schema } from 'effect';
import { UserSub } from '..';
import { type AuthenticatorTransportFuture } from '@simplewebauthn/server';

// Schema.Literal needs the runtime values — keep the array, but `satisfies` ties it
// to the library's union so a typo'd/invalid transport is a compile error.
const Transports = ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'] as const satisfies readonly AuthenticatorTransportFuture[];

// in the struct, replacing the old transports line:

/* ```sql
 * CREATE TABLE passkey_credentials (
 *   id               VARCHAR(255)  PRIMARY KEY,
 *   sub              UUID          NOT NULL REFERENCES users(sub),
 *   webauthn_user_id VARCHAR(255)  NOT NULL,
 *   public_key       BYTEA         NOT NULL,
 *   counter          INTEGER       NOT NULL DEFAULT 0,
 *   device_type      VARCHAR(32),
 *   backed_up        BOOLEAN       NOT NULL DEFAULT FALSE,
 *   transports       VARCHAR[]     DEFAULT NULL,
 *   created_at       TIMESTAMPTZ   NOT NULL DEFAULT now()
 * );
 */
export const PasskeyTable = Schema.Struct({
	id: Schema.String.pipe(Schema.maxLength(255)),
	sub: UserSub,
	webauthn_user_id: Schema.String.pipe(Schema.maxLength(255)),
	public_key: Schema.Uint8ArrayFromSelf,
	counter: Schema.NumberFromString,
	device_type: Schema.NullOr(Schema.Literal('singleDevice', 'multiDevice')),
	backed_up: Schema.optionalWith(Schema.Boolean, { default: () => false }),
	transports: Schema.optionalWith(Schema.mutable(Schema.Array(Schema.Literal(...Transports))), { nullable: true }),
	created_at: Schema.DateFromSelf,
});

export type PasskeyTable = typeof PasskeyTable.Type;
export type PasskeyCredentialEncoded = typeof PasskeyTable.Encoded;

// --- WebAuthn ceremony responses ---
// The JSON the browser returns from `navigator.credentials` (modelled to match `@simplewebauthn`'s
// `AuthenticationResponseJSON` / `RegistrationResponseJSON`) so the verify boundary validates structure
// instead of accepting `unknown`. `clientExtensionResults` is an open `{}` — the spec lets authenticators
// emit arbitrary extension outputs and the server ignores them. `mutable` arrays + the empty struct keep
// the decoded types directly assignable to the library's nominal types (no casts needed downstream).
const Base64URL = Schema.String;
const ClientExtensionResults = Schema.Struct({});
const AuthenticatorAttachment = Schema.Literal('platform', 'cross-platform');

export const AuthenticationResponse = Schema.Struct({
	id: Base64URL,
	rawId: Base64URL,
	response: Schema.Struct({
		clientDataJSON: Base64URL,
		authenticatorData: Base64URL,
		signature: Base64URL,
		userHandle: Schema.optional(Base64URL),
	}),
	authenticatorAttachment: Schema.optional(AuthenticatorAttachment),
	clientExtensionResults: ClientExtensionResults,
	type: Schema.Literal('public-key'),
});
export type AuthenticationResponse = typeof AuthenticationResponse.Type;

export const RegistrationResponse = Schema.Struct({
	id: Base64URL,
	rawId: Base64URL,
	response: Schema.Struct({
		clientDataJSON: Base64URL,
		attestationObject: Base64URL,
		authenticatorData: Schema.optional(Base64URL),
		transports: Schema.optional(Schema.mutable(Schema.Array(Schema.Literal(...Transports)))),
		publicKeyAlgorithm: Schema.optional(Schema.Number),
		publicKey: Schema.optional(Base64URL),
	}),
	authenticatorAttachment: Schema.optional(AuthenticatorAttachment),
	clientExtensionResults: ClientExtensionResults,
	type: Schema.Literal('public-key'),
});
export type RegistrationResponse = typeof RegistrationResponse.Type;

/** Input to `PasskeyService.verifyAuth`: the parked challenge key + the authentication ceremony response. */
export const VerifyAuthInput = Schema.Struct({
	challengeKey: Schema.String,
	response: AuthenticationResponse,
});
export type VerifyAuthInput = typeof VerifyAuthInput.Type;

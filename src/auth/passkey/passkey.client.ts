/**
 * Browser-side passkey helpers wrapping `@simplewebauthn/browser`.
 */
import { browserSupportsWebAuthn, WebAuthnError, type WebAuthnErrorCode } from '@simplewebauthn/browser';

/** Throws if the browser lacks WebAuthn support. */
export const guardPasskeySupport = () => {
	if (!browserSupportsWebAuthn()) throw new Error("Your device doesn't support passkeys.");
};

const webAuthnCode = (e: unknown): WebAuthnErrorCode | null => (e instanceof WebAuthnError ? e.code : null);

/**
 * Checks if the error represents a user cancellation of the passkey ceremony.
 * Matches `NotAllowedError` (browser-native) and `ERROR_CEREMONY_ABORTED` (SimpleWebAuthn).
 * Typically not worth surfacing to the user as a toast.
 *
 * @param e - The caught error.
 */
export const isPasskeyCancelled = (e: unknown) => (e instanceof Error && e.name === 'NotAllowedError') || webAuthnCode(e) === 'ERROR_CEREMONY_ABORTED';

/**
 * Checks if the error indicates the authenticator already holds a credential
 * for this relying party. Often safe to treat as a successful registration.
 *
 * @param e - The caught error.
 */
export const isAlreadyRegistered = (e: unknown) => webAuthnCode(e) === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED';

/** Human-readable messages for each WebAuthn error code. */
const ERROR_MESSAGES: Record<WebAuthnErrorCode, string> = {
	ERROR_CEREMONY_ABORTED: 'Passkey operation was cancelled.',
	ERROR_INVALID_DOMAIN: 'This domain is not allowed to use passkeys.',
	ERROR_INVALID_RP_ID: 'Passkey configuration error: relying party ID does not match the current domain.',
	ERROR_INVALID_USER_ID_LENGTH: 'Passkey registration failed: user ID length is invalid.',
	ERROR_MALFORMED_PUBKEYCREDPARAMS: 'Passkey configuration error: credential parameters are malformed.',
	ERROR_AUTHENTICATOR_GENERAL_ERROR: 'Your authenticator encountered an error. Please try again.',
	ERROR_AUTHENTICATOR_MISSING_DISCOVERABLE_CREDENTIAL_SUPPORT: 'Your authenticator does not support passkeys.',
	ERROR_AUTHENTICATOR_MISSING_USER_VERIFICATION_SUPPORT: 'Your authenticator does not support the required verification method.',
	ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED: 'This device is already registered as a passkey.',
	ERROR_AUTHENTICATOR_NO_SUPPORTED_PUBKEYCREDPARAMS_ALG: 'Your authenticator does not support the required security algorithms.',
	ERROR_AUTO_REGISTER_USER_VERIFICATION_FAILURE: 'Automatic passkey registration failed: user verification was not successful.',
	ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY: 'An unexpected passkey error occurred.',
};

/**
 * Converts a passkey error into a user-facing message suitable for a toast notification.
 * Returns `null` for user cancellations, a mapped message for known WebAuthn errors,
 * and falls back to `e.message` for generic errors.
 *
 * @param e - The caught error.
 * @returns A toast-ready string, or `null` if the error should be silently ignored.
 */
export const passkeyErrorMessage = (e: unknown): string | null =>
	isPasskeyCancelled(e)
		? null
		: ((webAuthnCode(e) && ERROR_MESSAGES[webAuthnCode(e)!]) ?? (e instanceof Error ? e.message : 'An unexpected passkey error occurred.'));

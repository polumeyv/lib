import { Data } from 'effect';
import type { HttpStatusError } from '@polumeyv/lib/error';

/** Tagged error for JWT operations (sign, verify, revoke, key import). */
export class JwtError extends Data.TaggedError('JwtError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

/** Tagged error for WebAuthn / passkey operations. */
export class WebAuthnError extends Data.TaggedError('WebAuthnError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 400 as const;
	}
}

/** Tagged error for generic OIDC failures (token exchange, profile fetch, etc.). */
export class OAuthError extends Data.TaggedError('OAuthError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 401 as const;
	}
}

/** Tagged error when an OAuth account already exists for a different local user. */
export class OAuthAccountConflictError extends Data.TaggedError('OAuthAccountConflictError')<{ email: string }> {}

/** Tagged error for OAuth2 client request validation failures. */
export class OAuth2RequestError extends Data.TaggedError('OAuth2RequestError')<{ message: string }> implements HttpStatusError {
	get statusCode() {
		return 400 as const;
	}
}

import { Data, Schema } from 'effect';
import { ValidationError, type HttpStatusError } from '@polumeyv/lib/error';
import { BaseUser, UserSub } from '../model';
import { Email } from '@polumeyv/lib/public/types';

/** Branded string representing an AES-GCM encrypted, base64url-encoded verify token. */
export const SealedToken = Schema.String.pipe(Schema.brand('SealedToken'));

export const InputEmailSchema = Schema.Struct({ email: Email });

export const makeOtpSchema = (codeLen: number) =>
	Schema.Struct({
		email: Email,
		token: SealedToken,
		code: Schema.Union(
			Schema.Literal('resend_'),
			Schema.String.pipe(Schema.pattern(new RegExp(`^\\d{${codeLen}}$`), { message: () => `Code must be ${codeLen} digits` })),
		),
	});

/**
 * Tagged return for an OTP session state.
 *  - `token`: the sealed verify token. `null` is the OIDC signal — the email is already linked to an
 *    OIDC provider, so the OTP step is skipped and the caller routes to the link flow instead of
 *    code entry. A session is never returned tokenless for any other reason (cooldown / max-sends
 *    states still carry a real or sentinel token), so `token === null` uniquely means "has OIDC".
 *  - `countdown`: resend cooldown in seconds — `null` = ready to send, `-1` = max sends reached,
 *    positive = still cooling down.
 */
export class OtpSession extends Data.TaggedClass('OtpSession')<{
	token: typeof SealedToken.Type | null;
	email: typeof Email.Type;
	countdown: number | null;
	hasOidc: boolean;
}> {}

/**
 * Tagged error for a wrong OTP code — user can retry. Subclasses `ValidationError` so the route
 * boundary maps it to a form `invalid()` with no app-side branching. Construct via
 * `LockedService.invalidCode(failed)` so the "X attempts remaining" copy stays consistent with the
 * lockout ladder.
 */
export class InvalidCode extends ValidationError {
	constructor(message: string) {
		super({ message });
	}
}
/**
 * Tagged error for a resend requested before the cooldown elapsed (`countdown` = seconds remaining)
 * or after the send cap is hit (`countdown` = -1). Subclasses `ValidationError` so the route boundary
 * maps it to a form `invalid()` with no app-side branching.
 */
export class ResendCooldown extends ValidationError {
	constructor(readonly countdown: number) {
		super({
			message:
				countdown === -1
					? "You've requested the maximum number of codes. Please try again later."
					: `Please wait ${countdown} second${countdown === 1 ? '' : 's'} before requesting another code.`,
		});
	}
}

/**
 * Tagged error for a locked account (timed or permanent). Carries `statusCode` 423 so the route
 * boundary throws it as an HTTP error (not a form `invalid()`) — the client catches it, shows an
 * alert dialog, and bounces back to sign-in. `remaining` (ms until unlock; `Number.MAX_SAFE_INTEGER`
 * for a permanent lock) crosses the boundary via the `body` getter so the client can hold a lockout
 * countdown and skip re-requesting with the same email while it's still active.
 *
 * Construct via `LockedService.userLocked(failed, failedAt)` / `LockedService.permLocked` — the
 * service owns the duration ladder and renders the message + remaining for you.
 */
export class UserLocked extends Data.TaggedError('UserLocked')<{ readonly message: string; readonly remaining: number }> implements HttpStatusError {
	readonly statusCode = 423 as const;

	/** Wire shape forwarded as the HTTP error body at the route boundary. */
	get body() {
		return { message: this.message, remaining: this.remaining };
	}
}

/** Successful OTP verification. `sub` is `null` for a brand-new email (no `users` row yet) — the
 *  caller starts signup; a real `sub` means an existing user and the caller establishes a session. */
export class AuthenticatedUser extends Data.TaggedClass('AuthenticatedUser')<{ sub: typeof UserSub.Type | null; email: typeof Email.Type; link: boolean }> {}

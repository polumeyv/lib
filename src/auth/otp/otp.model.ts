import { Data, Schema } from 'effect';
import { AuthConfigDefaults } from '../config';
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
 * Schema for submitting an OTP code for verification.
 * Extends `InputEmailSchema` with the user-entered code,
 * validated as a fixed-length numeric string.
 */
export const InputCodeSchema = makeOtpSchema(AuthConfigDefaults.otpCodeLen);

/** Tagged return for successful OTP session init or resend — sealed token + cooldown in seconds. client must check for null,
 * if so, set a timer for the cooldown period, if number exists, user is requesting too early  */
export class OtpSession extends Data.TaggedClass('OtpSession')<{ token: typeof SealedToken.Type; countdown: number | null }> {}

/** Tagged return for a wrong OTP code — user can retry. `failed` = consecutive failures (for "X attempts remaining"). */
export class InvalidCode extends Data.TaggedClass('InvalidCode')<{ failed: number }> {
	/** Human-readable message with remaining attempts (shown when <= 2). */
	message(lockDurations: readonly number[] = AuthConfigDefaults.lockDurationsMs): string {
		const attemptsLeft = Math.max(0, lockDurations.findIndex((d, i) => i >= this.failed && d > 0) - this.failed);
		return `Invalid or expired code.${attemptsLeft <= 2 ? ` ${attemptsLeft} attempt${attemptsLeft === 1 ? '' : 's'} remaining.` : ''}`;
	}
}
export const checkIsLocked = (lockDurations: readonly number[] = AuthConfigDefaults.lockDurationsMs, failed: number, failed_at: number | null) => {
	const d = lockDurations[failed] ?? Infinity;
	return d !== 0 && (d === Infinity || !failed_at || Date.now() - failed_at < d);
};

/** Tagged return for a locked account (timed or permanent). `failed_at` = lock timestamp; `null` = permanent lock. */
export class UserLocked extends Data.TaggedClass('UserLocked')<{ failed: number; failed_at: number | null }> {
	/** Whether the lock is currently active. */
	isLocked = (lockDurations: readonly number[] = AuthConfigDefaults.lockDurationsMs) => checkIsLocked(lockDurations, this.failed, this.failed_at);

	/** Human-readable lock message — timed duration or permanent "contact support". */
	message(lockDurations: readonly number[] = AuthConfigDefaults.lockDurationsMs): string {
		const d = lockDurations[this.failed];
		if (d === undefined || d === Infinity) return 'Your account has been permanently locked. Please contact support.';
		const mins = Math.ceil(d / 60_000);
		return `You've been locked out for ${mins >= 60 ? `${Math.floor(mins / 60)} ${mins < 120 ? 'hour' : 'hours'}` : `${mins} minute${mins === 1 ? '' : 's'}`} due to too many failed attempts. Please try again after the allotted time.`;
	}
}

/** Tagged return indicating the email is already linked to an OIDC provider — skips OTP flow. */
export class HasOidc extends Data.TaggedClass('HasOidc')<{ has_oidc: true; email: typeof Email.Type; countdown: number | null }> {}
export class AuthenticatedUser extends Data.TaggedClass('AuthenticatedUser')<{ sub: typeof UserSub.Type; email: typeof Email.Type; link: boolean }> {}

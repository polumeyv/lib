import { Context, Data, Effect } from 'effect';
import { ValidationError, type HttpStatusError } from '@polumeyv/lib/error';

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

export class LockedConfig extends Context.Tag('LockedConfig')<
	LockedConfig,
	{
		/** Progressive lockout durations in milliseconds, indexed by consecutive failure count. Last entry should be `Infinity` for permanent lock. */
		readonly lockDurationsMs: readonly number[];
	}
>() {}

const fmt = (mins: number) => (mins >= 60 ? `${Math.floor(mins / 60)} ${mins < 120 ? 'hour' : 'hours'}` : `${mins} minute${mins === 1 ? '' : 's'}`);

/**
 * Owns the `lockDurationsMs` ladder and centralises the OTP-attempt lockout maths.
 * Consumers (OtpService, OtpSessionStore) get pure decisions and pre-formatted error
 * instances, so the duration array lives in exactly one place.
 */
export class LockedService extends Effect.Service<LockedService>()('LockedService', {
	effect: Effect.gen(function* () {
		const { lockDurationsMs } = yield* LockedConfig;
		const permIndex = lockDurationsMs.indexOf(Infinity);

		const isLocked = (failed: number, failedAt: number) =>
			((d) => d !== 0 && (d === Infinity || !failedAt || Date.now() - failedAt < d))(lockDurationsMs[failed] ?? Infinity);

		// On a wrong-code attempt: cap real users (`hasSub`) below the Infinity rung — new-user flows have no DB row to lock and run uncapped.
		const nextLock = (currentFailed: number, hasSub: boolean) => {
			const cappedFailed = hasSub ? Math.min(currentFailed + 1, lockDurationsMs.length - 2) : currentFailed + 1;
			return { cappedFailed, lockMs: lockDurationsMs[cappedFailed] ?? Infinity };
		};

		const userLocked = (failed: number, failedAt: number) => {
			const d = lockDurationsMs[failed];
			const permanent = d === undefined || d === Infinity;
			const remaining = permanent ? Number.MAX_SAFE_INTEGER : Math.max(0, failedAt + d - Date.now());
			return new UserLocked({
				message: permanent
					? 'Your account has been permanently locked. Please contact support.'
					: `Your account is locked due to too many failed attempts. Try again in ${fmt(Math.max(1, Math.ceil(remaining / 60_000)))}.`,
				remaining,
			});
		};

		const permLocked = userLocked(permIndex, 0);

		const invalidCode = (failed: number) =>
			((a) => new InvalidCode(`Invalid or expired code.${a <= 2 ? ` ${a} attempt${a === 1 ? '' : 's'} remaining.` : ''}`))(
				Math.max(0, lockDurationsMs.findIndex((d, i) => i >= failed && d > 0) - failed),
			);

		const failIfLocked = (failed: number, failedAt: number) => (isLocked(failed, failedAt) ? Effect.fail(userLocked(failed, failedAt)) : Effect.void);

		return { nextLock, userLocked, permLocked, invalidCode, failIfLocked };
	}),
}) {}

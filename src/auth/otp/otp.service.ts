import { Effect, Schema, Cause, Context } from 'effect';
import { sessionExpired, CryptoService } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { OtpSession, ResendCooldown, AuthenticatedUser, makeOtpSchema } from './otp.model';
import { OtpSessionStore, SENTINEL } from './otp-session.store';
import { LockedService } from '../locked.service';
import { SealedToken } from './otp.model';

// -1 = max sends reached, positive seconds = still cooling down, null = ready to send.
const computeCooldown = (sends: number, lastSend: number, otpResendMs: number, maxEmailSends: number): number | null => {
	if (sends >= maxEmailSends) return -1;
	if (lastSend <= 0) return null;
	const remaining = Math.ceil((otpResendMs - (Date.now() - lastSend)) / 1000);
	return remaining > 0 ? remaining : null;
};

/**
 * Build the "send a fresh OTP code" outcome from the current state. Pure constructor —
 * callers must have already decided that sending is allowed (via `computeCooldown`).
 * Increments `sends`, stamps a new `last_send`, and carries other fields from `state`.
 */

export const OtpAlerts = Context.GenericTag<{
	sendVerificationCode: (to: typeof Email.Type, code: string) => Effect.Effect<void>;
}>('OtpAlerts');

export class OtpConfig extends Context.Tag('JwtConfig')<
	OtpConfig,
	{
		/** Minimum interval in milliseconds between OTP code sends (default: 35 000). */
		readonly otpResendMs: number;
		/** Optional maximum number of OTP sends per email address, to prevent abuse (default: 8). */
		readonly maxEmailSends: number;
		/** Maximum age in milliseconds before an OTP code expires (default: 300_000 — 5 min). */
		readonly otpCodeTtlMs: number;
		/** Number of digits in a generated OTP code (default: 6). */
		readonly otpCodeLen: number;
	}
>() {}

/**
 * OTP verification service — code generation, validation, rate-limiting, and progressive lockout.
 *
 * All session-state storage (Redis hash + user-lookup-and-cache) is delegated to `OtpSessionStore`.
 * This service deals in plain `OtpHashRedis` field reads + decisions; it never touches the Redis
 * client or the user repo directly.
 */
export class OtpService extends Effect.Service<OtpService>()('OtpService', {
	effect: Effect.gen(function* () {
		const { otpResendMs, maxEmailSends, otpCodeTtlMs, otpCodeLen } = yield* OtpConfig;
		const locked = yield* LockedService;
		const alerts = yield* OtpAlerts;
		const sessionStore = yield* OtpSessionStore;
		const { decodeJson } = yield* CryptoService;
		const { encodeJson } = yield* CryptoService;

		const computeCooldown = (sends: number, lastSend: number): number | null => {
			if (sends >= maxEmailSends) return -1;
			if (lastSend <= 0) return null;
			const remaining = Math.ceil((otpResendMs - (Date.now() - lastSend)) / 1000);
			return remaining > 0 ? remaining : null;
		};

		const createOtpSession = (email: typeof Email.Type) => Effect.andThen(sendOtp(email), (token) => new OtpSession({ token, email, countdown: null, hasOidc: false }));

		const sendOtp = (email: typeof Email.Type) =>
			Effect.andThen(
				((code) => Effect.map(encodeJson({ code, gen: Date.now() }), (s) => ({ token: SealedToken.make(s), code })))(
					(crypto.getRandomValues(new Uint32Array(1))[0]! % 10 ** otpCodeLen).toString().padStart(otpCodeLen, '0'),
				),
				({ code, token }) => Effect.as(alerts.sendVerificationCode(email, code), token),
			);

		return {
			seedLinkCache: (email: typeof Email.Type) => sessionStore.lookupAndCacheUser(email, false),

			initAndSend: (email: typeof Email.Type) =>
				//first, see if user already exists in session
				Effect.andThen(sessionStore.read(email, true), ({ raw, hasOidc }) =>
					//if they dont see if they are a user in postgres, cache result.
					Effect.andThen(sessionStore.initLookupUser(email, raw, hasOidc), (cachedUser) => {
						//they already have a token, work through whatever state the session is in
						if (raw?.token) {
							//check if the user is locked based on that state, before executing further
							return Effect.andThen(locked.failIfLocked(Number(raw.failed), Number(raw.failed_at)), () =>
								//the user isnt locked but they still could have a resend countdown based on that session,
								((countdown) =>
									hasOidc || countdown
										? // Still cooling down between sends — hand back the same session. Or if they have OIDC, hand back a session instead of immediately sending a code.
											Effect.succeed(new OtpSession({ token: raw.token, email, countdown, hasOidc }))
										: createOtpSession(email))(computeCooldown(Number(raw.sends), Number(raw.last_send))),
							);
						}
						//no session, check if this email is a user in db, if not initiate new code send
						if (!cachedUser) return createOtpSession(email);
						// we know a user exists
						// Postgres only stores the permanent-lock boolean, so if the user is locked in the DB, they're permanently locked.
						if (cachedUser.locked) return Effect.fail(locked.permLocked);
						//before sending a code, if they have OIDC, hand a session to them without first sending a code, maybe they want to login with google
						return cachedUser.has_oidc ? Effect.succeed(new OtpSession({ token: null, email, countdown: null, hasOidc: true })) : createOtpSession(email);
					}),
				),

			initLinkAndSend: (email: typeof Email.Type) =>
				Effect.andThen(sessionStore.read(email), ({ raw }) =>
					!raw
						? Effect.succeed(null)
						: Effect.andThen(sessionStore.decodeCachedUser(raw.user), (cachedUser) =>
								((countdown) =>
									!cachedUser && Number(raw.sends) < maxEmailSends
										? // A null decode means the session expired. Callers entering linking from an OAuth callback must `seedLinkCache(email)` first.
											sessionExpired()
										: countdown === -1
											? // Cap-checked first so maxed-out users get a deterministic response even with no cached user.
												Effect.succeed(new OtpSession({ token: SENTINEL, email, countdown: -1, hasOidc: cachedUser?.has_oidc ?? false }))
											: !cachedUser || cachedUser.locked
												? Effect.fail(locked.permLocked)
												: createOtpSession(email))(computeCooldown(Number(raw.sends), Number(raw.last_send))),
							),
				),

			handleOtp: (input: Schema.Schema.Type<ReturnType<typeof makeOtpSchema>>) =>
				Effect.andThen(sessionStore.read(input.email), ({ raw }) => {
					if (raw === null || !raw.token) return sessionExpired();
					if (raw.token !== input.token) return Effect.fail(new Cause.IllegalArgumentException('Token mismatch'));

					return Effect.andThen(decodeJson<{ code: string; gen: number }>(raw.token), (decoded) => {
						if (input.code === 'resend_')
							return ((cd) => (cd ? Effect.fail(new ResendCooldown(cd)) : sendOtp(input.email)))(computeCooldown(Number(raw.sends), Number(raw.last_send)));

						return ((timeNow) => {
							//validate that code is niehter expired or mismatched to the code stored in session
							if (input.code === decoded.code && timeNow - decoded.gen < otpCodeTtlMs)
								return Effect.as(sessionStore.clear(input.email), new AuthenticatedUser({ sub: raw.sub || null, email: input.email, link: raw.link === '1' }));
							// Wrong code — the store records the attempt + any lockout, and hands back the data
							return Effect.flatMap(sessionStore.writeFailedAttempt(input.email, raw, timeNow), ({ lockMs, cappedFailed }) =>
								//distinguish between weither this attempt locked out the user or just told them the code was invalid and incremented attempts
								Effect.fail(lockMs > 0 ? locked.userLocked(cappedFailed, timeNow) : locked.invalidCode(cappedFailed)),
							);
						})(Date.now());
					});
				}),
		};
	}),
	dependencies: [OtpSessionStore.Default, LockedService.Default, CryptoService.Default],
}) {}

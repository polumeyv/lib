import { Effect, Option, Schema } from 'effect';
import { Redis, CryptoService } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { LockedService } from '../locked.service';
import { UserSub } from '../model';
import { BaseUserRepository } from '../user/user.repo';
import { OidcAuthFlow } from '../federation/auth-flow';
import { SealedToken } from './otp.model';

const OtpHashKey = (email: string) => `otp:${email}`;
const HasOidcKey = (email: string) => `has_oidc:${email}`;
// 24 h — OTP session lifetime in Redis (covers the verify + resend windows).
const otpSessionTtl = 86_400;

/**
 * Wire-format sentinel used across the OTP hash:
 *  - `user`: "looked up, no users row found for this email".
 *  - `token`: "token chain invalidated" (failed-code lock, cap-reached response).
 * Branded as `SealedToken.Type` so it satisfies the token field without per-use-site casts.
 */
export const SENTINEL = '_' as typeof SealedToken.Type;

const CachedUserSchema = Schema.parseJson(
	Schema.Struct({
		sub: UserSub,
		locked: Schema.Boolean,
		terms_acc: Schema.NullOr(Schema.Date),
		has_oidc: Schema.Boolean,
	}),
);

/** Cached snapshot of a user record kept inside the OTP hash's `user` field. */
export type CachedUser = typeof CachedUserSchema.Type;

export type OtpHashRedis = {
	token: typeof SealedToken.Type; // "" | SENTINEL ("_") | real sealed token
	sub: typeof UserSub.Type; // "" | real users.sub UUID
	failed: string; // "0", "1", …
	link: string; // "0" | "1"
	sends: string; // "0", "1", …
	last_send: string; // "0" | ms timestamp
	failed_at: string; // "0" (no failure recorded) | ms timestamp
	user: string; // "" | SENTINEL ("_") | JSON-encoded CachedUser
};

const HASH_DEFAULTS: OtpHashRedis = {
	token: '' as typeof SealedToken.Type,
	sub: '' as typeof UserSub.Type,
	failed: '0',
	link: '0',
	sends: '0',
	last_send: '0',
	failed_at: '0',
	user: '',
};

/**
 * Stateful storage for OTP sessions — owns the Redis wire format (`OtpHashRedis`)
 */
export class OtpSessionStore extends Effect.Service<OtpSessionStore>()('OtpSessionStore', {
	effect: Effect.gen(function* () {
		const redis = yield* Redis;
		const users = yield* BaseUserRepository;
		const locked = yield* LockedService;

		//returns and reformats Bun's redis method for hgtall into a typed version of OtpHashRedis | null rather than Promise<Record<string, string>> which can return {}
		const read = (email: typeof Email.Type, withOidc = false) =>
			Effect.serviceOption(OidcAuthFlow).pipe(
				Effect.flatMap((oidc) =>
					redis.use((c) =>
						Promise.all([c.hgetall(OtpHashKey(email)), withOidc && Option.isSome(oidc) ? c.exists(HasOidcKey(email)).then(Boolean) : Promise.resolve(false)]),
					),
				),
				Effect.map(([raw, hasOidc]) => ({ raw: Object.keys(raw).length === 0 ? null : (raw as OtpHashRedis), hasOidc })),
			);

		// Read-modify-write merging `HASH_DEFAULTS` ← current ← patch, writes the full 8-field shape.
		// `ttl` provided → HSETEX (resets the key TTL). Omitted → HSET (preserves existing TTL — used for the failed-code path so attackers can't extend the session by hammering wrong codes).
		const write = (email: typeof Email.Type, patch: Partial<OtpHashRedis>, opts?: { ttl?: number }) =>
			redis.use((c) =>
				c.hgetall(OtpHashKey(email)).then((current) => {
					const merged = { ...HASH_DEFAULTS, ...current, ...patch };
					const entries = Object.entries(merged);
					return opts?.ttl !== undefined ? c.hsetex(OtpHashKey(email), 'EX', opts.ttl, 'FIELDS', entries.length, ...entries.flat()) : c.hset(OtpHashKey(email), merged);
				}),
			);

		// Generate a fresh OTP code and seal it into a verify token. Pure issuance — no persistence.
		// Returns the sealed `token` (to store) alongside the plaintext `code` (to deliver).

		// Issue + persist a fresh token: stamps `last_send`, bumps `sends`, resets the wrong-code
		// failure counter (a new code is a new challenge), carries `sub`/`link` from `state`, and
		// resets the session TTL. Returns the plaintext `code` (for delivery) + sealed `token`.
		const writeNewToken = (email: typeof Email.Type, state: Partial<OtpHashRedis>, token: typeof SealedToken.Type, code: string) =>
			write(
				email,
				{
					token,
					last_send: String(Date.now()),
					sends: String(Number(state.sends || '0') + 1),
					failed: '0',
					failed_at: '0',
					...(state.sub && { sub: state.sub }),
					...(state.link && { link: state.link }),
				},
				{ ttl: otpSessionTtl },
			);

		// Records a wrong-code attempt. HSET (no ttl) — must not extend the session window.
		// On permanent lock (lockMs === Infinity) also flips the user's DB row, so the OTP
		// service stays free of a BaseUserRepository dep.
		const writeFailedAttempt = (email: typeof Email.Type, raw: OtpHashRedis, timeNow: number) => {
			const { cappedFailed, lockMs } = locked.nextLock(Number(raw.failed), Boolean(raw.sub));
			const w = write(email, { token: lockMs ? SENTINEL : raw.token, failed: String(cappedFailed), failed_at: String(timeNow) });
			return Effect.as(lockMs === Infinity && raw.sub ? Effect.andThen(w, users.lockUser(raw.sub)) : w, { lockMs, cappedFailed });
		};

		const clear = (email: typeof Email.Type) => redis.use((c) => c.unlink(OtpHashKey(email)));

		/** Decode the `user` field. Returns `null` for the empty/sentinel encodings. */
		const decodeCachedUser = (rawUser: string) => (!rawUser || rawUser === SENTINEL ? Effect.succeed(null) : Schema.decode(CachedUserSchema)(rawUser));

		/** Encode a CachedUser for the `user` field; `null` becomes the "looked up, none found" sentinel. */
		const encodeCachedUser = (user: CachedUser | null) => (user === null ? Effect.succeed(SENTINEL) : Schema.encode(CachedUserSchema)(user));

		/**
		 * Look up the user from Postgres + persist the result back into the OTP hash so
		 * subsequent requests inside the same session window skip the DB hit.
		 * Resolves to the cached user (or `null` if no user exists for the email).
		 */
		const lookupAndCacheUser = (email: typeof Email.Type, hasOidc: boolean) =>
			(hasOidc ? users.getSubByEmailWithOidc(email) : users.getSubByEmail(email).pipe(Effect.map((u) => u && { ...u, has_oidc: false }))).pipe(
				Effect.andThen((row) =>
					((cachedUser: CachedUser | null) =>
						encodeCachedUser(cachedUser).pipe(
							Effect.andThen((json) => write(email, { user: json }, { ttl: otpSessionTtl })),
							Effect.as(cachedUser),
						))(row ?? null),
				),
			);

		/**
		 * Resolve a `CachedUser` for `email`: decodes the existing `user` field if the session hash
		 * exists, otherwise performs the DB lookup and seeds the cache. Returns `null` when no
		 * users row matches.
		 */
		const initLookupUser = (email: typeof Email.Type, raw: OtpHashRedis | null, hasOidc: boolean) =>
			raw ? decodeCachedUser(raw.user) : lookupAndCacheUser(email, hasOidc);

		return { read, write, writeNewToken, writeFailedAttempt, clear, decodeCachedUser, encodeCachedUser, lookupAndCacheUser, initLookupUser };
	}),
	dependencies: [BaseUserRepository.Default, LockedService.Default, CryptoService.Default],
}) {}

import { Effect, Option, Schema, Cause, Context, ParseResult } from 'effect';
import { SessionExpiredError, Redis } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { SealedToken, OtpSession, InvalidCode, UserLocked, HasOidc, AuthenticatedUser, makeOtpSchema } from './otp.model';
import { AuthConfig, type AuthConfigShape, HasOidcKey, IV_BYTES, B64URL } from '../config';
import { UserSub } from '../model';
import { BaseUserRepository } from '../user/user.repo';
import { OidcAuthFlow } from '../oauth/auth-flow';

const OtpHashKey = (email: string) => `otp:${email}`;

// A token guaranteed never to match a real AES-GCM-sealed token; used wherever
// we need to "publish" a token field that the client must not be able to verify against.
const INVALIDATED_TOKEN = SealedToken.make('_invalid_');

// Sentinel stored in the OTP hash's `user` field meaning "looked up, no user exists".
const NO_USER_SENTINEL = '_';

const CachedUserSchema = Schema.Struct({
	sub: UserSub,
	locked: Schema.Boolean,
	terms_acc: Schema.NullOr(Schema.Date),
	has_oidc: Schema.Boolean,
});
type CachedUser = typeof CachedUserSchema.Type;
const CachedUserJson = Schema.parseJson(CachedUserSchema);

type OtpHash = {
	token?: typeof SealedToken.Type;
	failed: number;
	sub: typeof UserSub.Type | null;
	link: boolean;
	sends: number;
	lastSend: number;
	failedAt: number | null;
	user?: string;
};

const parseHash = (h: Record<string, string>): OtpHash => ({
	token: (h.token || undefined) as typeof SealedToken.Type | undefined,
	failed: h.failed ? Number(h.failed) : 0,
	sub: (h.sub || null) as typeof UserSub.Type | null,
	link: h.link === '1',
	sends: h.sends ? Number(h.sends) : 0,
	lastSend: h.last_send ? Number(h.last_send) : 0,
	failedAt: h.failed_at ? Number(h.failed_at) : null,
	user: h.user || undefined,
});

// -1 = max sends reached, positive seconds = still cooling down, null = ready to send.
const computeCooldown = (sends: number, lastSend: number, otpResendMs: number, maxEmailSends: number, now: number): number | null => {
	if (sends >= maxEmailSends) return -1;
	if (lastSend <= 0) return null;
	const remaining = Math.ceil((otpResendMs - (now - lastSend)) / 1000);
	return remaining > 0 ? remaining : null;
};

const isLocked = (failed: number, failedAt: number | null, lockDurationsMs: readonly number[], now: number) => {
	const d = lockDurationsMs[failed] ?? Infinity;
	return d !== 0 && (d === Infinity || !failedAt || now - failedAt < d);
};

type HashOp = { kind: 'noop' } | { kind: 'clear' } | { kind: 'set'; fields: Record<string, string>; ttl?: number };

type SendOutcome = {
	response: OtpSession;
	hashOp: HashOp;
	alertCode?: string;
};

type Candidate = { code: string; sealed: typeof SealedToken.Type; now: number };

const sendDecision = (args: {
	sends: number;
	lastSend: number;
	sub: typeof UserSub.Type | null;
	failed: number;
	link: boolean;
	failedAt: number | null;
	currentToken: typeof SealedToken.Type;
	candidate: Candidate;
	config: AuthConfigShape;
}): SendOutcome => {
	const { sends, lastSend, sub, failed, link, failedAt, currentToken, candidate, config } = args;

	if (sends >= config.maxEmailSends) return { response: new OtpSession({ token: INVALIDATED_TOKEN, countdown: -1 }), hashOp: { kind: 'noop' } };

	const elapsed = candidate.now - lastSend;

	if (lastSend > 0 && elapsed < config.otpResendMs) return { response: new OtpSession({ token: currentToken, countdown: (config.otpResendMs - elapsed) / 1000 }), hashOp: { kind: 'noop' } };

	return {
		response: new OtpSession({ token: candidate.sealed, countdown: null }),
		alertCode: candidate.code,
		hashOp: {
			kind: 'set',
			ttl: config.otpSessionTtl,
			fields: {
				token: candidate.sealed,
				failed: String(failed),
				sub: sub ?? '',
				link: link ? '1' : '0',
				last_send: String(candidate.now),
				failed_at: failedAt ? String(failedAt) : '',
				sends: String(sends + 1),
			},
		},
	};
};

/** Tag for providing the raw JWK string used to derive the OTP encryption key. */
export class OtpKeyConfig extends Context.Tag('OtpKeyConfig')<OtpKeyConfig, { readonly raw: string }>() {}

export const OtpAlerts = Context.GenericTag<{
	sendVerificationCode: (to: typeof Email.Type, code: string) => Effect.Effect<void>;
}>('OtpAlerts');

/**
 * OTP verification service — code generation, validation, rate-limiting, and progressive lockout.
 *
 * Each public method reads the Redis hash, resolves any DB lookups, decides the response inline,
 * and applies only the side effects (hash writes, alert emails, user locks) the chosen branch needs.
 */
export class OtpService extends Effect.Service<OtpService>()('OtpService', {
	effect: Effect.gen(function* () {
		const config = yield* AuthConfig;
		const alerts = yield* OtpAlerts;
		const redis = yield* Redis;
		const users = yield* BaseUserRepository;
		const { raw: jwkRaw } = yield* OtpKeyConfig;
		const otpKey = yield* Effect.promise(() => crypto.subtle.importKey('jwk', JSON.parse(jwkRaw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']));

		const VerifyTokenCodec = Schema.transformOrFail(Schema.typeSchema(SealedToken), Schema.parseJson(Schema.Struct({ code: Schema.String, gen: Schema.Number })), {
			strict: false,
			decode: (sealed) =>
				Effect.tryPromise({
					try: () =>
						((bin) => crypto.subtle.decrypt({ name: 'AES-GCM', iv: bin.subarray(0, IV_BYTES) }, otpKey, bin.subarray(IV_BYTES)).then((pt) => new TextDecoder().decode(pt)))(
							Uint8Array.fromBase64(sealed, B64URL),
						),
					catch: () => new ParseResult.Type(SealedToken.ast, sealed, 'Decryption failed'),
				}),
			encode: (json) =>
				Effect.tryPromise({
					try: () =>
						((iv) =>
							crypto.subtle
								.encrypt({ name: 'AES-GCM', iv }, otpKey, new TextEncoder().encode(json))
								.then((ct) => ((out) => (out.set(iv), out.set(new Uint8Array(ct), IV_BYTES), SealedToken.make(out.toBase64(B64URL))))(new Uint8Array(IV_BYTES + ct.byteLength))))(
							crypto.getRandomValues(new Uint8Array(IV_BYTES)),
						),
					catch: () => new ParseResult.Type(SealedToken.ast, json, 'Encryption failed'),
				}),
		});

		const makeCandidate = (): Effect.Effect<Candidate, never> => {
			const now = Date.now();
			const code = (crypto.getRandomValues(new Uint32Array(1))[0]! % 10 ** config.otpCodeLen).toString().padStart(config.otpCodeLen, '0');
			return Effect.map(Effect.orDie(Schema.encode(VerifyTokenCodec)({ code, gen: now })), (sealed) => ({ code, sealed, now }));
		};

		const applyHashOp = (email: typeof Email.Type, op: HashOp) => {
			if (op.kind === 'noop') return Effect.void;
			if (op.kind === 'clear') return redis.use((c) => c.unlink(OtpHashKey(email)));

			const entries = Object.entries(op.fields);

			if (op.ttl !== undefined) return redis.use((c) => c.hsetex(OtpHashKey(email), 'EX', Number(op.ttl), 'FIELDS', entries.length, ...entries.flat()));

			return redis.use((c) => c.hset(OtpHashKey(email), op.fields));
		};

		// Decode a cached-user hash field (or the '_' sentinel) into CachedUser | null.
		const readCachedUser = (raw: string | undefined) => (!raw || raw === NO_USER_SENTINEL ? Effect.succeed(null) : Schema.decode(CachedUserJson)(raw));

		// Look up the user from Postgres + persist the result back into the OTP hash so
		// subsequent requests inside the same session window skip the DB hit.
		const lookupAndCacheUser = (email: typeof Email.Type, hasOidc: boolean) =>
			Effect.flatMap(
				hasOidc
					? users.getSubByEmailWithOidc(email)
					: Effect.map(
							users.getSubByEmail(email),
							Option.map((u): CachedUser => ({ ...u, has_oidc: false })),
						),
				(opt) =>
					Effect.flatMap(
						Option.match(opt, {
							onNone: () => Effect.succeed(NO_USER_SENTINEL as string),
							onSome: (user) => Schema.encode(CachedUserJson)(user),
						}),
						(json) =>
							Effect.as(
								redis.use((c) => c.hsetex(OtpHashKey(email), 'EX', config.otpSessionTtl, 'FIELDS', 1, 'user', json)),
								Option.getOrNull(opt),
							),
					),
			);

		const applySend = (email: typeof Email.Type, outcome: SendOutcome) =>
			Effect.gen(function* () {
				yield* applyHashOp(email, outcome.hashOp);
				if (outcome.alertCode) yield* alerts.sendVerificationCode(email, outcome.alertCode);
				return outcome.response;
			});

		return {
			/** Look up the user for `email` and seed the OTP cache. Used to bridge legitimate
			 *  out-of-band entry points (e.g. OAuth callback → link flow) into `initLinkAndSend`,
			 *  which is strictly cache-only by design and would otherwise fail SessionExpired.
			 *  Resolves to the cached user (or null if no user exists for the email). */
			seedLinkCache: (email: typeof Email.Type) => lookupAndCacheUser(email, false),

			initAndSend: (email: typeof Email.Type) =>
				Effect.gen(function* () {
					const oidc = yield* Effect.serviceOption(OidcAuthFlow);
					const [raw, hasOidc] = yield* redis.use((c) => Promise.all([c.hgetall(OtpHashKey(email)), Option.isSome(oidc) ? c.exists(HasOidcKey(email)).then(Boolean) : Promise.resolve(false)]));

					const hash = parseHash(raw);
					const cachedUser = !hash.token && !hash.user ? yield* lookupAndCacheUser(email, hasOidc) : yield* readCachedUser(hash.user);
					const candidate = yield* makeCandidate();

					if (hash.token) {
						if (isLocked(hash.failed, hash.failedAt, config.lockDurationsMs, candidate.now)) {
							return new UserLocked({ failed: hash.failed, failed_at: hash.failedAt });
						}
						const countdown = computeCooldown(hash.sends, hash.lastSend, config.otpResendMs, config.maxEmailSends, candidate.now);
						if (hasOidc) return new HasOidc({ has_oidc: true, email, countdown });
						if (countdown !== null) return new OtpSession({ token: hash.token, countdown });
						return yield* applySend(
							email,
							sendDecision({
								sends: hash.sends,
								lastSend: hash.lastSend,
								sub: hash.sub,
								failed: hash.failed,
								link: hash.link,
								failedAt: hash.failedAt,
								currentToken: hash.token,
								candidate,
								config,
							}),
						);
					}

					if (cachedUser === null) {
						return yield* applySend(
							email,
							sendDecision({
								sends: hash.sends,
								lastSend: hash.lastSend,
								sub: null,
								failed: 0,
								link: false,
								failedAt: null,
								currentToken: INVALIDATED_TOKEN,
								candidate,
								config,
							}),
						);
					}
					if (cachedUser.locked) {
						return new UserLocked({ failed: config.lockDurationsMs.indexOf(Infinity), failed_at: null });
					}
					if (cachedUser.has_oidc) {
						return new HasOidc({ has_oidc: true, email, countdown: null });
					}
					return yield* applySend(
						email,
						sendDecision({
							sends: hash.sends,
							lastSend: hash.lastSend,
							sub: cachedUser.sub,
							failed: 0,
							link: false,
							failedAt: null,
							currentToken: INVALIDATED_TOKEN,
							candidate,
							config,
						}),
					);
				}),

			initLinkAndSend: (email: typeof Email.Type) =>
				Effect.gen(function* () {
					const raw = yield* redis.use((c) => c.hgetall(OtpHashKey(email)));
					const hash = parseHash(raw);

					// Linking only consults a cached user; never triggers a DB lookup.
					// A missing/sentinel value is "session expired" — fail before deciding.
					// Callers entering linking from an OAuth callback must `seedLinkCache(email)` first.
					if ((!hash.user || hash.user === NO_USER_SENTINEL) && hash.sends < config.maxEmailSends) {
						return yield* Effect.fail(new SessionExpiredError({ message: 'Your session has expired, please sign in again' }));
					}

					const cachedUser = yield* readCachedUser(hash.user);
					const candidate = yield* makeCandidate();

					// Cap-checked first so maxed-out users get a deterministic response even with no cached user.
					if (computeCooldown(hash.sends, hash.lastSend, config.otpResendMs, config.maxEmailSends, candidate.now) === -1) {
						return new OtpSession({ token: INVALIDATED_TOKEN, countdown: -1 });
					}
					if (!cachedUser || cachedUser.locked) {
						return new UserLocked({ failed: config.lockDurationsMs.indexOf(Infinity), failed_at: null });
					}
					return yield* applySend(
						email,
						sendDecision({
							sends: hash.sends,
							lastSend: hash.lastSend,
							sub: cachedUser.sub,
							failed: 0,
							link: true,
							failedAt: null,
							currentToken: INVALIDATED_TOKEN,
							candidate,
							config,
						}),
					);
				}),

			handleOtp: (input: Schema.Schema.Type<ReturnType<typeof makeOtpSchema>>) =>
				Effect.gen(function* () {
					const raw = yield* redis.use((c) => c.hgetall(OtpHashKey(input.email)));
					const hash = parseHash(raw);

					if (!hash.token) return yield* Effect.fail(new SessionExpiredError({ message: 'Your verification session has expired, please request a new code' }));
					if (hash.token !== input.token) return yield* Effect.fail(new Cause.IllegalArgumentException('Token mismatch'));

					const decoded = yield* Schema.decode(VerifyTokenCodec)(hash.token);
					const candidate = yield* makeCandidate();

					if (input.code === 'resend_') {
						return yield* applySend(
							input.email,
							sendDecision({
								sends: hash.sends,
								lastSend: hash.lastSend,
								sub: hash.sub,
								failed: hash.failed,
								link: hash.link,
								failedAt: hash.failedAt,
								currentToken: hash.token,
								candidate,
								config,
							}),
						);
					}

					if (input.code === decoded.code && candidate.now - decoded.gen < config.otpCodeTtlMs) {
						yield* applyHashOp(input.email, { kind: 'clear' });
						return hash.sub ? new AuthenticatedUser({ sub: hash.sub, email: input.email, link: hash.link }) : ('AuthenticatedNewUser' as const);
					}

					const nextFailed = hash.failed + 1;
					// Cap real users (sub set) below the Infinity rung so `failed` stays in range; new-user
					// flows have no DB row to lock and run uncapped.
					const cappedFailed = hash.sub ? Math.min(nextFailed, config.lockDurationsMs.length - 2) : nextFailed;
					const lockMs = config.lockDurationsMs[cappedFailed] ?? Infinity;

					// No `ttl` here: matches today's HSET (preserves existing hash TTL) rather than HSETEX.
					yield* applyHashOp(input.email, {
						kind: 'set',
						fields: { token: lockMs ? INVALIDATED_TOKEN : hash.token, failed: String(cappedFailed), failed_at: String(candidate.now) },
					});
					if (lockMs === Infinity && hash.sub) yield* users.lockUser(hash.sub);

					return lockMs > 0 ? new UserLocked({ failed: cappedFailed, failed_at: lockMs !== Infinity ? candidate.now : null }) : new InvalidCode({ failed: cappedFailed });
				}),
		};
	}),
	dependencies: [BaseUserRepository.Default],
}) {}

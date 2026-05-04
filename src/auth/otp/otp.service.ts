import { Effect, Option, Schema, Cause, Context } from 'effect';
import { SessionExpiredError, Redis } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { makeVerifyTokenCodec, OtpKey, OtpKeyFromConfig } from './otp.crypto';
import { SealedToken, InputCodeSchema } from './otp.model';
import { AuthConfig, HasOidcKey } from '../config';
import { BaseUserRepository } from '../user/user.repo';
import { OidcAuthFlow } from '../oauth/auth-flow';
import {
	CachedUser,
	CachedUserJson,
	NO_USER_SENTINEL,
	parseHash,
	needsUserLookup,
	decideInit,
	decideLink,
	decideHandle,
	type Candidate,
	type Outcome,
	type OtpHash,
} from './otp.policy';

const OtpHashKey = (email: string) => `otp:${email}`;

export const OtpAlerts = Context.GenericTag<{
	sendVerificationCode: (to: typeof Email.Type, code: string) => Effect.Effect<void>;
}>('OtpAlerts');

/**
 * OTP verification service — code generation, validation, rate-limiting, and progressive lockout.
 *
 * All decision logic lives in `./otp.policy`; this service is the I/O glue: read the Redis hash,
 * resolve any DB lookups required by the policy, hand a snapshot to the matching `decide*` function,
 * then apply the returned `HashOp`/alert/lockUser uniformly.
 */
export class OtpService extends Effect.Service<OtpService>()('OtpService', {
	effect: Effect.gen(function* () {
		const config = yield* AuthConfig;
		const alerts = yield* OtpAlerts;
		const redis = yield* Redis;
		const users = yield* BaseUserRepository;
		const VerifyTokenCodec = makeVerifyTokenCodec(yield* OtpKey);

		const makeCandidate = (now: number): Effect.Effect<Candidate, never> =>
			Effect.gen(function* () {
				const code = (new DataView(crypto.getRandomValues(new Uint8Array(4)).buffer).getUint32(0) % 10 ** config.otpCodeLen)
					.toString()
					.padStart(config.otpCodeLen, '0');
				const sealed = yield* Effect.orDie(Schema.encode(VerifyTokenCodec)({ code, gen: now }));
				return { code, sealed };
			});

		const applyHashOp = (email: typeof Email.Type, op: Outcome<unknown>['hashOp']) => {
			if (op.kind === 'noop') return Effect.void;
			if (op.kind === 'clear') return redis.use((c) => c.unlink(OtpHashKey(email)));
			const entries = Object.entries(op.fields);
			if (op.ttl !== undefined) {
				const args = entries.flat();
				return redis.use((c) => c.hsetex(OtpHashKey(email), 'EX', op.ttl!, 'FIELDS', entries.length, ...args));
			}
			return redis.use((c) => c.hset(OtpHashKey(email), op.fields));
		};

		const applyOutcome = <R>(email: typeof Email.Type, outcome: Outcome<R>) =>
			Effect.as(
				Effect.all(
					[
						applyHashOp(email, outcome.hashOp),
						outcome.alertCode ? alerts.sendVerificationCode(email, outcome.alertCode) : Effect.void,
						outcome.lockUser ? users.lockUser(outcome.lockUser) : Effect.void,
					],
					{ concurrency: 'unbounded', discard: true },
				),
				outcome.response,
			);

		// Decode a cached-user hash field (or the '_' sentinel) into CachedUser | null.
		const readCachedUser = (raw: string | undefined) =>
			!raw || raw === NO_USER_SENTINEL ? Effect.succeed(null) : Effect.map(Schema.decode(CachedUserJson)(raw), (u): CachedUser => u);

		// Look up the user from Postgres + persist the result back into the OTP hash so
		// subsequent requests inside the same session window skip the DB hit.
		const lookupAndCacheUser = (email: typeof Email.Type, hasOidc: boolean) =>
			Effect.flatMap(
				hasOidc ? users.findSubByEmailWithOidc(email) : Effect.map(users.findSubByEmail(email), Option.map((u): CachedUser => ({ ...u, has_oidc: false }))),
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

		return {
			initAndSend: (email: typeof Email.Type) =>
				Effect.gen(function* () {
					const now = Date.now();
					const oidc = yield* Effect.serviceOption(OidcAuthFlow);
					const [raw, hasOidc] = yield* redis.use((c) =>
						Promise.all([c.hgetall(OtpHashKey(email)), Option.isSome(oidc) ? c.exists(HasOidcKey(email)).then(Boolean) : Promise.resolve(false)]),
					);
					const hash = parseHash(raw);
					const cachedUser = needsUserLookup(hash) ? yield* lookupAndCacheUser(email, hasOidc) : yield* readCachedUser(hash.user);
					const candidate = yield* makeCandidate(now);
					return yield* applyOutcome(email, decideInit({ hash, hasOidc, cachedUser, email, candidate, config, now }));
				}),

			initLinkAndSend: (email: typeof Email.Type) =>
				Effect.gen(function* () {
					const now = Date.now();
					const raw = yield* redis.use((c) => c.hgetall(OtpHashKey(email)));
					const hash = parseHash(raw);
					// `decideLink` only consults a cached user; it never triggers a DB lookup.
					// A missing/sentinel value is "session expired" — fail before the policy sees it.
					if ((!hash.user || hash.user === NO_USER_SENTINEL) && hash.sends < config.maxEmailSends) {
						return yield* Effect.fail(new SessionExpiredError({ message: 'Your session has expired, please sign in again' }));
					}
					const cachedUser = yield* readCachedUser(hash.user);
					const candidate = yield* makeCandidate(now);
					return yield* applyOutcome(email, decideLink({ hash, cachedUser, candidate, config, now }));
				}),

			handleOtp: (input: typeof InputCodeSchema.Type) =>
				Effect.gen(function* () {
					const now = Date.now();
					const raw = yield* redis.use((c) => c.hgetall(OtpHashKey(input.email)));
					const hash = parseHash(raw);
					if (!hash.token) return yield* Effect.fail(new SessionExpiredError({ message: 'Your verification session has expired, please request a new code' }));
					if (hash.token !== input.token) return yield* Effect.fail(new Cause.IllegalArgumentException('Token mismatch'));
					const decoded = yield* Schema.decode(VerifyTokenCodec)(hash.token);
					const candidate = yield* makeCandidate(now);
					return yield* applyOutcome(input.email, decideHandle({ hash, decoded, email: input.email, inputCode: input.code, candidate, config, now }));
				}),
		};
	}),
	dependencies: [BaseUserRepository.Default, OtpKeyFromConfig],
}) {}

// Re-exported so the policy module's typed handle stays internal to the package.
export type { OtpHash } from './otp.policy';

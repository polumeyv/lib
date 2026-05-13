import { describe, expect, test, beforeAll } from 'bun:test';
import { Effect, Exit, Layer, Option, Ref, Cause } from 'effect';
import { Redis } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { AuthConfig, AuthConfigDefaults, type AuthConfigShape } from '../config';
import { BaseUserRepository } from '../user/user.repo';
import { OidcAuthFlow } from '../oauth/auth-flow';
import { OtpService, OtpAlerts, OtpKeyConfig } from './otp.service';
import { AuthenticatedUser, HasOidc, InvalidCode, OtpSession, SealedToken, UserLocked } from './otp.model';
import { UserSub } from '../model';

const EMAIL = Email.make('test@example.com');
const SUB = UserSub.make('00000000-0000-0000-0000-000000000001');

type FakeRedisStore = Map<string, Map<string, string>>;
const FakeRedis = (store: FakeRedisStore, existsKeys: ReadonlySet<string> = new Set()) =>
	Layer.succeed(
		Redis,
		{
			use: (fn: (c: never) => unknown) => {
				const client = {
					hgetall: (key: string) => Promise.resolve(Object.fromEntries(store.get(key) ?? new Map())),
					hset: (key: string, fields: Record<string, string>) => {
						const h = store.get(key) ?? new Map();
						for (const [k, v] of Object.entries(fields)) h.set(k, v);
						store.set(key, h);
						return Promise.resolve(Object.keys(fields).length);
					},
					hsetex: (key: string, _mode: string, _ttl: number, _kw: string, count: number, ...kvs: string[]) => {
						const h = store.get(key) ?? new Map();
						for (let i = 0; i < count * 2; i += 2) h.set(kvs[i]!, kvs[i + 1]!);
						store.set(key, h);
						return Promise.resolve('OK');
					},
					unlink: (key: string) => Promise.resolve(store.delete(key) ? 1 : 0),
					exists: (key: string) => Promise.resolve(existsKeys.has(key) ? 1 : 0),
				};
				return Effect.promise(async () => fn(client as never));
			},
		} as never,
	);

// OtpService consults `OidcAuthFlow` only via `Effect.serviceOption` — its presence flips the
// Redis `has_oidc:` lookup on. Implementation is irrelevant for these tests.
const FakeOidcAuthFlow = Layer.succeed(OidcAuthFlow, OidcAuthFlow.of({} as never));

type LockTracker = Ref.Ref<readonly (typeof UserSub.Type)[]>;
const FakeUsers = (locks: LockTracker, lookup: { sub: typeof UserSub.Type; locked: boolean; terms_acc: Date | null; has_oidc?: boolean } | null = null) =>
	Layer.succeed(
		BaseUserRepository,
		BaseUserRepository.of({
			getSubByEmail: () => Effect.succeed(Option.fromNullable(lookup ? { sub: lookup.sub, locked: lookup.locked, terms_acc: lookup.terms_acc } : null)),
			getSubByEmailWithOidc: () => Effect.succeed(Option.fromNullable(lookup ? { sub: lookup.sub, locked: lookup.locked, terms_acc: lookup.terms_acc, has_oidc: lookup.has_oidc ?? false } : null)),
			lockUser: (sub: typeof UserSub.Type) => Ref.update(locks, (xs) => [...xs, sub]) as never,
		} as never),
	);

type AlertTracker = Ref.Ref<readonly { email: typeof Email.Type; code: string }[]>;
const FakeAlerts = (sent: AlertTracker) =>
	Layer.succeed(OtpAlerts, {
		sendVerificationCode: (email, code) => Ref.update(sent, (xs) => [...xs, { email, code }]),
	});

let JWK_RAW: string;
beforeAll(async () => {
	const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
	JWK_RAW = JSON.stringify(await crypto.subtle.exportKey('jwk', key));
});

const makeHarness = (
	opts: {
		store?: FakeRedisStore;
		existsKeys?: ReadonlySet<string>;
		oidcFlowPresent?: boolean;
		user?: { sub: typeof UserSub.Type; locked: boolean; terms_acc: Date | null; has_oidc?: boolean } | null;
		config?: Partial<AuthConfigShape>;
	} = {},
) => {
	const store = opts.store ?? new Map();
	const locks: LockTracker = Effect.runSync(Ref.make<readonly (typeof UserSub.Type)[]>([]));
	const sent: AlertTracker = Effect.runSync(Ref.make<readonly { email: typeof Email.Type; code: string }[]>([]));
	const redisLayer = FakeRedis(store, opts.existsKeys);
	const usersLayer = FakeUsers(locks, opts.user ?? null);
	const alertsLayer = FakeAlerts(sent);
	const configLayer = Layer.succeed(AuthConfig, { ...AuthConfigDefaults, cryptoKey: 'unused', ...opts.config });
	const keyLayer = Layer.succeed(OtpKeyConfig, { raw: JWK_RAW });
	// `OidcAuthFlow` is read via `Effect.serviceOption` at *method* invocation time, not service
	// construction — so it must live in the runtime context, alongside OtpService, not be consumed
	// by `Layer.provide`.
	const otpLayer = Layer.provide(OtpService.DefaultWithoutDependencies, Layer.mergeAll(redisLayer, usersLayer, alertsLayer, configLayer, keyLayer));
	const layer = opts.oidcFlowPresent ? Layer.merge(otpLayer, FakeOidcAuthFlow) : otpLayer;
	return { store, locks, sent, layer };
};

const run = <A, E>(effect: Effect.Effect<A, E, OtpService>, layer: Layer.Layer<OtpService>) => Effect.runPromise(Effect.scoped(Effect.provide(effect, layer)));

const runExit = <A, E>(effect: Effect.Effect<A, E, OtpService>, layer: Layer.Layer<OtpService>) => Effect.runPromiseExit(Effect.scoped(Effect.provide(effect, layer)));

describe('OtpService.initAndSend', () => {
	test('first send for an existing user issues a fresh session and triggers an alert', async () => {
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null } });
		const result = await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		);

		expect(result).toBeInstanceOf(OtpSession);
		expect((result as OtpSession).countdown).toBeNull();
		expect((result as OtpSession).token).not.toBe(SealedToken.make('_invalid_'));

		const sent = await Effect.runPromise(Ref.get(h.sent));
		expect(sent).toHaveLength(1);
		expect(sent[0]!.email).toBe(EMAIL);
		expect(sent[0]!.code).toMatch(/^\d{6}$/);

		const stored = h.store.get('otp:test@example.com');
		expect(stored?.get('sends')).toBe('1');
		expect(stored?.get('token')).toBe((result as OtpSession).token);
	});

	test('user with an OIDC account skips OTP and returns HasOidc', async () => {
		// HasOidc fires only when OidcAuthFlow is wired AND the Redis `has_oidc:{email}` key is set —
		// the lookup-with-oidc path is what surfaces `has_oidc: true` on the cached user.
		const h = makeHarness({
			user: { sub: SUB, locked: false, terms_acc: null, has_oidc: true },
			oidcFlowPresent: true,
			existsKeys: new Set(['has_oidc:test@example.com']),
		});
		const result = await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		);

		expect(result).toBeInstanceOf(HasOidc);
		expect((result as HasOidc).has_oidc).toBe(true);

		const sent = await Effect.runPromise(Ref.get(h.sent));
		expect(sent).toHaveLength(0);
	});

	test('locked user is rejected without sending', async () => {
		const h = makeHarness({ user: { sub: SUB, locked: true, terms_acc: null } });
		const result = await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		);

		expect(result).toBeInstanceOf(UserLocked);
		const sent = await Effect.runPromise(Ref.get(h.sent));
		expect(sent).toHaveLength(0);
	});

	test('resend within cooldown returns the existing session with a positive countdown', async () => {
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null } });
		const first = (await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		)) as OtpSession;
		const second = (await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		)) as OtpSession;

		expect(second.token).toBe(first.token);
		expect(second.countdown).not.toBeNull();
		expect(second.countdown!).toBeGreaterThan(0);

		const sent = await Effect.runPromise(Ref.get(h.sent));
		expect(sent).toHaveLength(1);
	});

	test('past maxEmailSends the session keeps the existing token but reports countdown -1', async () => {
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null }, config: { maxEmailSends: 1, otpResendMs: 0 } });
		const first = (await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		)) as OtpSession;
		const second = (await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		)) as OtpSession;

		expect(second.countdown).toBe(-1);
		expect(second.token).toBe(first.token);
		const sent = await Effect.runPromise(Ref.get(h.sent));
		expect(sent).toHaveLength(1);
	});

	test('unknown email still issues a session (does not reveal user existence)', async () => {
		const h = makeHarness({ user: null });
		const result = await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		);

		expect(result).toBeInstanceOf(OtpSession);
		expect((result as OtpSession).countdown).toBeNull();
		const sent = await Effect.runPromise(Ref.get(h.sent));
		expect(sent).toHaveLength(1);
	});
});

describe('OtpService.handleOtp', () => {
	test('correct code authenticates the user and clears the session', async () => {
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null } });
		const session = (await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		)) as OtpSession;
		const sent = await Effect.runPromise(Ref.get(h.sent));
		const code = sent[0]!.code;

		const result = await run(
			Effect.flatMap(OtpService, (otp) => otp.handleOtp({ email: EMAIL, token: session.token, code })),
			h.layer,
		);

		expect(result).toBeInstanceOf(AuthenticatedUser);
		expect((result as AuthenticatedUser).sub).toBe(SUB);
		expect(h.store.has('otp:test@example.com')).toBe(false);
	});

	test('wrong code returns InvalidCode and increments failed', async () => {
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null } });
		const session = (await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		)) as OtpSession;

		const result = await run(
			Effect.flatMap(OtpService, (otp) => otp.handleOtp({ email: EMAIL, token: session.token, code: '000000' })),
			h.layer,
		);

		expect(result).toBeInstanceOf(InvalidCode);
		expect((result as InvalidCode).failed).toBe(1);
		expect(h.store.get('otp:test@example.com')?.get('failed')).toBe('1');
	});

	test('a wrong attempt that hits a timed-lock rung returns UserLocked without locking the user in Postgres', async () => {
		// `decideHandle` caps real users at `lockDurationsMs.length - 2`, so [0, lockMs, Infinity]
		// → first wrong attempt jumps to index 1 (timed lock) and never reaches the Infinity rung.
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null }, config: { lockDurationsMs: [0, 60_000, Infinity] } });
		const session = (await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		)) as OtpSession;

		const result = await run(
			Effect.flatMap(OtpService, (otp) => otp.handleOtp({ email: EMAIL, token: session.token, code: '000000' })),
			h.layer,
		);

		expect(result).toBeInstanceOf(UserLocked);
		expect((result as UserLocked).failed).toBe(1);
		const locks = await Effect.runPromise(Ref.get(h.locks));
		expect(locks).toHaveLength(0);
	});

	test('token mismatch fails with IllegalArgumentException', async () => {
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null } });
		await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		);

		const exit = await runExit(
			Effect.flatMap(OtpService, (otp) => otp.handleOtp({ email: EMAIL, token: SealedToken.make('not-the-real-token'), code: '000000' })),
			h.layer,
		);

		expect(Exit.isFailure(exit)).toBe(true);
		if (Exit.isFailure(exit)) {
			const failure = Cause.failureOption(exit.cause);
			expect(Option.isSome(failure)).toBe(true);
			if (Option.isSome(failure)) expect((failure.value as Error).message).toBe('Token mismatch');
		}
	});

	test('no active session fails with SessionExpiredError', async () => {
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null } });

		const exit = await runExit(
			Effect.flatMap(OtpService, (otp) => otp.handleOtp({ email: EMAIL, token: SealedToken.make('anything'), code: '000000' })),
			h.layer,
		);

		expect(Exit.isFailure(exit)).toBe(true);
		if (Exit.isFailure(exit)) {
			const failure = Cause.failureOption(exit.cause);
			expect(Option.isSome(failure)).toBe(true);
			if (Option.isSome(failure)) expect((failure.value as { _tag: string })._tag).toBe('SessionExpiredError');
		}
	});
});

describe('OtpService.initLinkAndSend', () => {
	test('fails with SessionExpiredError when no cached user is present', async () => {
		const h = makeHarness({ user: null });

		const exit = await runExit(
			Effect.flatMap(OtpService, (otp) => otp.initLinkAndSend(EMAIL)),
			h.layer,
		);

		expect(Exit.isFailure(exit)).toBe(true);
		if (Exit.isFailure(exit)) {
			const failure = Cause.failureOption(exit.cause);
			expect(Option.isSome(failure)).toBe(true);
			if (Option.isSome(failure)) expect((failure.value as { _tag: string })._tag).toBe('SessionExpiredError');
		}
	});

	test('seedLinkCache + initLinkAndSend issues a linking session for an existing user', async () => {
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null } });

		const result = await run(
			Effect.flatMap(OtpService, (otp) => Effect.zipRight(otp.seedLinkCache(EMAIL), otp.initLinkAndSend(EMAIL))),
			h.layer,
		);

		expect(result).toBeInstanceOf(OtpSession);
		expect(h.store.get('otp:test@example.com')?.get('link')).toBe('1');
	});

	test('seedLinkCache writes the sentinel and initLinkAndSend still fails SessionExpired for unknown emails', async () => {
		const h = makeHarness({ user: null });

		const exit = await runExit(
			Effect.flatMap(OtpService, (otp) => Effect.zipRight(otp.seedLinkCache(EMAIL), otp.initLinkAndSend(EMAIL))),
			h.layer,
		);

		expect(Exit.isFailure(exit)).toBe(true);
		if (Exit.isFailure(exit)) {
			const failure = Cause.failureOption(exit.cause);
			if (Option.isSome(failure)) expect((failure.value as { _tag: string })._tag).toBe('SessionExpiredError');
		}
	});

	test('issues a linking session with link=1 once the cached user is present', async () => {
		// otpResendMs=0 so the link send isn't suppressed by cooldown from the preceding initAndSend.
		const h = makeHarness({ user: { sub: SUB, locked: false, terms_acc: null }, config: { otpResendMs: 0 } });
		await run(
			Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
			h.layer,
		);

		const result = await run(
			Effect.flatMap(OtpService, (otp) => otp.initLinkAndSend(EMAIL)),
			h.layer,
		);

		expect(result).toBeInstanceOf(OtpSession);
		expect(h.store.get('otp:test@example.com')?.get('link')).toBe('1');
	});
});

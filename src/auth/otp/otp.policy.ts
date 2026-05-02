import { Schema } from 'effect';
import type { Email } from '@polumeyv/lib/public/types';
import type { AuthConfigShape } from '../config';
import { UserSub } from '../model';
import { SealedToken, OtpSession, InvalidCode, UserLocked, HasOidc, AuthenticatedUser } from './otp.model';

// A token guaranteed never to match a real AES-GCM-sealed token; used wherever
// we need to "publish" a token field that the client must not be able to verify against.
export const INVALIDATED_TOKEN = SealedToken.make('_invalid_');

// Sentinel stored in the OTP hash's `user` field meaning "looked up, no user exists".
export const NO_USER_SENTINEL = '_';

export const CachedUser = Schema.Struct({
	sub: UserSub,
	locked: Schema.Boolean,
	terms_acc: Schema.NullOr(Schema.DateFromSelf),
	has_oidc: Schema.Boolean,
});
export type CachedUser = typeof CachedUser.Type;
export const CachedUserJson = Schema.parseJson(CachedUser);

export type OtpHash = {
	token?: typeof SealedToken.Type;
	failed: number;
	sub: typeof UserSub.Type | null;
	link: boolean;
	sends: number;
	lastSend: number;
	failedAt: number | null;
	user?: string;
};

export const parseHash = (h: Record<string, string>): OtpHash => ({
	token: (h.token || undefined) as typeof SealedToken.Type | undefined,
	failed: h.failed ? Number(h.failed) : 0,
	sub: (h.sub || null) as typeof UserSub.Type | null,
	link: h.link === '1',
	sends: h.sends ? Number(h.sends) : 0,
	lastSend: h.last_send ? Number(h.last_send) : 0,
	failedAt: h.failed_at ? Number(h.failed_at) : null,
	user: h.user || undefined,
});

// True iff the glue must look up the user in Postgres before calling decideInit.
// (No active session AND no cached user snapshot in the hash.)
export const needsUserLookup = (hash: OtpHash) => !hash.token && !hash.user;

// -1 = max sends reached, positive seconds = still cooling down, null = ready to send.
export const computeCooldown = (sends: number, lastSend: number, otpResendMs: number, maxEmailSends: number, now: number): number | null => {
	if (sends >= maxEmailSends) return -1;
	if (lastSend <= 0) return null;
	const remaining = Math.ceil((otpResendMs - (now - lastSend)) / 1000);
	return remaining > 0 ? remaining : null;
};

export const isLocked = (failed: number, failedAt: number | null, lockDurationsMs: readonly number[], now: number) => {
	const d = lockDurationsMs[failed] ?? Infinity;
	return d !== 0 && (d === Infinity || !failedAt || now - failedAt < d);
};

export type HashOp = { kind: 'noop' } | { kind: 'clear' } | { kind: 'set'; fields: Record<string, string>; ttl?: number };

export type Outcome<R> = {
	response: R;
	hashOp: HashOp;
	alertCode?: string;
	lockUser?: typeof UserSub.Type;
};

export type Candidate = { code: string; sealed: typeof SealedToken.Type };

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
	now: number;
}): Outcome<OtpSession> => {
	const { sends, lastSend, sub, failed, link, failedAt, currentToken, candidate, config, now } = args;
	if (sends >= config.maxEmailSends) {
		return { response: new OtpSession({ token: INVALIDATED_TOKEN, countdown: -1 }), hashOp: { kind: 'noop' } };
	}
	const elapsed = now - lastSend;
	if (lastSend > 0 && elapsed < config.otpResendMs) {
		return { response: new OtpSession({ token: currentToken, countdown: (config.otpResendMs - elapsed) / 1000 }), hashOp: { kind: 'noop' } };
	}
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
				last_send: String(now),
				failed_at: failedAt ? String(failedAt) : '',
				sends: String(sends + 1),
			},
		},
	};
};

export const decideInit = (i: {
	hash: OtpHash;
	hasOidc: boolean;
	cachedUser: CachedUser | null;
	email: typeof Email.Type;
	candidate: Candidate;
	config: AuthConfigShape;
	now: number;
}): Outcome<UserLocked | HasOidc | OtpSession> => {
	const { hash, hasOidc, cachedUser, email, candidate, config, now } = i;

	if (hash.token) {
		if (isLocked(hash.failed, hash.failedAt, config.lockDurationsMs, now)) {
			return { response: new UserLocked({ failed: hash.failed, failed_at: hash.failedAt }), hashOp: { kind: 'noop' } };
		}
		const countdown = computeCooldown(hash.sends, hash.lastSend, config.otpResendMs, config.maxEmailSends, now);
		if (hasOidc) return { response: new HasOidc({ has_oidc: true, email, countdown }), hashOp: { kind: 'noop' } };
		if (countdown !== null) return { response: new OtpSession({ token: hash.token, countdown }), hashOp: { kind: 'noop' } };
		return sendDecision({
			sends: hash.sends,
			lastSend: hash.lastSend,
			sub: hash.sub,
			failed: hash.failed,
			link: hash.link,
			failedAt: hash.failedAt,
			currentToken: hash.token,
			candidate,
			config,
			now,
		});
	}

	if (cachedUser === null) {
		return sendDecision({
			sends: hash.sends,
			lastSend: hash.lastSend,
			sub: null,
			failed: 0,
			link: false,
			failedAt: null,
			currentToken: INVALIDATED_TOKEN,
			candidate,
			config,
			now,
		});
	}
	if (cachedUser.locked) {
		return { response: new UserLocked({ failed: config.lockDurationsMs.indexOf(Infinity), failed_at: null }), hashOp: { kind: 'noop' } };
	}
	if (cachedUser.has_oidc) {
		return { response: new HasOidc({ has_oidc: true, email, countdown: null }), hashOp: { kind: 'noop' } };
	}
	return sendDecision({
		sends: hash.sends,
		lastSend: hash.lastSend,
		sub: cachedUser.sub,
		failed: 0,
		link: false,
		failedAt: null,
		currentToken: INVALIDATED_TOKEN,
		candidate,
		config,
		now,
	});
};

export const decideLink = (i: {
	hash: OtpHash;
	cachedUser: CachedUser | null;
	candidate: Candidate;
	config: AuthConfigShape;
	now: number;
}): Outcome<UserLocked | OtpSession> => {
	const { hash, cachedUser, candidate, config, now } = i;

	// Cap-checked first so maxed-out users get a deterministic response even with no cached user.
	if (computeCooldown(hash.sends, hash.lastSend, config.otpResendMs, config.maxEmailSends, now) === -1) {
		return { response: new OtpSession({ token: INVALIDATED_TOKEN, countdown: -1 }), hashOp: { kind: 'noop' } };
	}
	// Glue is expected to throw SessionExpiredError before reaching here when cachedUser is null;
	// fall back to a permanent-lock response so the policy stays total.
	if (!cachedUser || cachedUser.locked) {
		return { response: new UserLocked({ failed: config.lockDurationsMs.indexOf(Infinity), failed_at: null }), hashOp: { kind: 'noop' } };
	}
	return sendDecision({
		sends: hash.sends,
		lastSend: hash.lastSend,
		sub: cachedUser.sub,
		failed: 0,
		link: true,
		failedAt: null,
		currentToken: INVALIDATED_TOKEN,
		candidate,
		config,
		now,
	});
};

export const decideHandle = (i: {
	hash: OtpHash;
	decoded: { code: string; gen: number };
	email: typeof Email.Type;
	inputCode: string;
	candidate: Candidate;
	config: AuthConfigShape;
	now: number;
}): Outcome<AuthenticatedUser | 'AuthenticatedNewUser' | InvalidCode | UserLocked | OtpSession> => {
	const { hash, decoded, email, inputCode, candidate, config, now } = i;

	if (inputCode === 'resend_') {
		return sendDecision({
			sends: hash.sends,
			lastSend: hash.lastSend,
			sub: hash.sub,
			failed: hash.failed,
			link: hash.link,
			failedAt: hash.failedAt,
			currentToken: hash.token!,
			candidate,
			config,
			now,
		});
	}

	if (inputCode === decoded.code && now - decoded.gen < config.otpCodeTtlMs) {
		return {
			response: hash.sub ? new AuthenticatedUser({ sub: hash.sub, email, link: hash.link }) : ('AuthenticatedNewUser' as const),
			hashOp: { kind: 'clear' },
		};
	}

	const nextFailed = hash.failed + 1;
	const cappedIfNoUser = hash.sub ? Math.min(nextFailed, config.lockDurationsMs.length - 2) : nextFailed;
	const lockMs = config.lockDurationsMs[cappedIfNoUser] ?? Infinity;

	return {
		response:
			lockMs > 0
				? new UserLocked({ failed: cappedIfNoUser, failed_at: lockMs !== Infinity ? now : null })
				: new InvalidCode({ failed: cappedIfNoUser }),
		// No `ttl`: matches today's HSET (preserves existing hash TTL) rather than HSETEX.
		hashOp: { kind: 'set', fields: { token: lockMs ? INVALIDATED_TOKEN : hash.token!, failed: String(cappedIfNoUser), failed_at: String(now) } },
		lockUser: lockMs === Infinity && hash.sub ? hash.sub : undefined,
	};
};

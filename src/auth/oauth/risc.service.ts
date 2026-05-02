/**
 * Cross-Account Protection (RISC) event receiver.
 *
 * Google pushes signed JWTs (Security Event Tokens) to a registered endpoint
 * whenever a user's Google Account has a security-relevant change — token
 * revocation, session revocation, account hijack, etc. We validate the JWT
 * and dispatch to a handler so the caller can invalidate our local state
 * (delete tokens, kill sessions).
 *
 * Spec: https://developers.google.com/identity/protocols/risc
 */

import { Context, Effect } from 'effect';
import { Postgres } from '@polumeyv/lib/server';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { OAuthError } from '../errors';

const RISC_DISCOVERY = 'https://accounts.google.com/.well-known/risc-configuration';
const GOOGLE_ISSUER = 'https://accounts.google.com/';

type RiscDiscovery = {
	issuer: string;
	jwks_uri: string;
};

type SubjectClaim = {
	subject_type?: string;
	iss?: string;
	sub?: string;
	email?: string;
	token_type?: string;
	token_identifier_alg?: string;
	token?: string;
};

type SecurityEventPayload = JWTPayload & {
	events?: Record<string, { subject?: SubjectClaim; reason?: string; state?: string }>;
};

export type RiscEvent = {
	jti: string;
	type: string;
	subject: SubjectClaim;
	reason?: string;
	state?: string;
};

export class RiscConfig extends Context.Tag('RiscConfig')<RiscConfig, { audiences: readonly string[] }>() {}

export class RiscService extends Effect.Service<RiscService>()('RiscService', {
	effect: Effect.gen(function* () {
		const { audiences } = yield* RiscConfig;
		const pg = yield* Postgres;

		// One-time fetch of the RISC discovery document + JWKS. jose caches JWKS
		// responses internally and honors Cache-Control so we don't need to.
		let discovery: RiscDiscovery | null = null;
		let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

		const loadDiscovery = Effect.tryPromise({
			try: async () => {
				if (discovery && jwks) return { discovery, jwks };
				const res = await fetch(RISC_DISCOVERY);
				if (!res.ok) throw new Error(`RISC discovery ${res.status}`);
				discovery = (await res.json()) as RiscDiscovery;
				jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
				return { discovery, jwks };
			},
			catch: (e) => new OAuthError({ cause: e, message: 'RISC discovery failed' }),
		});

		/** Validate + decode a Security Event Token. Throws on any failure. */
		const verifyToken = (token: string) =>
			Effect.flatMap(loadDiscovery, ({ discovery, jwks }) =>
				Effect.tryPromise({
					try: async () => {
						const { payload } = await jwtVerify<SecurityEventPayload>(token, jwks, {
							issuer: discovery.issuer,
							audience: audiences as string[],
							// Security event tokens have no expiry — don't check `exp`.
							clockTolerance: Number.MAX_SAFE_INTEGER,
						});
						if (!payload.jti) throw new Error('Missing jti');
						if (!payload.events) throw new Error('Missing events claim');
						return payload;
					},
					catch: (e) => new OAuthError({ cause: e, message: 'RISC token validation failed' }),
				}),
			);

		/** Record this jti as seen; returns `true` if it was new (caller should process), `false` if dup. */
		const recordJti = (jti: string, type: string, subject: string | null) =>
			Effect.map(
				pg.use(
					(sql) => sql<{ inserted: boolean }[]>`
					INSERT INTO risc_events (jti, event_type, subject) VALUES (${jti}, ${type}, ${subject})
					ON CONFLICT (jti) DO NOTHING
					RETURNING TRUE as inserted
				`,
				),
				(rows) => rows.length > 0,
			);

		/** Verify + flatten into an event list, deduped by jti. Empty list means already seen. */
		const process = (token: string) =>
			Effect.flatMap(verifyToken(token), (payload) => {
				const jti = payload.jti!;
				const events = Object.entries(payload.events!).map(([type, ev]) => ({
					jti,
					type,
					subject: ev.subject ?? {},
					reason: ev.reason,
					state: ev.state,
				}));
				// Record the whole set under a single jti; if dup, return [].
				const first = events[0];
				return Effect.map(
					recordJti(jti, first?.type ?? 'unknown', first?.subject.sub ?? null),
					(isNew) => (isNew ? events : ([] as RiscEvent[])),
				);
			});

		return { process, verifyToken };
	}),
	dependencies: [],
}) {}

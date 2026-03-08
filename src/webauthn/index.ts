/**
 * @module @polumeyv/clients/webauthn
 *
 * Effect-based WebAuthn client using `@simplewebauthn/server`.
 *
 * Exports:
 *  - `WebAuthn`      — Context tag
 *  - `WebAuthnError` — Tagged error
 *  - `makeWebAuthn`  — Factory: `(rpID, rpName, expectedOrigin) => WebAuthn` (synchronous)
 *
 * @example
 * ```ts
 * // App layer construction
 * Layer.effect(WebAuthn, Effect.map(
 *   Effect.all([Config.string('PASSKEY_RP_ID'), Config.string('PASSKEY_RP_NAME'), Config.string('PUBLIC_APP_URL')]),
 *   ([rpId, rpName, origin]) => makeWebAuthn(rpId, rpName, origin),
 * ))
 *
 * // Usage in a service
 * const wa = yield* WebAuthn;
 * const options = yield* wa.generateRegOptions({ userName: 'user@example.com' });
 * ```
 */
import { generateAuthenticationOptions, verifyAuthenticationResponse, generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import { Context, Data, Effect } from 'effect';

export type { AuthenticationResponseJSON, RegistrationResponseJSON, AuthenticatorTransportFuture, CredentialDeviceType } from '@simplewebauthn/server';

export class WebAuthnError extends Data.TaggedError('WebAuthnError')<{ cause?: unknown; message?: string }> {}

type GenAuthOpts = Omit<NonNullable<Parameters<typeof generateAuthenticationOptions>[0]>, 'rpID'>;
type VerifyAuthOpts = { response: Parameters<typeof verifyAuthenticationResponse>[0]['response']; expectedChallenge: string; credential: Parameters<typeof verifyAuthenticationResponse>[0]['credential'] };
type GenRegOpts = Omit<Parameters<typeof generateRegistrationOptions>[0], 'rpID' | 'rpName'>;
type VerifyRegOpts = { response: Parameters<typeof verifyRegistrationResponse>[0]['response']; expectedChallenge: string };

interface WebAuthnImpl {
	generateAuthOptions: (opts?: GenAuthOpts) => Effect.Effect<Awaited<ReturnType<typeof generateAuthenticationOptions>>, WebAuthnError>;
	verifyAuth: (opts: VerifyAuthOpts) => Effect.Effect<Awaited<ReturnType<typeof verifyAuthenticationResponse>>, WebAuthnError>;
	generateRegOptions: (opts: GenRegOpts) => Effect.Effect<Awaited<ReturnType<typeof generateRegistrationOptions>>, WebAuthnError>;
	verifyReg: (opts: VerifyRegOpts) => Effect.Effect<Awaited<ReturnType<typeof verifyRegistrationResponse>>, WebAuthnError>;
}

export class WebAuthn extends Context.Tag('WebAuthn')<WebAuthn, WebAuthnImpl>() {}

export const makeWebAuthn = (rpID: string, rpName: string, expectedOrigin: string): WebAuthnImpl =>
	WebAuthn.of({
		generateAuthOptions: (opts) =>
			Effect.tryPromise({ try: () => generateAuthenticationOptions({ rpID, ...opts }), catch: (e) => new WebAuthnError({ cause: e }) }),
		verifyAuth: (opts) =>
			Effect.tryPromise({
				try: () => verifyAuthenticationResponse({ response: opts.response, expectedChallenge: opts.expectedChallenge, expectedOrigin, expectedRPID: rpID, credential: opts.credential }),
				catch: (e) => new WebAuthnError({ cause: e }),
			}),
		generateRegOptions: (opts) =>
			Effect.tryPromise({ try: () => generateRegistrationOptions({ rpID, rpName, ...opts }), catch: (e) => new WebAuthnError({ cause: e }) }),
		verifyReg: (opts) =>
			Effect.tryPromise({
				try: () => verifyRegistrationResponse({ response: opts.response, expectedChallenge: opts.expectedChallenge, expectedOrigin, expectedRPID: rpID }),
				catch: (e) => new WebAuthnError({ cause: e }),
			}),
	});

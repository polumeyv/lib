import { generateAuthenticationOptions, verifyAuthenticationResponse, generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { Context, Effect, Schema } from 'effect';
import { Redis } from '@polumeyv/lib/server';
import { PasskeyRepository } from './passkey.repo';
import { AuthConfig } from '../config';
import { UserSub } from '../model';
import { SessionService } from '@polumeyv/lib/server';
import { WebAuthnError } from '../errors';

export class PasskeyConfig extends Context.Tag('PasskeyConfig')<
	PasskeyConfig,
	{ readonly rpID: string; readonly rpName: string; readonly expectedOrigin: string }
>() {}

const Key = (sub: string) => `webauthn:${sub}`;

/** Passkey (WebAuthn) authentication service — server-only. Consuming apps must provide `Redis`, `AuthConfig`, `Postgres`, and `PasskeyConfig` layers. */
export class PasskeyService extends Effect.Service<PasskeyService>()('PasskeyService', {
	effect: Effect.gen(function* () {
		const { webauthnSessionTtl } = yield* AuthConfig;
		const session = yield* SessionService;
		const { rpID, rpName, expectedOrigin } = yield* PasskeyConfig;
		const repo = yield* PasskeyRepository;

		return {
			/** Generates authentication options and stores the challenge in Redis. */
			generateAuthOptions: Effect.tap(
				Effect.zip(
					Effect.tryPromise({
						try: () => generateAuthenticationOptions({ rpID }),
						catch: (e) => new WebAuthnError({ cause: e, message: 'Failed to generate auth options' }),
					}),
					Effect.sync(() => Bun.randomUUIDv7()),
				),
				([options, challengeKey]) => session.push(options.challenge, webauthnSessionTtl, Key(challengeKey)),
			).pipe(Effect.tapError((e) => Effect.logWarning('[passkey] generateAuthOptions failed', e))),

			/** Verifies an authentication response against the stored challenge and credential. Updates the counter on success. */
			verifyAuth: ({ challengeKey, response }: { challengeKey: string; response: AuthenticationResponseJSON }) =>
				Effect.zip(session.pop<{ challenge: string }>(Key(challengeKey)), repo.findOne(response.id)).pipe(
					Effect.tryMapPromise({
						try: ([stored, credential]) =>
							verifyAuthenticationResponse({
								response,
								expectedChallenge: stored.challenge,
								expectedOrigin,
								expectedRPID: rpID,
								credential: {
									id: credential.id,
									publicKey: new Uint8Array(credential.public_key),
									counter: credential.counter,
									transports: credential.transports ? [...credential.transports] : undefined,
								},
							}).then((r) => ({ r, credential })),
						catch: (e) => new WebAuthnError({ cause: e, message: 'Auth response verification threw' }),
					}),
					Effect.filterOrFail(
						({ r }) => r.verified,
						() => new WebAuthnError({ message: 'Auth is not verified' }),
					),
					Effect.andThen(({ r, credential }) => Effect.as(repo.updateCounter({ id: credential.id, counter: r.authenticationInfo.newCounter }), credential.sub)),
					Effect.tapError((e) => Effect.logWarning('[passkey] verifyAuth failed', e)),
				),

			/** Generates registration options for a user, excluding any existing credentials. */
			generateRegOptions: (user: { sub: typeof UserSub.Type; email: string }) =>
				repo.findCredentials(user.sub).pipe(
					Effect.tryMapPromise({
						try: (creds) =>
							generateRegistrationOptions({
								rpID,
								rpName,
								userName: user.email,
								attestationType: 'none',
								preferredAuthenticatorType: 'localDevice',
								excludeCredentials: creds.map(({ id, transports }) => ({ id, transports: transports ? [...transports] : undefined })),
							}),
						catch: (e) => new WebAuthnError({ cause: e, message: 'Failed to generate registration options' }),
					}),
					Effect.tap((options) => session.push(Key(user.sub), webauthnSessionTtl, { challenge: options.challenge, webauthn_user_id: options.user.id })),
					Effect.tapError((e) => Effect.logWarning('[passkey] generateRegOptions failed', e)),
				),

			/** Verifies a registration response and persists the new credential. Fails if verification fails. */
			verifyReg: (sub: typeof UserSub.Type, response: RegistrationResponseJSON) =>
				Effect.andThen(session.pop<{ challenge: string; webauthn_user_id: string }>(Key(sub)), (stored) =>
					Effect.andThen(
						Effect.filterOrFail(
							Effect.tryPromise({
								try: () => verifyRegistrationResponse({ response, expectedChallenge: stored.challenge, expectedOrigin, expectedRPID: rpID }),
								catch: (e) => new WebAuthnError({ cause: e, message: 'Registration response verification threw' }),
							}),
							(r) => r.verified,
							() => new WebAuthnError({ message: 'Registration response verification rejected' }),
						),
						(r) =>
							repo.insert({
								id: r.registrationInfo.credential.id,
								sub,
								webauthn_user_id: stored.webauthn_user_id,
								public_key: new Uint8Array(r.registrationInfo.credential.publicKey),
								counter: r.registrationInfo.credential.counter,
								device_type: r.registrationInfo.credentialDeviceType,
								backed_up: r.registrationInfo.credentialBackedUp,
								transports: r.registrationInfo.credential.transports ?? null,
							}),
					),
				).pipe(Effect.tapError((e) => Effect.logWarning('[passkey] verifyReg failed', e))),

			listPasskeys: (sub: typeof UserSub.Type) => repo.findAll(sub),

			deletePasskey: (sub: typeof UserSub.Type, id: string) => repo.remove({ sub, id }),
		};
	}),
	dependencies: [PasskeyRepository.Default],
}) {}

import { generateAuthenticationOptions, verifyAuthenticationResponse, generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { CredentialDeviceType, AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { Context, Data, Effect, Layer } from 'effect';
import { Postgres, SessionService } from '@polumeyv/lib/server';
import type { HttpStatusError } from '@polumeyv/lib/error';
import type { UserSub, AuthPayload } from '../../user/model';
import type { PasskeyTable, RegistrationResponse, VerifyAuthInput } from './model';

/** Tagged error for WebAuthn / passkey operations. */
export class WebAuthnError extends Data.TaggedError('WebAuthnError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	readonly statusCode = 400 as const;
}

const Key = (challengeId: string) => `webauthn:${challengeId}`;

export class PasskeyConfig extends Context.Service<PasskeyConfig, { readonly rpID: string; readonly rpName: string; readonly expectedOrigin: string }>()(
	'PasskeyConfig',
) {}

/** Passkey (WebAuthn) authentication service — server-only. Consuming apps must provide `Redis`, `Postgres`, and `PasskeyConfig` layers. */
export class PasskeyService extends Context.Service<PasskeyService>()('PasskeyService', {
	make: Effect.gen(function* () {
		const session = yield* SessionService;
		const { rpID, rpName, expectedOrigin } = yield* PasskeyConfig;
		const pg = yield* Postgres;

		return {
			/** Generates authentication options and stores the challenge in Redis. */
			generateAuthOptions: Effect.gen(function* () {
				const challengeKey = Key(Bun.randomUUIDv7());
				const optionsJSON = yield* Effect.promise(() => generateAuthenticationOptions({ rpID }));
				yield* session.set(challengeKey, 300, optionsJSON.challenge);
				return [optionsJSON, challengeKey] as const;
			}),

			/** Verifies an authentication response against the stored challenge and credential. Updates the counter on success. */
			verifyAuth: ({ challengeKey, response }: VerifyAuthInput) =>
				Effect.gen(function* () {
					const stored = yield* session.take<{ challenge: string }>(Key(challengeKey));
					// Unregistered passkey: the lookup returns no row → a clear, user-facing message instead of the
					// generic NoSuchElementError (which the client can't translate into anything meaningful).
					const credential = yield* pg.first<PasskeyTable[]>((sql) => sql`SELECT * FROM passkey_credentials WHERE id = ${response.id}`);
					if (!credential) return yield* new WebAuthnError({ message: 'No account is registered for this passkey.' });

					const r = yield* Effect.filterOrFail(
						Effect.tryPromise({
							try: () =>
								verifyAuthenticationResponse({
									response,
									expectedChallenge: stored.challenge,
									expectedOrigin,
									expectedRPID: rpID,
									credential: {
										id: credential.id,
										publicKey: new Uint8Array(credential.public_key),
										counter: credential.counter,
										transports: credential.transports?.slice(),
									},
								}),
							catch: (e) => new WebAuthnError({ cause: e, message: 'Auth response verification threw' }),
						}),
						(r) => r.verified,
						() => new WebAuthnError({ message: 'Auth is not verified' }),
					);

					// Bump the credential counter and load the auth payload in one round-trip.
					return yield* pg.first<[AuthPayload]>(
						(sql) => sql`
							WITH bump AS (
								UPDATE passkey_credentials SET counter = ${r.authenticationInfo.newCounter} WHERE id = ${credential.id}
							)
							SELECT sub, email, (terms_acc IS NOT NULL) AS terms_acc FROM users WHERE sub = ${credential.sub}
						`,
						{ onNull: 'fail' },
					);
				}),

			/** Generates registration options for a user, excluding any existing credentials. */
			generateRegOptions: (user: { sub: typeof UserSub.Type; email: string }) =>
				Effect.gen(function* () {
					const creds = yield* pg.use((sql) => sql<Pick<PasskeyTable, 'id' | 'transports'>[]>`SELECT id, transports FROM passkey_credentials WHERE sub = ${user.sub}`);

					const options = yield* Effect.tryPromise({
						try: () =>
							generateRegistrationOptions({
								rpID,
								rpName,
								userName: user.email,
								attestationType: 'none',
								preferredAuthenticatorType: 'localDevice',
								excludeCredentials: creds.map(({ id, transports }) => ({ id, transports: transports ? [...transports] : undefined })),
							}),
						catch: (e) => new WebAuthnError({ cause: e, message: 'Failed to generate registration options' }),
					});

					yield* session.set(Key(user.sub), 300, { challenge: options.challenge, webauthn_user_id: options.user.id });
					return options;
				}),

			/** Verifies a registration response and persists the new credential. Fails if verification fails. */
			verifyReg: (sub: UserSub, response: RegistrationResponse) =>
				Effect.gen(function* () {
					const stored = yield* session.take<{ challenge: string; webauthn_user_id: string }>(Key(sub));

					const r = yield* Effect.filterOrFail(
						Effect.tryPromise({
							try: () => verifyRegistrationResponse({ response, expectedChallenge: stored.challenge, expectedOrigin, expectedRPID: rpID }),
							catch: (e) => new WebAuthnError({ cause: e, message: 'Registration response verification threw' }),
						}),
						(r) => r.verified,
						() => new WebAuthnError({ message: 'Registration response verification rejected' }),
					);

					const { credential: cred, credentialDeviceType, credentialBackedUp } = r.registrationInfo;
					return yield* pg.use(
						(sql) => sql`
							INSERT INTO passkey_credentials (id, sub, webauthn_user_id, public_key, counter, device_type, backed_up, transports)
							VALUES (
								${cred.id},
								${sub},
								${stored.webauthn_user_id},
								${new Uint8Array(cred.publicKey)},
								${cred.counter},
								${credentialDeviceType},
								${credentialBackedUp},
								${cred.transports ? sql.array([...cred.transports]) : null}
							)
						`,
					);
				}),

			listPasskeys: (sub: UserSub) =>
				pg.use(
					(sql) =>
						sql<
							Pick<PasskeyTable, 'id' | 'device_type' | 'created_at'>[]
						>`SELECT id, device_type, created_at FROM passkey_credentials WHERE sub = ${sub} ORDER BY created_at DESC`,
				),

			deletePasskey: (sub: UserSub, id: string) => pg.use((sql) => sql`DELETE FROM passkey_credentials WHERE id = ${id} AND sub = ${sub}`),
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make);
}

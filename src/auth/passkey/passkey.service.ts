import { generateAuthenticationOptions, verifyAuthenticationResponse, generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, RegistrationResponseJSON, CredentialDeviceType, AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { Context, Effect } from 'effect';
import { Postgres, SessionService } from '@polumeyv/lib/server';
import { UserSub } from '../model';
import { WebAuthnError } from '../errors';

const Key = (challengeId: string) => `webauthn:${challengeId}`;

/**
 * ### Required table
 *
 * ```sql
 * CREATE TABLE passkey_credentials (
 *   id               VARCHAR(255)  PRIMARY KEY,
 *   sub              UUID          NOT NULL REFERENCES users(sub),
 *   webauthn_user_id VARCHAR(255)  NOT NULL,
 *   public_key       BYTEA         NOT NULL,
 *   counter          INTEGER       NOT NULL DEFAULT 0,
 *   device_type      VARCHAR(32),
 *   backed_up        BOOLEAN       NOT NULL DEFAULT FALSE,
 *   transports       VARCHAR[]     DEFAULT NULL,
 *   created_at       TIMESTAMPTZ   NOT NULL DEFAULT now()
 * );
 * ```
 */
interface PasskeyCredential {
	id: string;
	sub: typeof UserSub.Type;
	webauthn_user_id: string;
	public_key: Uint8Array;
	counter: number;
	device_type: CredentialDeviceType | null;
	backed_up: boolean;
	transports: AuthenticatorTransportFuture[] | null;
	created_at: Date;
}

export class PasskeyConfig extends Context.Tag('PasskeyConfig')<PasskeyConfig, { readonly rpID: string; readonly rpName: string; readonly expectedOrigin: string }>() {}

/** Passkey (WebAuthn) authentication service — server-only. Consuming apps must provide `Redis`, `Postgres`, and `PasskeyConfig` layers. */
export class PasskeyService extends Effect.Service<PasskeyService>()('PasskeyService', {
	effect: Effect.gen(function* () {
		const session = yield* SessionService;
		const { rpID, rpName, expectedOrigin } = yield* PasskeyConfig;
		const pg = yield* Postgres;

		return {
			/** Generates authentication options and stores the challenge in Redis. */
			generateAuthOptions: Effect.zip(
				Effect.tryPromise({
					try: () => generateAuthenticationOptions({ rpID }),
					catch: (e) => new WebAuthnError({ cause: e, message: 'Failed to generate auth options' }),
				}),
				Effect.sync(() => Bun.randomUUIDv7()),
			).pipe(
				Effect.tap(([options, challengeKey]) => session.push(options.challenge, 300, Key(challengeKey))),
				Effect.tapError((e) => Effect.logWarning('[passkey] generateAuthOptions failed', e)),
			),

			/** Verifies an authentication response against the stored challenge and credential. Updates the counter on success. */
			verifyAuth: ({ challengeKey, response }: { challengeKey: string; response: AuthenticationResponseJSON }) =>
				Effect.zip(
					session.pop<{ challenge: string }>(Key(challengeKey)),
					pg.first((sql) => sql<PasskeyCredential[]>`SELECT * FROM passkey_credentials WHERE id = ${response.id}`).pipe(Effect.flatMap(Effect.fromNullable)),
				).pipe(
					Effect.flatMap(([stored, credential]) =>
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
						}).pipe(
							Effect.filterOrFail(
								(r) => r.verified,
								() => new WebAuthnError({ message: 'Auth is not verified' }),
							),
							Effect.tap((r) => pg.use((sql) => sql`UPDATE passkey_credentials SET counter = ${r.authenticationInfo.newCounter} WHERE id = ${credential.id}`)),
							Effect.as(credential.sub),
						),
					),
					Effect.tapError((e) => Effect.logWarning('[passkey] verifyAuth failed', e)),
				),

			/** Generates registration options for a user, excluding any existing credentials. */
			generateRegOptions: (user: { sub: typeof UserSub.Type; email: string }) =>
				pg
					.use((sql) => sql<Pick<PasskeyCredential, 'id' | 'transports'>[]>`SELECT id, transports FROM passkey_credentials WHERE sub = ${user.sub}`)
					.pipe(
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
						Effect.tap((options) => session.push(Key(user.sub), 300, { challenge: options.challenge, webauthn_user_id: options.user.id })),
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
							pg.use(
								(sql) => sql`
								INSERT INTO passkey_credentials (id, sub, webauthn_user_id, public_key, counter, device_type, backed_up, transports)
								VALUES (
									${r.registrationInfo.credential.id},
									${sub},
									${stored.webauthn_user_id},
									${new Uint8Array(r.registrationInfo.credential.publicKey)},
									${r.registrationInfo.credential.counter},
									${r.registrationInfo.credentialDeviceType},
									${r.registrationInfo.credentialBackedUp},
									${r.registrationInfo.credential.transports ? sql.array([...r.registrationInfo.credential.transports]) : null}
								)
							`,
							),
					),
				).pipe(Effect.tapError((e) => Effect.logWarning('[passkey] verifyReg failed', e))),

			listPasskeys: (sub: typeof UserSub.Type) =>
				pg.use(
					(sql) =>
						sql<
							Pick<PasskeyCredential, 'id' | 'device_type' | 'created_at'>[]
						>`SELECT id, device_type, created_at FROM passkey_credentials WHERE sub = ${sub} ORDER BY created_at DESC`,
				),

			deletePasskey: (sub: typeof UserSub.Type, id: string) => pg.use((sql) => sql`DELETE FROM passkey_credentials WHERE id = ${id} AND sub = ${sub}`),
		};
	}),
}) {}

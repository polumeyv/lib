/**
 * Passkey credential schema, types, and repository.
 *
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
 *
 * | Column             | Type           | Description                                                         |
 * |--------------------|----------------|---------------------------------------------------------------------|
 * | `id`               | `VARCHAR(255)` | Credential ID from the authenticator.                               |
 * | `sub`              | `UUID`         | Foreign key to `users.sub`.                                         |
 * | `webauthn_user_id` | `VARCHAR(255)` | WebAuthn user handle (opaque ID sent to the authenticator).         |
 * | `public_key`       | `BYTEA`        | COSE public key bytes.                                              |
 * | `counter`          | `INTEGER`      | Signature counter for clone detection.                              |
 * | `device_type`      | `VARCHAR(32)`  | `singleDevice` or `multiDevice` (nullable).                        |
 * | `backed_up`        | `BOOLEAN`      | Whether the credential is backed up (e.g. synced via iCloud/Google).|
 * | `transports`       | `VARCHAR[]`    | Hint array (`usb`, `ble`, `nfc`, `internal`, etc.) or `NULL`.      |
 * | `created_at`       | `TIMESTAMPTZ`  | When the credential was registered.                                 |
 */
import { Effect } from 'effect';
import { Postgres } from '@polumeyv/lib/server';
import type { CredentialDeviceType, AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { UserSub } from '../model';

export type { RegistrationResponseJSON, AuthenticationResponseJSON, WebAuthnCredential } from '@simplewebauthn/server';

/** A stored WebAuthn passkey credential row. */
export interface PasskeyCredential {
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

export type PasskeySummary = Pick<PasskeyCredential, 'id' | 'device_type' | 'created_at'>;
export type PasskeyForAuth = Pick<PasskeyCredential, 'id' | 'transports'>;

export class PasskeyRepository extends Effect.Service<PasskeyRepository>()('PasskeyRepository', {
	effect: Effect.gen(function* () {
		const pg = yield* Postgres;

		return {
			findAll: (sub: typeof UserSub.Type) =>
				pg.use((sql) => sql<PasskeySummary[]>`SELECT id, device_type, created_at FROM passkey_credentials WHERE sub = ${sub} ORDER BY created_at DESC`),

			findCredentials: (sub: typeof UserSub.Type) =>
				pg.use((sql) => sql<PasskeyForAuth[]>`SELECT id, transports FROM passkey_credentials WHERE sub = ${sub}`),

			findOne: (id: string) =>
				Effect.andThen(
					pg.first((sql) => sql<PasskeyCredential[]>`SELECT * FROM passkey_credentials WHERE id = ${id}`),
					Effect.fromNullable,
				),

			insert: (req: Omit<PasskeyCredential, 'created_at'>) =>
				pg.use(
					(sql) => sql`
					INSERT INTO passkey_credentials (id, sub, webauthn_user_id, public_key, counter, device_type, backed_up, transports)
					VALUES (${req.id}, ${req.sub}, ${req.webauthn_user_id}, ${req.public_key}, ${req.counter}, ${req.device_type}, ${req.backed_up}, ${req.transports ? sql.array(req.transports) : null})
				`,
				),

			updateCounter: (req: Pick<PasskeyCredential, 'id' | 'counter'>) =>
				pg.use((sql) => sql`UPDATE passkey_credentials SET counter = ${req.counter} WHERE id = ${req.id}`),

			remove: (req: Pick<PasskeyCredential, 'sub' | 'id'>) =>
				pg.use((sql) => sql`DELETE FROM passkey_credentials WHERE id = ${req.id} AND sub = ${req.sub}`),
		};
	}),
}) {}

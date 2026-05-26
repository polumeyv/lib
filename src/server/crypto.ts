/**
 * AES-256-GCM at-rest encryption for secrets.
 *
 * Apps provide a passphrase via `CryptoConfig`; the service derives a 32-byte AES key (SHA-256
 * of the UTF-8 passphrase) at construction and exposes:
 *  - `encode / decode` — Schema codec over `string | null` (null passes through), for storage
 *    layers that wrap nullable token columns. Callers needing structured payloads `JSON.stringify`/`JSON.parse` themselves.
 *
 * Wire format: base64url-encoded `iv (12 bytes) || ciphertext || GCM tag (16 bytes)`.
 */

import { Context, Effect, Layer, Option, Schema, SchemaGetter, SchemaIssue } from 'effect';

const IV_BYTES = 12;
/** App-provided passphrase. Derived to a 256-bit AES-GCM key via SHA-256 at service construction. */
export class CryptoConfig extends Context.Service<CryptoConfig, { readonly key: string }>()('CryptoConfig') {}

export class CryptoService extends Context.Service<CryptoService>()('CryptoService', {
	make: Effect.gen(function* () {
		const { key: passphrase } = yield* CryptoConfig;

		const aesKey = yield* Effect.promise(() =>
			crypto.subtle
				.digest('SHA-256', new TextEncoder().encode(passphrase))
				.then((hash) => crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])),
		);

		// Schema codec for nullable string fields (e.g. OAuth tokens in Postgres). Null passes through.
		// AES-GCM transform over a non-null string: ciphertext (Encoded) <-> plaintext (Type).
		const Codec = Schema.NullOr(
			Schema.String.pipe(
				Schema.decodeTo(Schema.String, {
					decode: SchemaGetter.transformOrFail((ciphertext: string) =>
						Effect.tryPromise({
							try: () =>
								((bin) =>
									crypto.subtle.decrypt({ name: 'AES-GCM', iv: bin.subarray(0, IV_BYTES) }, aesKey, bin.subarray(IV_BYTES)).then((pt) => new TextDecoder().decode(pt)))(
									Uint8Array.fromBase64(ciphertext, { alphabet: 'base64url' }),
								),
							catch: () => new SchemaIssue.InvalidValue(Option.some(ciphertext), { message: 'Decryption failed' }),
						}),
					),
					encode: SchemaGetter.transformOrFail((plaintext: string) =>
						Effect.tryPromise({
							try: () =>
								((iv) =>
									crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext)).then((ct) => {
										const out = new Uint8Array(IV_BYTES + ct.byteLength);
										out.set(iv);
										out.set(new Uint8Array(ct), IV_BYTES);
										return out.toBase64({ alphabet: 'base64url', omitPadding: true });
									}))(crypto.getRandomValues(new Uint8Array(IV_BYTES))),
							catch: () => new SchemaIssue.InvalidValue(Option.some(plaintext), { message: 'Encryption failed' }),
						}),
					),
				}),
			),
		);
		return {
			encode: Schema.encodeEffect(Codec),
			decode: Schema.decodeEffect(Codec),
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make);
}

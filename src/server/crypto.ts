/**
 * AES-256-GCM at-rest encryption for secrets.
 *
 * Apps provide a passphrase via `CryptoConfig`; the service derives a 32-byte AES key (SHA-256
 * of the UTF-8 passphrase) at construction and exposes:
 *  - `encode / decode` — Schema codec over `string | null` (null passes through), for storage
 *    layers that wrap nullable token columns
 *  - `encodeJson / decodeJson` — same crypto over an arbitrary JSON value (`JSON.stringify` then
 *    encrypt; decrypt then `JSON.parse`), for storing structured payloads as ciphertext
 *
 * Wire format: base64url-encoded `iv (12 bytes) || ciphertext || GCM tag (16 bytes)`.
 */

import { Context, Effect, ParseResult, Schema } from 'effect';

const IV_BYTES = 12;
const B64URL = { alphabet: 'base64url' as const, omitPadding: true };

/** App-provided passphrase. Derived to a 256-bit AES-GCM key via SHA-256 at service construction. */
export class CryptoConfig extends Context.Tag('CryptoConfig')<CryptoConfig, { readonly key: string }>() {}

export class CryptoService extends Effect.Service<CryptoService>()('CryptoService', {
	effect: Effect.gen(function* () {
		const { key: passphrase } = yield* CryptoConfig;
		const aesKey = yield* Effect.promise(async () => {
			const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(passphrase));
			return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
		});

		// AES-GCM transform over a non-null string: ciphertext (Encoded) <-> plaintext (Type).
		const StringCrypto = Schema.transformOrFail(Schema.String, Schema.String, {
			strict: true,
			decode: (ciphertext, _, ast) =>
				Effect.tryPromise({
					try: () =>
						((bin) =>
							crypto.subtle.decrypt({ name: 'AES-GCM', iv: bin.subarray(0, IV_BYTES) }, aesKey, bin.subarray(IV_BYTES)).then((pt) => new TextDecoder().decode(pt)))(
							Uint8Array.fromBase64(ciphertext, { alphabet: 'base64url' }),
						),
					catch: () => new ParseResult.Type(ast, ciphertext, 'Decryption failed'),
				}),
			encode: (plaintext, _, ast) =>
				Effect.tryPromise({
					try: () =>
						((iv) =>
							crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext)).then((ct) => {
								const out = new Uint8Array(IV_BYTES + ct.byteLength);
								out.set(iv);
								out.set(new Uint8Array(ct), IV_BYTES);
								return out.toBase64(B64URL);
							}))(crypto.getRandomValues(new Uint8Array(IV_BYTES))),
					catch: () => new ParseResult.Type(ast, plaintext, 'Encryption failed'),
				}),
		});

		// Schema codec for nullable string fields (e.g. OAuth tokens in Postgres). Null passes through.
		const Codec = Schema.NullOr(StringCrypto);
		// JSON value <-> ciphertext: decrypt then `JSON.parse`, `JSON.stringify` then encrypt.
		const JsonCodec = Schema.compose(StringCrypto, Schema.parseJson());

		const decodeJsonCodec = Schema.decode(JsonCodec);
		return {
			encode: Schema.encode(Codec),
			decode: Schema.decode(Codec),
			encodeJson: Schema.encode(JsonCodec),
			// Decryption is authenticated (AES-GCM tag) and the payload is one we encrypted ourselves,
			// so the shape is guaranteed by construction — callers name it via the type parameter.
			decodeJson: <T = unknown>(ciphertext: string) => decodeJsonCodec(ciphertext) as Effect.Effect<T, ParseResult.ParseError>,
		};
	}),
}) {}

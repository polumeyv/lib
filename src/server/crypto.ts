/**
 * AES-256-GCM at-rest encryption for secrets.
 *
 * Apps provide a passphrase via `CryptoConfig`; the service derives a 32-byte AES key (SHA-256
 * of the UTF-8 passphrase) at construction and exposes:
 *  - `codec` — the AES Schema codec over a non-null string (ciphertext ⇄ plaintext). Compose it into a larger
 *    schema for structured payloads: `codec.pipe(S.decodeTo(JsonPayload))`.
 *  - `encode / decode` — `codec` wrapped in `S.NullOr` (null passes through), for storage layers over nullable columns.
 *
 * Wire format: base64url-encoded `iv (12 bytes) || ciphertext || GCM tag (16 bytes)`.
 */

import { Context, Effect, Layer, Option, SchemaGetter, SchemaIssue } from 'effect';
import * as S from 'effect/Schema';

/** App-provided passphrase. Derived to a 256-bit AES-GCM key via SHA-256 at service construction. */
export class CryptoConfig extends Context.Service<CryptoConfig, { readonly key: string; readonly iv_bytes?: number }>()('CryptoConfig') {}

export class CryptoService extends Context.Service<CryptoService>()('CryptoService', {
	make: Effect.gen(function* () {
		const { key: passphrase, iv_bytes = 12 } = yield* CryptoConfig;

		const aesKey = yield* Effect.promise(() =>
			crypto.subtle
				.digest('SHA-256', new TextEncoder().encode(passphrase))
				.then((hash) => crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])),
		);

		// AES-GCM transform over a non-null string: ciphertext (Encoded) <-> plaintext (Type). Exposed as `codec` so callers
		// can compose it into their own schemas (e.g. `codec.pipe(S.decodeTo(JsonPayload))`) instead of bridging a function.
		const codec = S.String.pipe(
			S.decodeTo(S.String, {
				decode: SchemaGetter.transformOrFail((ciphertext: string) =>
					Effect.tryPromise({
						try: () =>
							((bin) =>
								crypto.subtle.decrypt({ name: 'AES-GCM', iv: bin.subarray(0, iv_bytes) }, aesKey, bin.subarray(iv_bytes)).then((pt) => new TextDecoder().decode(pt)))(
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
									const out = new Uint8Array(iv_bytes + ct.byteLength);
									out.set(iv);
									out.set(new Uint8Array(ct), iv_bytes);
									return out.toBase64({ alphabet: 'base64url', omitPadding: true });
								}))(crypto.getRandomValues(new Uint8Array(iv_bytes))),
						catch: () => new SchemaIssue.InvalidValue(Option.some(plaintext), { message: 'Encryption failed' }),
					}),
				),
			}),
		);
		// Nullable convenience for storage layers that wrap nullable columns (e.g. OAuth tokens): null passes through.
		const NullableCodec = S.NullOr(codec);
		return {
			codec,
			encode: S.encodeEffect(NullableCodec),
			decode: S.decodeEffect(NullableCodec),
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make);
}

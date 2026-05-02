import { Effect, Context, Layer, Schema, ParseResult } from 'effect';
import { SealedToken } from './otp.model';
import { IV_BYTES, B64URL } from '../config';

/** Tag for providing the raw JWK string used to derive the OTP encryption key. */
export class OtpKeyConfig extends Context.Tag('OtpKeyConfig')<OtpKeyConfig, { readonly raw: string }>() {}

/** Tag for the imported AES-GCM CryptoKey used to seal and unseal OTP tokens. */
export class OtpKey extends Context.Tag('OtpKey')<OtpKey, CryptoKey>() {}

/** Layer that decodes the raw JWK config and imports it as an AES-GCM CryptoKey. */
export const OtpKeyFromConfig = Layer.effect(
	OtpKey,
	Effect.flatMap(OtpKeyConfig, ({ raw }) =>
		Effect.promise(() => crypto.subtle.importKey('jwk', JSON.parse(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])),
	),
);

/**
 * Bidirectional codec between a sealed AES-GCM token and its plaintext `{ code, gen }` payload.
 * Encode: generates a random IV, encrypts the JSON payload, and returns a base64url SealedToken.
 * Decode: splits the IV from ciphertext, decrypts, and parses the JSON payload.
 */
export const makeVerifyTokenCodec = (key: CryptoKey) =>
	Schema.transformOrFail(Schema.typeSchema(SealedToken), Schema.parseJson(Schema.Struct({ code: Schema.String, gen: Schema.Number })), {
		strict: false,
		decode: (sealed) =>
			Effect.tryPromise({
				try: () =>
					((bin) =>
						crypto.subtle.decrypt({ name: 'AES-GCM', iv: bin.subarray(0, IV_BYTES) }, key, bin.subarray(IV_BYTES)).then((pt) => new TextDecoder().decode(pt)))(
						Uint8Array.fromBase64(sealed, B64URL),
					),
				catch: () => new ParseResult.Type(SealedToken.ast, sealed, 'Decryption failed'),
			}),
		encode: (json) =>
			Effect.tryPromise({
				try: () =>
					((iv) =>
						crypto.subtle
							.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(json))
							.then((ct) =>
								((out) => (out.set(iv), out.set(new Uint8Array(ct), IV_BYTES), SealedToken.make(out.toBase64(B64URL))))(
									new Uint8Array(IV_BYTES + ct.byteLength),
								),
							))(crypto.getRandomValues(new Uint8Array(IV_BYTES))),
				catch: () => new ParseResult.Type(SealedToken.ast, json, 'Encryption failed'),
			}),
	});

import { Effect, ParseResult, Schema } from 'effect';
import { OAuth2ClientRegistry } from './client-registry';
import { OAuth2RequestError } from '../errors';

export const makeOAuthRequestSchema = (registry: ReadonlyMap<string, { readonly redirectUris: readonly string[]; readonly scope: string }>) =>
	Schema.Struct({
		client_id: Schema.String.pipe(
			Schema.filter((id) => {
				if (!registry.has(id)) return 'Unknown client_id';
			}),
		),
		redirect_uri: Schema.String,
		response_type: Schema.Literal('code'),
		scope: Schema.String,
		state: Schema.optional(Schema.String),
		code_challenge: Schema.String.pipe(Schema.minLength(43), Schema.maxLength(128)),
		code_challenge_method: Schema.Literal('S256'),
		nonce: Schema.optional(Schema.String),
	}).pipe(
		Schema.filter((req) => {
			const client = registry.get(req.client_id)!;
			if (!client.redirectUris.includes(req.redirect_uri)) return 'Invalid redirect_uri';
			if (client.scope !== req.scope) return 'Invalid scope';
		}),
	);

/** Parse + validate an OAuth2 authorization request against the registered client registry. */
export const validateOAuthRequest = (searchParams: URLSearchParams) =>
	Effect.flatMap(OAuth2ClientRegistry, (registry) =>
		Effect.mapError(
			Schema.decodeUnknown(makeOAuthRequestSchema(registry))(Object.fromEntries(searchParams)),
			(e) => new OAuth2RequestError({ message: ParseResult.TreeFormatter.formatErrorSync(e) }),
		),
	);

import { Context } from 'effect';

export interface OAuth2Client {
	readonly clientSecret: string;
	readonly redirectUris: readonly string[];
	readonly scope: string;
}

/** Registered OAuth2 clients keyed by client_id. */
export class OAuth2ClientRegistry extends Context.Tag('OAuth2ClientRegistry')<OAuth2ClientRegistry, ReadonlyMap<string, OAuth2Client>>() {}

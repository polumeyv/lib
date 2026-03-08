/**
 * @module @polumeyv/clients/mailcow
 *
 * Effect-based Mailcow API client for managing mail server resources.
 *
 * Exports:
 *  - `Mailcow`      — Context tag
 *  - `MailcowError`  — Tagged error
 *  - `makeMailcow`   — Factory: `(host, apiKey, serverIp, mailHost) => Mailcow` (synchronous — no lifecycle)
 *
 * @example
 * ```ts
 * // App layer construction
 * Layer.effect(Mailcow, Effect.map(
 *   Effect.all([Config.string('MAILCOW_HOST'), Config.string('MAILCOW_API_KEY'), Config.string('MAILCOW_SERVER_IP'), Config.string('MAILCOW_MAIL_HOST')]),
 *   ([host, apiKey, serverIp, mailHost]) => makeMailcow(host, apiKey, serverIp, mailHost),
 * ))
 *
 * // Usage in a service
 * const mc = yield* Mailcow;
 * const mailboxes = yield* mc.get('list-mailboxes', '/get/mailbox/all', MailboxSchema);
 * yield* mc.post('add-mailbox', '/add/mailbox', { local_part: 'user', domain: 'example.com', ... });
 * ```
 */
import { Context, Data, Effect, Option, ParseResult, Schema, Array as Arr, pipe } from 'effect';

export class MailcowError extends Data.TaggedError('MailcowError')<{ cause?: unknown; message?: string }> {}

interface MailcowImpl {
	get: <A, I>(operation: string, url: string, schema: Schema.Schema<A, I>) => Effect.Effect<A, MailcowError | ParseResult.ParseError, never>;
	post: (operation: string, url: string, body: unknown) => Effect.Effect<void, MailcowError | ParseResult.ParseError, never>;
	serverIp: string;
	mailHost: string;
}

export class Mailcow extends Context.Tag('Mailcow')<Mailcow, MailcowImpl>() {}

const ResponseSchema = Schema.Array(Schema.Struct({ type: Schema.Literal('success', 'error', 'danger'), msg: Schema.optional(Schema.Unknown) }));

export const makeMailcow = (host: string, apiKey: string, serverIp: string, mailHost: string) => {
	const base = `${host}/api/v1`;
	const headers = { 'Content-Type': 'application/json', 'X-API-Key': apiKey };

	const request = <A, I>(operation: string, url: string, schema: Schema.Schema<A, I>, body?: unknown) =>
		Effect.andThen(
			Effect.tryPromise({
				try: () => fetch(`${base}${url}`, body !== undefined ? { method: 'POST', headers, body: JSON.stringify(body) } : { headers }).then((r) => r.json()),
				catch: (e) => new MailcowError({ cause: e }),
			}),
			Schema.decodeUnknown(schema),
		);

	return Mailcow.of({
		get: (operation, url, schema) => request(operation, url, schema),
		post: (operation, url, body) =>
			Effect.andThen(request(operation, url, ResponseSchema, body), (rs) =>
				pipe(
					Arr.findFirst(rs, (x) => x.type !== 'success'),
					Option.match({
						onNone: () => Effect.void,
						onSome: (err) => Effect.fail(new MailcowError({ message: `[${operation}] ${Array.isArray(err.msg) ? Arr.join(err.msg as string[], ', ') : String(err.msg)}` })),
					}),
				),
			),
		serverIp,
		mailHost,
	});
};

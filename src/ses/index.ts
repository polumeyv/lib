/**
 * @module @polumeyv/clients/ses
 *
 * Effect-based AWS SES v2 email client.
 *
 * Exports:
 *  - `Ses`      — Context tag
 *  - `SesError` — Tagged error
 *  - `makeSes`  — Factory: `(enabled: string) => Effect<Ses>` (when not `'true'`, emails are logged instead of sent)
 *
 * @example
 * ```ts
 * // App layer construction
 * Layer.effect(Ses, makeSes(EMAIL_ENABLED))
 *
 * // Usage in a service
 * const ses = yield* Ses;
 * yield* ses.sendEmail({ from: 'noreply@example.com', to, subject: 'Hello', html: '<p>Hi</p>', text: 'Hi' });
 * ```
 */
import { SESv2Client, SendEmailCommand, type Attachment } from '@aws-sdk/client-sesv2';
import { Context, Data, Effect } from 'effect';

export class SesError extends Data.TaggedError('SesError')<{ cause?: unknown; message?: string }> {}

const utf8 = (data: string) => ({ Data: data, Charset: 'UTF-8' }) as const;

interface SesImpl {
	sendEmail: (params: {
		from: string;
		to: string;
		subject: string;
		html: string;
		text: string;
		attachments?: Attachment[];
	}) => Effect.Effect<void, SesError>;
}

export class Ses extends Context.Tag('Ses')<Ses, SesImpl>() {}

export const makeSes = (enabled: string) =>
	Effect.map(Effect.sync(() => new SESv2Client()), (client) =>
		Ses.of({
			sendEmail: ({ from, to, subject, html, text, attachments }) =>
				enabled === 'true'
					? Effect.tryPromise({
							try: () =>
								client.send(
									new SendEmailCommand({
										FromEmailAddress: from,
										Destination: { ToAddresses: [to] },
										Content: {
											Simple: {
												Subject: utf8(subject),
												Body: { Html: utf8(html), Text: utf8(text) },
												Attachments: attachments,
											},
										},
									}),
								),
							catch: (e) => new SesError({ cause: e, message: `Failed to send email to ${to}` }),
						}).pipe(
							Effect.tapError((e) => Effect.logError(`[SES] ${e.cause}`)),
							Effect.asVoid,
						)
					: Effect.logInfo(`[DEV] Skipped email to ${to}: ${subject}`).pipe(Effect.asVoid),
		}),
	);

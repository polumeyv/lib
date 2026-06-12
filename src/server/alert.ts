/**
 * @module @polumeyv/utils/server/alert
 *
 * Effect-bridged Amazon SES v2 email sender. Apps provide an `AlertConfig` layer; the service
 * builds the `SESv2Client` once, exposes `send`, and (when `enabled: false`, e.g. dev) short-circuits
 * to a log-and-noop instead of hitting SES. The SES SDK is a plain npm package (not a Bun builtin),
 * so — unlike `Postgres`/`Redis` — there's no tag/live split: the whole service lives here.
 *
 * ```ts
 * // app db.ts:
 * Layer.provideMerge(
 *     Layer.mergeAll(AlertService.layer, …),
 *     Layer.succeed(AlertConfig, { region: PUBLIC_AWS_REGION, from: `noreply@${getHostname(PUBLIC_POLUMEYV_URL)}`, enabled: !dev }),
 * );
 *
 * // any service / handler:
 * const alert = yield* AlertService;
 * yield* alert.send({ to, subject, html, text });
 * ```
 *
 * `send` resolves to `void` and never wraps presentation — callers pass the final `html`/`text`
 * (branded shells, escaping, templating stay in the app). The sender is always `AlertConfig.from`;
 * `replyTo`/`attachments` are per-message options.
 */
import { SESv2Client, SendEmailCommand, type Attachment } from '@aws-sdk/client-sesv2';
import { Context, Data, Effect, Layer } from 'effect';
import type { HttpStatusError } from '@polumeyv/lib/error';

const utf8 = (Data: string) => ({ Data, Charset: 'UTF-8' }) as const;

export class AlertError extends Data.TaggedError('AlertError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 500 as const;
	}
}

/** App-provided SES settings. `from` is the default sender address; `enabled: false` short-circuits `send` to a log-and-noop (dev / tests). */
export class AlertConfig extends Context.Service<
	AlertConfig,
	{
		readonly region: string;
		readonly from: string;
		readonly enabled: boolean;
	}
>()('AlertConfig') {}

/** A single email, sent from `AlertConfig.from`; `replyTo` / `attachments` are optional per-message. */
export interface EmailInput {
	to: string;
	subject: string;
	html: string;
	text: string;
	replyTo?: string;
	attachments?: Attachment[];
}

/** Effect-bridged SES v2 sender. Apps provide `AlertConfig` and add `AlertService.layer`; consumers `yield* AlertService` for `{ send }`. */
export class AlertService extends Context.Service<AlertService>()('AlertService', {
	make: Effect.gen(function* () {
		const config = yield* AlertConfig;
		const client = new SESv2Client({ region: config.region });

		const send = (email: EmailInput): Effect.Effect<void, AlertError> =>
			!config.enabled
				? Effect.asVoid(Effect.logInfo(`[DEV] Skipped email to ${email.to}: ${email.subject}`))
				: Effect.tryPromise({
						try: () =>
							client.send(
								new SendEmailCommand({
									FromEmailAddress: config.from,
									Destination: { ToAddresses: [email.to] },
									Content: {
										Simple: { Subject: utf8(email.subject), Body: { Html: utf8(email.html), Text: utf8(email.text) }, Attachments: email.attachments },
									},
									...(email.replyTo ? { ReplyToAddresses: [email.replyTo] } : {}),
								}),
							),
						catch: (cause) => new AlertError({ cause }),
					}).pipe(
						Effect.asVoid,
						Effect.tapError((e) => Effect.logError('[SES]', e)),
					);

		return { send };
	}),
}) {
	static readonly layer = Layer.effect(this, this.make);
}

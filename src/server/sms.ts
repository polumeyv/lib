/**
 * @module @polumeyv/utils/server/sms
 *
 * Effect-bridged Telnyx SMS client. Apps provide `SmsConfig`; the service wraps the single
 * `POST /v2/messages` call. When `enabled: false` (e.g. dev), `send` logs and resolves to
 * `{ success: false }` instead of hitting the network.
 *
 * ```ts
 * // app db.ts:
 * Layer.provideMerge(
 *     Layer.mergeAll(SmsService.Default, …),
 *     Layer.succeed(SmsConfig, { apiKey, phoneNumber, messagingProfileId, enabled: !dev }),
 * );
 *
 * // any service:
 * const sms = yield* SmsService;
 * yield* sms.send({ to: '+15551234567', message: 'Hello!' });
 * ```
 */
import { Context, Data, Effect } from 'effect';
import type { HttpStatusError } from '@polumeyv/lib/error';

const TELNYX_API_URL = 'https://api.telnyx.com/v2/messages';

export class SmsError extends Data.TaggedError('SmsError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 500 as const;
	}
}

/** Check if message is an opt-out keyword */
export const isOptOutMessage = (text: string): boolean => ['STOP', 'UNSUBSCRIBE', 'CANCEL', 'END', 'QUIT'].includes(text.trim().toUpperCase());

/** Check if message is an opt-in keyword */
export const isOptInMessage = (text: string): boolean => ['START', 'SUBSCRIBE', 'YES', 'UNSTOP'].includes(text.trim().toUpperCase());

/** App-provided Telnyx credentials. `enabled: false` short-circuits `send` to a log-and-noop (dev / tests). */
export class SmsConfig extends Context.Tag('SmsConfig')<
	SmsConfig,
	{
		readonly apiKey: string;
		readonly phoneNumber: string;
		readonly messagingProfileId: string;
		readonly enabled: boolean;
	}
>() {}

/** Effect-bridged Telnyx SMS sender. */
export class SmsService extends Effect.Service<SmsService>()('SmsService', {
	effect: Effect.gen(function* () {
		const config = yield* SmsConfig;

		const send = ({ to, message }: { to: string; message: string }): Effect.Effect<{ success: boolean; messageId?: string }, SmsError> =>
			!config.enabled
				? Effect.as(Effect.logInfo(`[DEV] Skipped SMS to ${to}: ${message.slice(0, 50)}`), { success: false })
				: Effect.tryPromise({
						try: async () => {
							const response = await fetch(TELNYX_API_URL, {
								method: 'POST',
								headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.apiKey}` },
								body: JSON.stringify({
									from: config.phoneNumber,
									to,
									text: message,
									type: 'SMS',
									messaging_profile_id: config.messagingProfileId,
								}),
							});
							if (!response.ok) {
								const errorData = (await response.json()) as { errors?: Array<{ code?: string; detail?: string }> };
								throw new Error(`Telnyx error: ${errorData.errors?.[0]?.code} — ${errorData.errors?.[0]?.detail}`);
							}
							const data = (await response.json()) as { data: { id: string } };
							return { success: true as const, messageId: data.data.id };
						},
						catch: (e) => new SmsError({ cause: e, message: `Failed to send SMS to ${to}` }),
					}).pipe(Effect.tapError((e) => Effect.logError(`[SMS] ${e.cause}`)));

		return { send };
	}),
}) {}

/**
 * @module @polumeyv/utils/server/sms
 *
 * Effect-based Telnyx SMS client.
 *
 * Exports:
 *  - `Sms`      — Context tag
 *  - `SmsError` — Tagged error
 *  - `makeSms`  — Factory: `(config) => Sms` (when `enabled` is `false`, messages are logged instead of sent)
 *
 * @example
 * ```ts
 * // App layer construction
 * Layer.succeed(Sms, makeSms({ apiKey, phoneNumber, messagingProfileId, enabled: !dev }))
 *
 * // Usage in a service
 * const sms = yield* Sms;
 * yield* sms.send({ to: '+15551234567', message: 'Hello!' });
 * ```
 */
import { Context, Data, Effect } from 'effect';
import type { HttpStatusError } from './error';

const TELNYX_API_URL = 'https://api.telnyx.com/v2/messages';

export class SmsError extends Data.TaggedError('SmsError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 500 as const;
	}
}

interface SmsImpl {
	send: (params: { to: string; message: string }) => Effect.Effect<{ success: boolean; messageId?: string }, SmsError>;
}

export class Sms extends Context.Tag('Sms')<Sms, SmsImpl>() {}

/** Check if message is an opt-out keyword */
export const isOptOutMessage = (text: string): boolean => ['STOP', 'UNSUBSCRIBE', 'CANCEL', 'END', 'QUIT'].includes(text.trim().toUpperCase());

/** Check if message is an opt-in keyword */
export const isOptInMessage = (text: string): boolean => ['START', 'SUBSCRIBE', 'YES', 'UNSTOP'].includes(text.trim().toUpperCase());

export const makeSms = (config: { apiKey: string; phoneNumber: string; messagingProfileId: string; enabled: boolean }) =>
	Sms.of({
		send: ({ to, message }) =>
			config.enabled
				? Effect.tryPromise({
						try: async () => {
							const response = await fetch(TELNYX_API_URL, {
								method: 'POST',
								headers: {
									'Content-Type': 'application/json',
									Authorization: `Bearer ${config.apiKey}`,
								},
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
					}).pipe(Effect.tapError((e) => Effect.logError(`[SMS] ${e.cause}`)))
				: Effect.logInfo(`[DEV] Skipped SMS to ${to}: ${message.slice(0, 50)}`).pipe(Effect.map(() => ({ success: false as const }))),
	});

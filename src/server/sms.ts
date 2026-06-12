import { Context, Data, Effect, Layer } from 'effect';
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

/** Telnyx credentials for `SmsService.layer`. `enabled: false` short-circuits `send` to a log-and-noop (dev / tests). */
export interface SmsOptions {
	readonly apiKey: string;
	readonly phoneNumber: string;
	readonly messagingProfileId: string;
	readonly enabled: boolean;
}

class SmsConfig extends Context.Service<SmsConfig, SmsOptions>()('SmsConfig') {}

/** Effect-bridged Telnyx SMS sender. */
export class SmsService extends Context.Service<SmsService>()('SmsService', {
	make: Effect.gen(function* () {
		const config = yield* SmsConfig;

		const send = ({ to, message }: { to: string; message: string }): Effect.Effect<{ success: boolean }, SmsError> =>
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
							return { success: true as const };
						},
						catch: (e) => new SmsError({ cause: e, message: `Failed to send SMS to ${to}` }),
					}).pipe(Effect.tapError((e) => Effect.logError(`[SMS] ${e.cause}`)));

		return { send };
	}),
}) {
	/** Config is layer input, not a separate app-provided service (cf. `IdpClient.layer`). */
	static layer = (options: SmsOptions) => Layer.provide(Layer.effect(this, this.make), Layer.succeed(SmsConfig, options));
}

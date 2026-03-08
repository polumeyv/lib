/**
 * @module @polumeyv/clients/stripe — Webhook verification
 *
 * Exports:
 *  - `StripeWebhook`     — Context tag (webhook event verification)
 *  - `makeStripeWebhook` — Factory: `(secretKey, webhookSecret) => StripeWebhook`
 */
import StripeSDK from 'stripe';
import { Context, Effect } from 'effect';
import { StripeError } from './stripe';

export class StripeWebhook extends Context.Tag('StripeWebhook')<StripeWebhook, {
	verify: (body: string, signature: string) => Effect.Effect<StripeSDK.Event, StripeError, never>;
}>() {}

export const makeStripeWebhook = (secretKey: string, webhookSecret: string) => {
	const stripe = new StripeSDK(secretKey);
	return StripeWebhook.of({
		verify: (body, signature) =>
			Effect.tryPromise({
				try: () => stripe.webhooks.constructEventAsync(body, signature, webhookSecret),
				catch: (e) => new StripeError({ cause: e }),
			}),
	});
};

/**
 * @module @polumeyv/utils/server/stripe
 *
 * Tagged Effect error for Stripe SDK failures plus a `makeStripeCall` factory.
 * Each app constructs its own `new StripeSDK(secretKey)` directly (no Layer
 * needed — Stripe has no connection lifecycle), then wires up `stripeCall`
 * with `makeStripeCall(stripe)`. The helper:
 *   1. Wraps the SDK rejection in a tagged `StripeError` so callers can
 *      `Effect.catchTag('StripeError', …)`.
 *   2. Logs the underlying SDK error via `Effect.logError` on every failure
 *      so production logs show the real cause, not just `StripeError`.
 */
import StripeSDK from 'stripe';
import { Data, Effect } from 'effect';
import type { HttpStatusError } from './error';

type StripeSDKError = InstanceType<typeof StripeSDK.errors.StripeError>;

export class StripeError extends Data.TaggedError('StripeError')<{ err: StripeSDKError }> implements HttpStatusError {
	get statusCode() {
		return this.err.statusCode ?? 500;
	}
	get code() {
		return this.err.code;
	}
}

/** Build the Effect bridge for a given Stripe SDK instance. Maps rejections to
 *  `StripeError` and logs the underlying SDK error on every failure. */
export const makeStripeCall = (stripe: StripeSDK) => <T>(fn: (s: StripeSDK) => Promise<T>) =>
	Effect.tryPromise({ try: () => fn(stripe), catch: (e) => new StripeError({ err: e as StripeSDKError }) }).pipe(
		Effect.tapError((e) => Effect.logError('Stripe SDK error', { code: e.code, statusCode: e.statusCode, err: e.err })),
	);

/** Webhook signature verifier bound to a Stripe instance + secret. Returns
 *  `(body, signature) => Effect<Stripe.Event, StripeError>`. */
export const makeStripeVerifyWebhook = (stripe: StripeSDK, secret: string) => (body: string, signature: string) =>
	Effect.tryPromise({
		try: () => stripe.webhooks.constructEventAsync(body, signature, secret),
		catch: (e) => new StripeError({ err: e as StripeSDKError }),
	});

/** One-shot constructor: builds the SDK instance + bound `stripeCall`, plus an
 *  optional `stripeVerifyWebhook` if `webhookSecret` is given. Apps export
 *  whatever they need via destructure:
 *
 *  ```ts
 *  export const { stripe, stripeCall } = makeStripe({ secretKey, apiVersion });
 *  export const { stripe, stripeCall, stripeVerifyWebhook } = makeStripe({ secretKey, apiVersion, webhookSecret });
 *  ```
 */
export function makeStripe(config: { secretKey: string; apiVersion?: string; webhookSecret: string }): {
	stripe: StripeSDK;
	stripeCall: ReturnType<typeof makeStripeCall>;
	stripeVerifyWebhook: ReturnType<typeof makeStripeVerifyWebhook>;
};
export function makeStripe(config: { secretKey: string; apiVersion?: string }): {
	stripe: StripeSDK;
	stripeCall: ReturnType<typeof makeStripeCall>;
};
export function makeStripe(config: { secretKey: string; apiVersion?: string; webhookSecret?: string }) {
	// apiVersion typing is a literal union per Stripe SDK release; runtime accepts any string the API understands.
	const stripe = new StripeSDK(config.secretKey, config.apiVersion ? { apiVersion: config.apiVersion as typeof StripeSDK.API_VERSION } : undefined);
	return {
		stripe,
		stripeCall: makeStripeCall(stripe),
		...(config.webhookSecret ? { stripeVerifyWebhook: makeStripeVerifyWebhook(stripe, config.webhookSecret) } : {}),
	};
}

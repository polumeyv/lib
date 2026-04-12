/**
 * @module @polumeyv/utils/server/stripe
 *
 * Effect-based Stripe client.
 *
 * Exports:
 *  - `Stripe`       — Context tag (API calls + webhook verification)
 *  - `StripeError`  — Tagged error (exposes `.statusCode` and `.code` from Stripe's error)
 *  - `makeStripe`   — Factory: `(secretKey, webhookSecret?) => Stripe`
 */
import StripeSDK from 'stripe';
import { Context, Data, Effect } from 'effect';
import type { HttpStatusError } from './error';

export class StripeError extends Data.TaggedError('StripeError')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	private get err() {
		return this.cause as StripeSDK.errors.StripeError;
	}
	get statusCode() {
		return this.err?.statusCode ?? 500;
	}
	get code() {
		return this.err?.code;
	}
}

export class Stripe extends Context.Tag('Stripe')<Stripe, {
	use: <T>(fn: (stripe: StripeSDK) => Promise<T>) => Effect.Effect<T, StripeError, never>;
	verify: (body: string, signature: string) => Effect.Effect<StripeSDK.Event, StripeError, never>;
}>() {}

export const makeStripe = (secretKey: string, webhookSecret?: string) => {
	const stripe = new StripeSDK(secretKey, { apiVersion: '2026-03-25.dahlia' });
	return Stripe.of({
		use: (fn) => Effect.tryPromise({ try: () => fn(stripe), catch: (e) => new StripeError({ cause: e }) }),
		verify: (body, signature) =>
			webhookSecret
				? Effect.tryPromise({
						try: () => stripe.webhooks.constructEventAsync(body, signature, webhookSecret),
						catch: (e) => new StripeError({ cause: e }),
					})
				: Effect.fail(new StripeError({ message: 'No webhook secret configured' })),
	});
};

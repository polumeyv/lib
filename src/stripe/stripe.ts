/**
 * @module @polumeyv/clients/stripe — Core API client
 *
 * Exports:
 *  - `Stripe`       — Context tag (API calls only)
 *  - `StripeError`  — Tagged error (exposes `.statusCode` and `.code` from Stripe's error)
 *  - `makeStripe`   — Factory: `(secretKey) => Stripe`
 */
import StripeSDK from 'stripe';
import { Context, Data, Effect } from 'effect';

export class StripeError extends Data.TaggedError('StripeError')<{ cause?: unknown; message?: string }> {
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
}>() {}

export const makeStripe = (secretKey: string) => {
	const stripe = new StripeSDK(secretKey);
	return Stripe.of({
		use: (fn) => Effect.tryPromise({ try: () => fn(stripe), catch: (e) => new StripeError({ cause: e }) }),
	});
};

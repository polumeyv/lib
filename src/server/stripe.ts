/**
 * @module @polumeyv/utils/server/stripe
 *
 * Effect-bridged Stripe SDK service. Apps provide a `StripeConfig` layer; the
 * service builds the SDK instance, exposes it as `stripe`, wraps Promise calls
 * via `call()`, and (when `webhookSecret` is configured) verifies inbound webhook
 * signatures via `verifyWebhook()`.
 *
 * ```ts
 * // app db.ts:
 * Layer.provideMerge(
 *     Layer.mergeAll(StripeService.Default, BaseUserRepository.Default, …),
 *     Layer.succeed(StripeConfig, { secretKey: STRIPE_SECRET_KEY, apiVersion: '2026-04-22.dahlia', webhookSecret: STRIPE_WEBHOOK_SECRET }),
 * );
 *
 * // any service:
 * const stripe = yield* StripeService;
 * const c = yield* stripe.call((s) => s.customers.create({ … }));
 * const event = yield* stripe.verifyWebhook(body, signature);
 * ```
 */
import StripeSDK from 'stripe';
import { Context, Data, Effect } from 'effect';
import type { HttpStatusError } from '@polumeyv/lib/error';

type StripeSDKError = InstanceType<typeof StripeSDK.errors.StripeError>;

/** Tagged Effect error wrapping an SDK rejection. `statusCode` defaults to 500 when Stripe didn't return one. */
export class StripeError extends Data.TaggedError('StripeError')<{ err: StripeSDKError }> implements HttpStatusError {
	get statusCode() {
		return this.err.statusCode ?? 500;
	}
	get code() {
		return this.err.code;
	}
}

/** App-provided Stripe credentials. `webhookSecret` is required only by apps that handle inbound Stripe webhooks. */
export class StripeConfig extends Context.Tag('StripeConfig')<
	StripeConfig,
	{
		readonly secretKey: string;
		readonly apiVersion?: string;
		readonly webhookSecret?: string;
	}
>() {}

/**
 * Effect-bridged Stripe SDK service. Apps provide `StripeConfig` and add
 * `StripeService.Default` to their layer; consumers `yield* StripeService` to
 * get `{ stripe, call, verifyWebhook }`.
 */
export class StripeService extends Effect.Service<StripeService>()('StripeService', {
	effect: Effect.gen(function* () {
		const config = yield* StripeConfig;
		// apiVersion typing is a literal union per Stripe SDK release; runtime accepts any string the API understands.
		const stripe = new StripeSDK(config.secretKey, config.apiVersion ? { apiVersion: config.apiVersion as typeof StripeSDK.API_VERSION } : undefined);

		const call = <T>(fn: (s: StripeSDK) => Promise<T>) =>
			Effect.tryPromise({ try: () => fn(stripe), catch: (e) => new StripeError({ err: e as StripeSDKError }) }).pipe(
				Effect.tapError((e) => Effect.logError('Stripe SDK error', { code: e.code, statusCode: e.statusCode, err: e.err })),
			);

		const verifyWebhook = (body: string, signature: string) =>
			Effect.tryPromise({
				try: () => {
					if (!config.webhookSecret) throw new Error('verifyWebhook called but StripeConfig has no webhookSecret');
					return stripe.webhooks.constructEventAsync(body, signature, config.webhookSecret);
				},
				catch: (e) => new StripeError({ err: e as StripeSDKError }),
			});

		return { stripe, call, verifyWebhook };
	}),
}) {}

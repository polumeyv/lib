import StripeSDK from 'stripe';
import { Cause, Context, Data, Effect, Layer } from 'effect';
import type { HttpStatusError } from '@polumeyv/lib/error';

/** The one Stripe API version pin for every app. `StripeService` defaults to it; bump it here and the whole
 *  platform moves together. `StripeConfig.apiVersion` remains a per-app override for staged migrations. */
export const STRIPE_API_VERSION = '2026-04-22.dahlia';

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
export class StripeConfig extends Context.Service<
	StripeConfig,
	{
		readonly secretKey: string;
		readonly apiVersion?: string;
		readonly webhookSecret?: string;
	}
>()('StripeConfig') {}

/**
 * Effect-bridged Stripe SDK service. Apps provide `StripeConfig` and add
 * `StripeService.layer` to their layer; consumers `yield* StripeService` to
 * get `{ stripe, call, verifyWebhook }`.
 */
export class StripeService extends Context.Service<StripeService>()('StripeService', {
	make: Effect.gen(function* () {
		const config = yield* StripeConfig;
		// apiVersion typing is a literal union per Stripe SDK release; runtime accepts any string the API understands.
		const stripe = new StripeSDK(config.secretKey, { apiVersion: (config.apiVersion ?? STRIPE_API_VERSION) as typeof StripeSDK.API_VERSION });

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
}) {
	static readonly layer = Layer.effect(this, this.make);
}

// ── Connect (v2 accounts) helpers shared by the products that onboard connected accounts ────────────────────────────

/** The shape of `StripeService.call` — the class type is the Context tag, not the service, so helpers that take the
 *  destructured `call` type against this alias. */
export type StripeCall = <T>(fn: (s: StripeSDK) => Promise<T>) => Effect.Effect<T, StripeError>;

/** Is a v2 Connect account done onboarding? No requirement entry may still be waiting on the user. The single
 *  definition every payout/charge gate reads (cresends affiliates, pro merchants, the `account.updated` webhook). */
export const isOnboardingComplete = (account: Pick<StripeSDK.V2.Core.Account, 'requirements'>) =>
	!(account.requirements?.entries ?? []).some((e) => e.awaiting_action_from === 'user');

/** Mint a v2 account-onboarding link. Call sites choose the configurations and bounce-back URLs; the
 *  `use_case.account_onboarding` scaffolding lives here so the products can't drift. */
export const createConnectOnboardingLink = (
	call: StripeCall,
	opts: { account: string; configurations: Array<'merchant' | 'recipient'>; refreshUrl: string; returnUrl: string },
) =>
	call((s) =>
		s.v2.core.accountLinks.create({
			account: opts.account,
			use_case: {
				type: 'account_onboarding',
				account_onboarding: { configurations: opts.configurations, refresh_url: opts.refreshUrl, return_url: opts.returnUrl },
			},
		}),
	);

/**
 * Shared Stripe webhook entry: require + verify the `stripe-signature` header, log the event, dispatch. Dispatch
 * failures are logged and PROPAGATE — the route returns non-2xx and Stripe redelivers, so handlers must stay
 * idempotent (they are: idempotency-keyed transfers, `ON CONFLICT` inserts, plain UPDATEs).
 */
export const handleStripeWebhook = <Ret extends Effect.Effect<any, any, any>>(request: Request, dispatch: (event: StripeSDK.Event) => Ret) =>
	Effect.flatMap(StripeService, (stripe) =>
		Effect.promise(() => request.text()).pipe(
			Effect.flatMap((body) => {
				const signature = request.headers.get('stripe-signature');
				return signature
					? stripe.verifyWebhook(body, signature).pipe(Effect.mapError(() => new Cause.IllegalArgumentError('Webhook signature verification failed')))
					: Effect.fail(new Cause.IllegalArgumentError('Missing stripe-signature header'));
			}),
			Effect.tap((event) => Effect.logInfo('[stripe:webhook]', event.type, event.id)),
			Effect.flatMap((event) => {
				// Collapse the per-branch Effect union a switch-based dispatch infers — assignment unions E/R where
				// generic inference would pin them to the first branch.
				const handled = dispatch(event) as Effect.Effect<Effect.Success<Ret>, Effect.Error<Ret>, Effect.Services<Ret>>;
				return Effect.tapCause(handled, (cause) => Effect.logError('[stripe:webhook] ' + event.type, cause));
			}),
		),
	);

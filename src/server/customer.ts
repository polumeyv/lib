/**
 * Stripe customer service — shared by polumeyv-auth and cresends-dashboard.
 *
 * Each app extends this in its own Effect.Service to layer on app-specific
 * methods (cookie writes, billing portal returns).
 *
 * Assumes a `users` table with `sub` (UUID), `stripe_cus_id` (nullable string),
 * and `email` columns. Caches `{ id, pm }` JSON under Redis key `cus:{sub}` with
 * a sentinel value `0` recording a temporary Stripe outage to avoid retry storms.
 */

import { Cause, Effect, Schema, Either } from 'effect';
import { type Stripe } from 'stripe';
import { PaymentMethod } from '../public/types';
import { Postgres } from './postgres';
import { Redis } from './redis';
import { UserSub } from '../auth';
import { invalid } from '@polumeyv/lib/error';
import { StripeService } from './stripe';

export const CachedCustomer = Schema.parseJson(Schema.Struct({ id: Schema.String, pm: PaymentMethod }));

export type StripeCustomerUser = { sub: typeof UserSub.Type; email: string };

const CACHE_TTL = 84_000;

const extractCustomer = (c: Stripe.Customer | Stripe.DeletedCustomer) => ({
	id: c.id,
	pm: c.deleted
		? null
		: ((pm) => (pm && typeof pm !== 'string' && pm.card ? { brand: pm.card.brand, last4: pm.card.last4 } : null))(c.invoice_settings?.default_payment_method),
});

export class StripeCustomerService extends Effect.Service<StripeCustomerService>()('StripeCustomerService', {
	effect: Effect.gen(function* () {
		const pg = yield* Postgres;
		const redis = yield* Redis;
		const { call: stripeCall } = yield* StripeService;

		const cacheRaw = (sub: typeof UserSub.Type, value: string | null) => redis.use((c) => c.setex(`cus:${sub}`, CACHE_TTL, value ?? '0'));

		const cacheCustomer = (sub: typeof UserSub.Type, data: typeof CachedCustomer.Type) =>
			Effect.andThen(Schema.encode(CachedCustomer)(data), (json) => redis.use((c) => c.setex(`cus:${sub}`, CACHE_TTL, json)));

		const validateCoupon = (code: string) =>
			Effect.flatMap(
				stripeCall((s) => s.promotionCodes.list({ code, active: true, limit: 1, expand: ['data.promotion.coupon'] })),
				(promos) => {
					const pc = promos.data[0];
					const coupon = pc?.promotion.coupon;
					if (!pc || !coupon || typeof coupon === 'string') return invalid('Invalid promo code');
					return Effect.succeed({ id: pc.id, name: coupon.name ?? code, percentOff: coupon.percent_off, amountOff: coupon.amount_off });
				},
			);

		const createCustomer = <U extends StripeCustomerUser>(user: U) =>
			Effect.andThen(
				stripeCall((stripe) => stripe.customers.create({ email: user.email, metadata: { sub: user.sub } })),
				(c) =>
					((data = extractCustomer(c)) =>
						Effect.as(Effect.all([pg.use((sql) => sql`UPDATE users SET stripe_cus_id = ${c.id} WHERE sub = ${user.sub}`), cacheCustomer(user.sub, data)]), data))(),
			).pipe(
				Effect.catchTag('StripeError', (e) =>
					Effect.zipRight(
						Effect.all([Effect.logWarning('[CustomerService] customer creation failed', e), cacheRaw(user.sub, null)]),
						Effect.fail(new Cause.NoSuchElementException('Our payment provider was temporarily unavailable — please try again shortly.')),
					),
				),
			);

		const getCustomerFromDb = (sub: typeof UserSub.Type) =>
			Effect.map(
				pg.first((sql) => sql`SELECT stripe_cus_id, email FROM users WHERE sub = ${sub}`),
				(row): Either.Either<string, string> => (row.stripe_cus_id ? Either.right(row.stripe_cus_id) : Either.left(row.email)),
			);

		const getCustomer = <U extends StripeCustomerUser>(user: U) =>
			Effect.andThen(
				redis.use((c) => c.get(`cus:${user.sub}`)),
				(raw) =>
					raw
						? raw === '0'
							? createCustomer(user)
							: Schema.decode(CachedCustomer)(raw)
						: Effect.andThen(
								getCustomerFromDb(user.sub),
								Either.match({
									onRight: (id) =>
										Effect.andThen(
											stripeCall((s) => s.customers.retrieve(id, { expand: ['invoice_settings.default_payment_method'] })),
											(c) => ((data = extractCustomer(c)) => Effect.as(cacheCustomer(user.sub, data), data))(),
										),
									onLeft: () => createCustomer(user),
								}),
							),
			);

		const getInvoices = <U extends StripeCustomerUser>(user: U) =>
			Effect.andThen(getCustomer(user), ({ id }) =>
				Effect.map(
					stripeCall((stripe) => stripe.invoices.list({ customer: id, limit: 24 })),
					(result) =>
						result.data.map((inv) => ({
							id: inv.id,
							date: inv.created,
							amount: inv.amount_paid,
							status: inv.status ?? 'unknown',
							url: inv.hosted_invoice_url ?? null,
						})),
				),
			);

		const createSetupIntent = <U extends StripeCustomerUser>(user: U) =>
			Effect.andThen(getCustomer(user), ({ id }) =>
				Effect.all(
					{
						clientSecret: Effect.flatMap(
							stripeCall((s) => s.setupIntents.create({ customer: id, automatic_payment_methods: { enabled: true } })),
							(si) => Effect.fromNullable(si.client_secret),
						),
						customerSessionClientSecret: Effect.map(
							stripeCall((s) => s.customerSessions.create({ customer: id, components: { payment_element: { enabled: true } } })),
							(cs) => cs.client_secret,
						),
					},
					{ concurrency: 'unbounded' },
				),
			);

		const setPaymentMethod = <U extends StripeCustomerUser>(user: U, default_payment_method: string) =>
			Effect.andThen(getCustomer(user), (cus) =>
				Effect.andThen(
					stripeCall((stripe) =>
						stripe.customers.update(cus.id, {
							invoice_settings: { default_payment_method },
							expand: ['invoice_settings.default_payment_method'],
						}),
					),
					(c) => ((data = extractCustomer(c)) => Effect.as(cacheCustomer(user.sub, data), data.pm))(),
				),
			);

		const getPaymentMethod = <U extends StripeCustomerUser>(user: U) => Effect.map(getCustomer(user), ({ pm }) => pm);

		return {
			cacheRaw,
			cacheCustomer,
			validateCoupon,
			createCustomer,
			getCustomerFromDb,
			getCustomer,
			getInvoices,
			createSetupIntent,
			setPaymentMethod,
			getPaymentMethod,
		};
	}),
	dependencies: [StripeService.Default],
}) {}

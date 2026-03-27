# @polumeyv/clients

Effect-based infrastructure clients for Bun applications. Each client exports a Context tag and a factory function — the consuming app reads its own config and constructs layers.

## Clients

- `@polumeyv/clients/postgres` — Bun-native SQL connection pool (scoped)
- `@polumeyv/clients/redis` — Bun-native Redis connection (scoped)
- `@polumeyv/clients/stripe` — Stripe API + webhook verification
- `@polumeyv/clients/ses` — AWS SES v2 email (with dev mode logging)

## Usage

```ts
import { Config, Effect, Layer } from 'effect';
import { Postgres, makePostgres } from '@polumeyv/clients/postgres';
import { Redis, makeRedis } from '@polumeyv/clients/redis';
import { Stripe, makeStripe, StripeWebhook, makeStripeWebhook } from '@polumeyv/clients/stripe';
import { Ses, makeSes } from '@polumeyv/clients/ses';

// Scoped clients — Layer.scoped + Effect.flatMap
const PostgresLive = Layer.scoped(Postgres, Effect.flatMap(Config.string('DATABASE_URL'), makePostgres));
const RedisLive = Layer.scoped(Redis, Effect.flatMap(Config.string('REDIS_URL'), makeRedis));

// Synchronous clients — Layer.effect + Effect.map
const StripeLive = Layer.effect(Stripe, Effect.map(Config.string('STRIPE_SECRET_KEY'), makeStripe));
const StripeWebhookLive = Layer.effect(StripeWebhook, Effect.map(
  Effect.all([Config.string('STRIPE_SECRET_KEY'), Config.string('STRIPE_WEBHOOK_SECRET')]),
  ([sk, ws]) => makeStripeWebhook(sk, ws),
));

const SesLive = Layer.effect(Ses, Effect.flatMap(
  Config.string('EMAIL_ENABLED').pipe(Config.map((v) => v === 'true')),
  makeSes,
));

// Compose into your app runtime
const InfraLive = Layer.mergeAll(PostgresLive, RedisLive, StripeLive, StripeWebhookLive, SesLive);
```

Then use them in your services:

```ts
const pg = yield* Postgres;
const rows = yield* pg.use((sql) => sql`SELECT * FROM users WHERE id = ${id}`);

const redis = yield* Redis;
const value = yield* redis.use((c) => c.get('key'));
```

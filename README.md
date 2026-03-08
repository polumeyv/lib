# @polumeyv/clients

Effect-based infrastructure clients for Bun applications. Each client exports a **Context tag**, a **tagged error**, and a **factory function** — the consuming app reads its own config and constructs layers.

## Clients

| Import | Tag | Error | Factory | Lifecycle |
|--------|-----|-------|---------|-----------|
| `@polumeyv/clients/postgres` | `Postgres` | `PostgresError` | `makePostgres(url)` | Scoped (connection pool) |
| `@polumeyv/clients/redis` | `Redis` | `RedisError` | `makeRedis(url?, options?)` | Scoped (connection) |
| `@polumeyv/clients/stripe` | `Stripe` | `StripeError` | `makeStripe(secretKey)` | None |
| `@polumeyv/clients/stripe` | `StripeWebhook` | `StripeError` | `makeStripeWebhook(secretKey, webhookSecret)` | None |
| `@polumeyv/clients/mailcow` | `Mailcow` | `MailcowError` | `makeMailcow(host, apiKey, serverIp, mailHost)` | None |
| `@polumeyv/clients/ses` | `Ses` | `SesError` | `makeSes(enabled)` | None |
| `@polumeyv/clients/jose` | `Jose` | `JoseError` | `makeJose(privateKeyPem, publicKeyPem)` | None (async key import) |
| `@polumeyv/clients/webauthn` | `WebAuthn` | `WebAuthnError` | `makeWebAuthn(rpID, rpName, expectedOrigin)` | None |

## Pattern

Every client follows the same structure:

```
Tag         — Context.Tag identifying the service in the Effect dependency graph
Error       — Data.TaggedError for typed error handling via Match.tags
make{Name}  — Takes raw config values, creates the underlying SDK client internally,
              returns the Tag implementation (or an Effect of it for scoped clients)
```

**No `*Live` layers are exported.** The app is responsible for reading config and constructing layers — this keeps env var names decoupled from the client library.

## Usage

```ts
import { Config, Effect, Layer } from 'effect';
import { Postgres, makePostgres } from '@polumeyv/clients/postgres';
import { Redis, makeRedis } from '@polumeyv/clients/redis';
import { Stripe, makeStripe, StripeWebhook, makeStripeWebhook } from '@polumeyv/clients/stripe';
import { Mailcow, makeMailcow } from '@polumeyv/clients/mailcow';
import { Ses, makeSes } from '@polumeyv/clients/ses';

// Scoped clients use Layer.scoped + Effect.flatMap
const PostgresLive = Layer.scoped(Postgres, Effect.flatMap(Config.string('DATABASE_URL'), makePostgres));
const RedisLive = Layer.scoped(Redis, Effect.flatMap(Config.string('REDIS_URL'), makeRedis));

// Synchronous clients use Layer.effect + Effect.map
const StripeLive = Layer.effect(Stripe, Effect.map(Config.string('STRIPE_SECRET_KEY'), makeStripe));
const StripeWebhookLive = Layer.effect(StripeWebhook, Effect.map(
  Effect.all([Config.string('STRIPE_SECRET_KEY'), Config.string('STRIPE_WEBHOOK_SECRET')]),
  ([sk, ws]) => makeStripeWebhook(sk, ws),
));

const MailcowLive = Layer.effect(Mailcow, Effect.map(
  Effect.all([Config.string('MAILCOW_HOST'), Config.string('MAILCOW_API_KEY'), Config.string('MAILCOW_SERVER_IP'), Config.string('MAILCOW_MAIL_HOST')]),
  ([host, apiKey, serverIp, mailHost]) => makeMailcow(host, apiKey, serverIp, mailHost),
));

// makeSes returns an Effect (wraps SESv2Client creation), so use Effect.flatMap
const SesLive = Layer.effect(Ses, Effect.flatMap(
  Config.string('EMAIL_ENABLED').pipe(Config.map((v) => v === 'true')),
  makeSes,
));

// Compose into your app runtime
const InfraLive = Layer.mergeAll(PostgresLive, RedisLive, StripeLive, StripeWebhookLive, MailcowLive, SesLive);
```

## Requirements

- **Runtime**: [Bun](https://bun.sh) (Postgres and Redis clients use Bun-native APIs)
- **Peer dependency**: `effect ^3.19.0`

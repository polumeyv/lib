# @polumeyv/lib

Effect-based infrastructure + auth library for Bun applications. Each module exports a `Context.Tag` (or `Effect.Service`) and a factory — the consuming app reads its own config and composes layers.

## Modules

### Server (`@polumeyv/lib/server`)
- `postgres` — Bun-native SQL connection pool (scoped)
- `redis` — Bun-native Redis connection (scoped)
- `stripe` — Stripe API + webhook verification
- `ses` — AWS SES v2 email (with dev-mode logging)
- `sms` — Telnyx SMS (with dev-mode logging)
- `s3` — Bun-native S3 client
- `session` — `push`/`peek`/`pop`/`delete` over Redis
- `crypto` — `encryptSecret`/`decryptSecret` (AES-256-GCM, `enc:v1:` prefix)

### Auth (`@polumeyv/lib/auth`)
- `Jwt` + `JwtConfig` — Ed25519 JWT signing/verification, refresh-token rotation
- `OtpService` + `OtpAlerts` — email-OTP flow with rate-limit + progressive lockout (decisions in `otp.policy`, glue in `otp.service`)
- `PasskeyService` + `PasskeyConfig` — WebAuthn registration/authentication
- `OAuthAccountStore` — sole writer to `oidc_accounts`; row schema seals at-rest token encryption via `EncryptedString` codec
- `OAuthProviderRegistry` + `OAuthProviderResolver` — registered OAuth providers + cached `openid-client` `Configuration`
- `OidcAuthFlow` — authorize-URL build + callback exchange + signup/linking sessions; composes provider resolver + account store
- `OAuthTokenVault` — `getValidAccessToken(sub, provider)`; refreshes via `refreshTokenGrant` + persists; consumed by downstream apps that call third-party APIs (e.g. Google Calendar)
- `RiscService` — Google Cross-Account Protection event receiver (`process` decodes, `dispatchToStore` applies events to `OAuthAccountStore`)
- `BaseUserRepository` — `users` table read/write
- `AuthConfig` + `makeAuthConfig` — TTLs, lockout schedule, crypto key

### Auth — public (`@polumeyv/lib/auth`, `@polumeyv/lib/auth/idp-client`)
- Branded types (`UserSub`, `Email`)
- Schemas (`AuthPayload`, `OAuthClaims`, `OAuthResult`, `BaseUser`)
- Tagged result classes (`OtpSession`, `InvalidCode`, `UserLocked`, `HasOidc`, `AuthenticatedUser`)
- `IdpClient` (+ `IdpClient.layer`) — downstream-app client for the IdP: authorize-URL, code exchange, token refresh/revoke, and JWKS-backed access-token verification

### Public types (`@polumeyv/lib/public/types`, `@polumeyv/lib/public/types/db`, `@polumeyv/lib/public/s3`)
Branded primitives + DB row types safe for both server and client bundles.

## Composition

Each consumer app builds its own runtime by combining layers:

```ts
import { Effect, Layer, ManagedRuntime } from 'effect';
import { Postgres, makePostgres, Redis, makeRedis, SessionService, Stripe, makeStripe } from '@polumeyv/lib/server';
import {
  AuthConfig, makeAuthConfig,
  OAuthProviderRegistry, OAuthAccountStore, OidcAuthFlow, OAuthTokenVault,
} from '@polumeyv/lib/auth';

const Live = Layer.provideMerge(
  Layer.mergeAll(
    OAuthAccountStore.Default,
    OidcAuthFlow.Default,
    OAuthTokenVault.Default,
    // ...your app services
  ),
  Layer.mergeAll(
    Layer.scoped(Postgres, makePostgres(DATABASE_URL)),
    Layer.scoped(Redis, makeRedis(REDIS_URL)),
    SessionService.Default,
    Layer.succeed(OAuthProviderRegistry, OAuthProviderRegistry.of(new Map([
      ['google', { discoveryUrl: '...', clientId: '...', clientSecret: '...', redirectUri: '...' }],
    ]))),
    makeAuthConfig({ cryptoKey: CRYPTO_KEY }),
  ),
);

export const Runtime = ManagedRuntime.make(Live);
```

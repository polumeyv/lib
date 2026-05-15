# Changelog

## v0.9.0

### Added

- **`HttpError`** tagged class — `{ status, message }`. Generic fallback when there's no domain-specific name.
- **`Redirect`** tagged class — accepts `string` (location) OR `{ status, location }`, with defaults `status: 303` and `location: '/'`. Constructor handles defaulting so callers never need to spell them out.
- **`redirect(location?, status?)`** helper — sugar for `Effect.fail(new Redirect(...))`. Callers do `yield* redirect('/foo')` instead of constructing the class.

### Changed

- App `db.ts run()` handlers now translate `ValidationError → invalid()`, `Redirect → redirect()`, and any `HttpStatusError`-shaped error via the existing `error(status, message)` fallback. Route code no longer imports `@sveltejs/kit`'s `error`/`redirect`/`invalid` — domain-named tagged errors fail through to db.ts.

## v0.8.1

### Changed

- **`PostgresError` is no longer exported.** Now that v0.8.0 made it self-describing (statusCode + message from SQLSTATE), callers never need to import the class — they just let it propagate. Made internal to `postgres.ts`. Consumers see the error type via TS inference on `pg.use`/`pg.first` return signatures.
- Callers (`Affiliate.service.ts` in auth + cresends-dashboard; `data.remote.ts` in cresends-dashboard) updated to drop explicit `Effect.Effect<…, PostgresError, …>` annotations — the row shape now lives on the inline `sql<T>` template, error and context channels are inferred.

## v0.8.0

### Changed

- **`PostgresError` now maps Postgres SQLSTATE codes to HTTP status codes + user-facing messages automatically.** Previously every PostgresError surfaced as 500 with the generic "Synchronous Error in Postgres.use" message; callers had to write per-route translation logic (`catchIf` predicates, custom tagged errors) to surface 409/400/etc. for constraint violations. Now:
  - 23502 (not_null) / 23514 (check) / 22xxx (data exception) → **400**
  - 23P01 (exclusion) / 23505 (unique) / 23503 (fkey) / 40xxx (serialization, deadlock) → **409**
  - 42501 (insufficient_privilege) → **403**
  - 57014 (query_canceled) → **408**
  - 08xxx (connection) / 53xxx (insufficient_resources) / 57xxx (operator_intervention) → **503**
  - Specific codes override class-level defaults; unknown codes still surface as 500.
  - The `message` is derived from the SQLSTATE so users see "A record with that value already exists" instead of "Synchronous Error in Postgres.use".
  - Exposed `code` getter on the error class for callers that need the raw SQLSTATE.
- **Removed `SlotConflictError`.** It was a hand-rolled wrapper to convert 23P01 PostgresError → 409 with a friendlier message. The new PostgresError surfaces 409 automatically.

## v0.7.4

### Changed

- **Breaking:** `ProBookings.amount` is now `Schema.Number` (was `Schema.NullOr(Schema.Number)`). DB migration sets `bookings.amount NOT NULL DEFAULT 0` so app code can stop `?? 0`-defaulting. Existing NULL rows are backfilled to `0`.

## v0.7.3

### Changed

- **Breaking (lib-internal):** `makeStripeCustomer().validateCoupon` no longer imports `@sveltejs/kit` to throw `invalid()` — the lib must be framework-agnostic to bundle into apps that don't use the validation surface (e.g. polumeyv-pro). It now `Effect.fail`s with a new tagged `InvalidPromoCode` error. App-side wrappers (auth + cresends-dashboard) catch the tag and translate to `invalid('Invalid promo code')` at the route boundary.

## v0.7.2

### Added

- `ProBusinesses.payouts_enabled` — cached from Stripe `account.updated` webhook so `getConnectStatus` doesn't have to retrieve the account from Stripe on every page load.

## v0.7.1

### Added

- `ProBusinesses`: `platform_fee_bps`, `charges_enabled`, `onboarding_complete` fields — cached Connect onboarding state + per-business application_fee_amount basis points.
- `ProBookings`: `payment_intent_id`, `payment_status`, `platform_fee_amount`, `transfer_id` — Stripe destination-charge bookkeeping per booking.

## v0.7.0

### Added

- `makeStripeCustomer(stripeCall)` — shared Stripe customer service core for apps using a `users` table with `stripe_cus_id`. Returns `getCustomer`, `getPaymentMethod`, `setPaymentMethod`, `getInvoices`, `createSetupIntent`, `validateCoupon`, `createCustomer`, plus the cache helpers and the `CachedCustomer` schema. Replaces the duplicated ~150-line `Customer.service.ts` files in `polumeyv-auth` and `cresends-dashboard`; each app now wraps the factory and layers on app-specific extras (cookie writes, billing portal returns).

## v0.5.0

### Changed

- **Internal:** `OtpPolicy` module collapsed into `OtpService`. The pure decision functions (`decideInit`, `decideLink`, `decideHandle`) had no callers outside `OtpService` and pre-conditions the service had to enforce — the seam was hypothetical. `sendDecision`, `parseHash`, `computeCooldown`, `isLocked` remain at module scope (multi-use). No public API change.
- **Tests:** Added `otp.service.test.ts` covering `initAndSend`, `initLinkAndSend`, and `handleOtp` flows against fake Redis / `BaseUserRepository` adapters.

## v0.3.0

### Breaking

- **Removed** `OidcService`. Replaced by three smaller modules:
  - `OAuthAccountStore` — sole writer to `oidc_accounts`; row schema seals at-rest token encryption via the new `EncryptedString` codec; callers pass and receive plaintext tokens.
  - `OAuthProviderResolver` — provider config + cached `openid-client` `Configuration`. `OAuthProviderRegistry` (renamed from `OidcProviderRegistry`) is the underlying `Context.Tag`.
  - `OidcAuthFlow` — `buildAuthUrl`, `exchangeCode`, `createSignupSession`, `createLinkingSession`, `linkAccount`. Composes the resolver + the store.
- **Renamed** `OidcProviderRegistry` → `OAuthProviderRegistry`.
- **Removed** dead helpers: `maybeEncrypt`, `maybeDecrypt`, the legacy-plaintext fallback in `decryptSecret` (now throws on missing `enc:v1:` prefix).

### Added

- `OAuthTokenVault.getValidAccessToken(sub, provider)` — refresh-on-stale token vault for downstream apps that call third-party APIs (e.g. Google Calendar). Replaces hand-rolled per-app refresh logic.
- `RiscService.dispatchToStore(events)` — applies decoded Google RISC events to `OAuthAccountStore`. Eliminates per-app webhook switch statements.
- `OAuthAccountStore` methods: `link`, `findBySub`, `findActive`, `findByProviderSubject`, `findByEmail`, `listForUser`, `replaceAccessToken`, `clearTokens`, `unlinkAll`, `unlinkByProviderSubject`, `setStatus`, `resolveLogin`.
- `EncryptedString` Schema codec — single seam for at-rest encryption of OAuth tokens.

### Changed

- `OtpService` checks for `OidcAuthFlow` (not `OidcService`) when deciding `HasOidc`.

## v0.1.6

[compare changes](https://github.com/polumeyv/utils-lib/compare/v0.1.4...v0.1.6)

### 🏡 Chore

- Upgrade stripe, remove unused deps, simplify tsconfig ([eef6bde](https://github.com/polumeyv/utils-lib/commit/eef6bde))

### ❤️ Contributors

- Polumeyv ([@Nic-Polumeyv](https://github.com/Nic-Polumeyv))

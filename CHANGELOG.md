# Changelog

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

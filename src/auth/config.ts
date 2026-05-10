import { Context, Layer } from 'effect';

// ---------------------------------------------------------------------------
// AuthConfig — unified tunable constants
// ---------------------------------------------------------------------------

export interface AuthConfigShape {
	/** Number of digits in a generated OTP code (default: 6). */
	readonly otpCodeLen: number;
	/** Minimum interval in milliseconds between OTP code sends (default: 35 000). */
	readonly otpResendMs: number;
	/** Maximum age in milliseconds before an OTP code expires (default: 300 000 — 5 min). */
	readonly otpCodeTtlMs: number;
	/** TTL in seconds for the OTP verification session in Redis (default: 86 400 — 24 h). */
	readonly otpSessionTtl: number;
	/** Progressive lockout durations in milliseconds, indexed by consecutive failure count. Last entry should be `Infinity` for permanent lock. */
	readonly lockDurationsMs: readonly number[];
	/** TTL in seconds for signup sessions in Redis (default: 3 600 — 1 h). Used by SignupService and OidcService. */
	readonly signupSessionTtl: number;
	/** JWT access token lifetime in seconds (default: 900 — 15 min). */
	readonly accessTtl: number;
	/** JWT refresh token lifetime in seconds (default: 604 800 — 7 days). */
	readonly refreshTtl: number;
	/** OAuth2 access token lifetime in seconds, for tokens issued to consumer apps (default: 900 — 15 min). */
	readonly oauth2AccessTtl: number;
	/** OAuth2 refresh token lifetime in seconds — non-rotating, so covers the full session (default: 7 776 000 — 90 days). */
	readonly oauth2RefreshTtl: number;
	/** Space-separated OAuth scopes requested from the identity provider (default: 'openid email profile'). */
	readonly oauthScopes: string;
	/** TTL in seconds for PKCE OAuth sessions in Redis (default: 300 — 5 min). */
	readonly oauthSessionTtl: number;
	/** TTL in seconds for OIDC account-linking sessions in Redis (default: 600 — 10 min). */
	readonly oidcLinkSessionTtl: number;
	/** TTL in seconds for WebAuthn challenge sessions in Redis (default: 300 — 5 min). */
	readonly webauthnSessionTtl: number;
	/** TTL in seconds for OTP signup tokens in Redis — opaque cookie token bridging code verification → name entry (default: 600 — 10 min). */
	readonly otpSignupTokenTtl: number;
	/** TTL in seconds for OAuth2 authorization codes in Redis (default: 300 — 5 min). */
	readonly oauth2AuthCodeTtl: number;
	/** TTL in seconds for parked Deferred OAuth2 authorize entries in Redis (default: 3 600 — 1 h). */
	readonly deferredAuthorizeTtl: number;
	/** Optional maximum number of OTP sends per email address, to prevent abuse (default: 8). */
	readonly maxEmailSends: number;
	/** Max-age in seconds for the access_token cookie (default: 900 — 15 min). */
	readonly accessCookieMaxAge: number;
	/** Max-age in seconds for the refresh_token cookie (default: 7 776 000 — 90 days). */
	readonly refreshCookieMaxAge: number;
	/** Max-age in seconds for the pkce_ver cookie (default: 600 — 10 min). */
	readonly pkceCookieMaxAge: number;
	/** Symmetric passphrase used to encrypt OAuth tokens at rest in `oidc_accounts`. Required. */
	readonly cryptoKey: string;
}

export class AuthConfig extends Context.Tag('AuthConfig')<AuthConfig, AuthConfigShape>() {}

export const AuthConfigDefaults: AuthConfigShape = {
	otpCodeLen: 6,
	otpResendMs: 35_000,
	otpCodeTtlMs: 300_000,
	otpSessionTtl: 86_400,
	lockDurationsMs: [0, 0, 0, 0, 0, 600_000, 900_000, 1_800_000, 3_600_000, 7_200_000, Infinity],
	signupSessionTtl: 3_600,
	accessTtl: 900,
	refreshTtl: 604_800,
	oauth2AccessTtl: 900,
	oauth2RefreshTtl: 7_776_000,
	oauthScopes: 'openid email profile',
	oauthSessionTtl: 300,
	oidcLinkSessionTtl: 600,
	webauthnSessionTtl: 300,
	otpSignupTokenTtl: 600,
	oauth2AuthCodeTtl: 300,
	deferredAuthorizeTtl: 3_600,
	maxEmailSends: 8,
	accessCookieMaxAge: 900,
	refreshCookieMaxAge: 7_776_000,
	pkceCookieMaxAge: 600,
	cryptoKey: '',
};

export const makeAuthConfig = (overrides?: Partial<AuthConfigShape>) => Layer.succeed(AuthConfig, { ...AuthConfigDefaults, ...overrides });

// ---------------------------------------------------------------------------
// Non-configurable constants
// ---------------------------------------------------------------------------

/** AES-GCM initialization vector length in bytes (96-bit nonce per NIST recommendation). */
export const IV_BYTES = 12;

/** Base64url encoding options — URL-safe alphabet with no padding, used for sealed tokens. */
export const B64URL = { alphabet: 'base64url' as const, omitPadding: true };

/** Redis key for the has_oidc cache — whether an email is associated with an OIDC provider. */
export const HasOidcKey = (email: string) => `has_oidc:${email}`;

// ---------------------------------------------------------------------------
// OAuth protocol constants — single source of truth for all auth servers & apps
// ---------------------------------------------------------------------------

export const OAUTH = {
	signingAlg: 'ES256',
	scopes: ['openid', 'profile', 'email'],
	defaultScope: 'openid profile email',
	responseTypes: ['code'],
	grantTypes: ['authorization_code', 'refresh_token'],
	codeChallengeMethod: 'S256',
	claims: ['sub', 'role', 'email', 'sms', 'name', 'b_id', 'b_role'],
	accessClaims: ['sub', 'role'],
	refreshClaims: ['sub', 'role', 'type'],
	businessClaims: ['sub', 'b_id', 'b_role'],
} as const;

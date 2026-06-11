import { describe, it, expect } from 'bun:test';
import { Cause, Effect, Exit } from 'effect';
import { IdpClient, sessionCookiePolicy, type CookieJar } from './idp-client';

// The cookie policy is the point of the centralization: per-app copies are how the dashboard once shipped with the
// access/refresh maxAges swapped (15-minute refresh cookie → silent OAuth round-trip every navigation). Pin the
// names, paths and TTLs so a drift is a failing test, not a prod incident.
describe('sessionCookiePolicy', () => {
	it('access_token: path /, 15 minutes', () => expect(sessionCookiePolicy.access_token).toEqual({ path: '/', maxAge: 900 }));
	it('refresh_token: path /, 90 days', () => expect(sessionCookiePolicy.refresh_token).toEqual({ path: '/', maxAge: 7_776_000 }));
	it('pkce_ver: scoped to the callback route, 10 minutes', () => expect(sessionCookiePolicy.pkce_ver).toEqual({ path: '/oauth2/callback', maxAge: 600 }));
});

describe('handleCallback', () => {
	it('fails with a clear sign-in-again error when the pkce_ver cookie is absent', async () => {
		const deleted: string[] = [];
		const jar: CookieJar = { get: () => undefined, set: () => {}, delete: (name) => void deleted.push(name) };
		// Discovery is lazy, and the missing-verifier guard fires before any exchange — no IdP needed.
		const exit = await Effect.runPromiseExit(
			Effect.andThen(IdpClient, (idp) => idp.handleCallback(new URL('https://app.example/oauth2/callback?code=x'), () => Effect.void)).pipe(
				Effect.provide(
					IdpClient.layer({
						publicAuthUrl: new URL('http://localhost:9'),
						clientId: 'test_client',
						clientSecret: 'test_secret',
						redirectUri: 'https://app.example/oauth2/callback',
						cookies: () => jar,
					}),
				),
			),
		);
		expect(Exit.isFailure(exit)).toBe(true);
		if (Exit.isFailure(exit)) {
			const squashed = Cause.squash(exit.cause);
			expect(squashed).toBeInstanceOf(Cause.IllegalArgumentError);
			expect((squashed as Error).message).toBe('Missing session verifier. Please sign in again.');
		}
		// The guard must fail before touching any cookie — nothing to consume, nothing to delete.
		expect(deleted).toEqual([]);
	});
});

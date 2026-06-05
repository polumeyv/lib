import { describe, it, expect } from 'bun:test';
import { resolveError, SessionExpiredError, Unauthorized } from './error';

// `resolveError` is the server half of the cross-app error contract: it turns any thrown value into `{ status, code }`
// that the boundary puts on the wire and the client maps to UX. This is the exact mapping the original booking bug got
// wrong (a session expiry must be `SESSION_EXPIRED`, a slot clash `SLOT_TAKEN`), so it's pinned here.

describe('resolveError · explicit-code errors win', () => {
	it('SessionExpiredError → 401 / SESSION_EXPIRED', () => {
		const r = resolveError(new SessionExpiredError());
		expect(r.status).toBe(401);
		expect(r.code).toBe('SESSION_EXPIRED');
	});
	it('Unauthorized → 401 / UNAUTHORIZED', () => {
		const r = resolveError(new Unauthorized());
		expect(r.status).toBe(401);
		expect(r.code).toBe('UNAUTHORIZED');
	});
	it("a declared `code` beats the status fallback", () => expect(resolveError({ statusCode: 500, code: 'PAYMENT_REQUIRED' }).code).toBe('PAYMENT_REQUIRED'));
});

describe('resolveError · framework/Effect tags map through the one table', () => {
	it('SchemaError → 400 / INVALID_REQUEST', () => {
		const r = resolveError({ _tag: 'SchemaError' });
		expect(r.status).toBe(400);
		expect(r.code).toBe('INVALID_REQUEST');
	});
	it('NoSuchElementError → 404 / NOT_FOUND', () => {
		const r = resolveError({ _tag: 'NoSuchElementError' });
		expect(r.status).toBe(404);
		expect(r.code).toBe('NOT_FOUND');
	});
	it('never leaks an internal tag name as the wire code', () => expect(resolveError({ _tag: 'NoSuchElementError' }).code).not.toBe('NoSuchElementError'));
});

describe('resolveError · a raw PostgresError carries a SQLSTATE `code`, not an ErrorCode', () => {
	it('a 23P01 exclusion violation → 409 / SLOT_TAKEN (SQLSTATE rejected, derived from the status)', () => {
		const r = resolveError({ _tag: 'PostgresError', statusCode: 409, code: '23P01' });
		expect(r.status).toBe(409);
		expect(r.code).toBe('SLOT_TAKEN');
	});
});

describe('resolveError · status → code fallback (un-tagged, code-less errors)', () => {
	const cases = [
		[401, 'UNAUTHORIZED'],
		[402, 'PAYMENT_REQUIRED'],
		[404, 'NOT_FOUND'],
		[409, 'SLOT_TAKEN'],
		[400, 'INVALID_REQUEST'],
		[500, 'INTERNAL'],
		[503, 'INTERNAL'],
	] as const;
	for (const [status, code] of cases) it(`${status} → ${code}`, () => expect(resolveError({ statusCode: status }).code).toBe(code));
});

describe('resolveError · unknown defects + precedence', () => {
	it('a plain Error → 500 / INTERNAL / Defect, with a message', () => {
		const r = resolveError(new Error('boom'));
		expect(r.status).toBe(500);
		expect(r.code).toBe('INTERNAL');
		expect(r.tag).toBe('Defect');
		expect(r.message).toBe('boom');
	});
	it('an empty object → 500 / INTERNAL with a fallback message', () => {
		const r = resolveError({});
		expect(r.status).toBe(500);
		expect(r.message).toBeTruthy();
	});
	it('an explicit `statusCode` beats a tag', () => expect(resolveError({ statusCode: 418, _tag: 'SchemaError' }).status).toBe(418));
});

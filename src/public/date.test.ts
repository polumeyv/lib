import { describe, it, expect } from 'bun:test';
import { todayIn, localTimeZone, addDays, addMonths, addYears, dayOfMonth } from './date';
import { formatDateDisplay, formatTimeDisplay, formatTimeRange, formatBookingDateTime } from './formatters';
import { DateString, TimeString } from '../schemas/primitives';

// Calendar math on branded `DateString` values, replacing `@internationalized/date`'s CalendarDate
// arithmetic. The clamping cases are the load-bearing ones: Effect DateTime.add clamps month overflow
// (Jan 31 + 1 month stays in February) exactly like CalendarDate.add did — a naive Date.setMonth would
// roll into March.

const d = DateString.make;
const t = TimeString.make;

describe('addDays', () => {
	it('carries across a month boundary', () => expect(addDays(d('2024-12-31'), 1)).toBe(d('2025-01-01')));
	it('lands on a leap day', () => expect(addDays(d('2024-02-28'), 1)).toBe(d('2024-02-29')));
	it('skips the leap day in a non-leap year', () => expect(addDays(d('2023-02-28'), 1)).toBe(d('2023-03-01')));
	it('subtracts across a year boundary', () => expect(addDays(d('2025-01-01'), -1)).toBe(d('2024-12-31')));
	it('handles week-scale jumps', () => expect(addDays(d('2024-01-15'), 7)).toBe(d('2024-01-22')));
});

describe('addMonths', () => {
	it('clamps Jan 31 into February (leap year)', () => expect(addMonths(d('2024-01-31'), 1)).toBe(d('2024-02-29')));
	it('clamps Jan 31 into February (non-leap year)', () => expect(addMonths(d('2023-01-31'), 1)).toBe(d('2023-02-28')));
	it('clamps backward into February', () => expect(addMonths(d('2024-03-31'), -1)).toBe(d('2024-02-29')));
	it('crosses a year boundary', () => expect(addMonths(d('2024-11-15'), 2)).toBe(d('2025-01-15')));
	it('keeps the day when it fits', () => expect(addMonths(d('2024-01-15'), 1)).toBe(d('2024-02-15')));
});

describe('addYears', () => {
	it('adds whole years', () => expect(addYears(d('1990-06-15'), 30)).toBe(d('2020-06-15')));
	it('clamps Feb 29 in a non-leap target year', () => expect(addYears(d('2024-02-29'), 1)).toBe(d('2025-02-28')));
	it('subtracts a century', () => expect(addYears(d('2026-06-12'), -100)).toBe(d('1926-06-12')));
});

describe('dayOfMonth', () => {
	it('reads the day field', () => expect(dayOfMonth(d('2024-01-31'))).toBe(31));
	it('reads single-digit days', () => expect(dayOfMonth(d('2024-01-05'))).toBe(5));
});

describe('todayIn', () => {
	it('returns a valid DateString for any valid zone', () => {
		expect(todayIn('America/New_York')).toMatch(/^\d{4}-\d{2}-\d{2}$/);
		expect(todayIn('Asia/Tokyo')).toMatch(/^\d{4}-\d{2}-\d{2}$/);
	});
	it("matches the system clock's UTC date", () => {
		const before = new Date().toISOString().slice(0, 10);
		const result = todayIn('UTC');
		const after = new Date().toISOString().slice(0, 10);
		expect([before, after]).toContain(result);
	});
	it('throws on an invalid zone id', () => expect(() => todayIn('Not/AZone')).toThrow());
});

describe('localTimeZone', () => {
	it('returns the runtime IANA zone', () => expect(localTimeZone()).toBe(new Intl.DateTimeFormat().resolvedOptions().timeZone));
});

// Formatter regression pins: these rendered through @internationalized/date's DateFormatter before, which
// delegates to Intl.DateTimeFormat — same engine underneath, so output must be unchanged. Range strings use
// locale separators/spaces that vary by ICU build, so those assert content, not exact bytes.

describe('formatDateDisplay', () => {
	it('renders the default long form', () => expect(formatDateDisplay(d('2024-01-01'))).toBe('Monday, January 1, 2024'));
	it('respects custom options', () =>
		expect(formatDateDisplay(d('2024-01-01'), { month: 'long', day: 'numeric', year: 'numeric' })).toBe('January 1, 2024'));
	it('never shifts the date (UTC-pinned)', () => expect(formatDateDisplay(d('2024-12-31'))).toContain('December 31, 2024'));
});

describe('time/date-time formatters', () => {
	it('formatTimeDisplay renders 12-hour wall-clock', () => {
		expect(formatTimeDisplay(t('09:30'))).toBe('9:30 AM');
		expect(formatTimeDisplay(t('17:00'))).toBe('5:00 PM');
		expect(formatTimeDisplay(t('00:00'))).toBe('12:00 AM');
	});
	it('formatTimeRange contains both endpoints', () => {
		const range = formatTimeRange(t('09:30'), t('10:15'));
		expect(range).toContain('9:30');
		expect(range).toContain('10:15');
	});
	it('formatBookingDateTime renders in the business zone', () => {
		const rendered = formatBookingDateTime(new Date('2024-01-01T14:30:00Z'), 'America/New_York');
		expect(rendered).toContain('Monday, January 1, 2024');
		expect(rendered).toContain('9:30 AM');
		expect(rendered).toContain('EST');
	});
});

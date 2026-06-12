import { describe, it, expect } from 'bun:test';
import { timeToMinutes, minutesToTime, addMinutesToTime, isoToMinutes, minutesToIso } from './time';

// These helpers replaced `@internationalized/date`'s parseTime/Time.add/parseDuration as the one place the
// booking domain does wall-clock math. The wrap/balance cases below are exactly the behaviors the old library
// guaranteed (Time.add balances hours and wraps at midnight; toString zero-pads), pinned so the swap is inert.

describe('timeToMinutes', () => {
	it('parses HH:MM', () => expect(timeToMinutes('09:30')).toBe(570));
	it('parses midnight', () => expect(timeToMinutes('00:00')).toBe(0));
	it('parses end of day', () => expect(timeToMinutes('23:59')).toBe(1439));
	it('ignores seconds (HH:MM:SS rows from Postgres time columns)', () => expect(timeToMinutes('09:30:15')).toBe(570));
});

describe('minutesToTime', () => {
	it('zero-pads', () => expect(minutesToTime(570)).toBe('09:30'));
	it('renders midnight', () => expect(minutesToTime(0)).toBe('00:00'));
	it('wraps a full day to midnight', () => expect(minutesToTime(1440)).toBe('00:00'));
	it('wraps past midnight', () => expect(minutesToTime(1500)).toBe('01:00'));
	it('wraps negative values backward', () => expect(minutesToTime(-30)).toBe('23:30'));
});

describe('addMinutesToTime', () => {
	it('adds within the hour', () => expect(addMinutesToTime('09:00', 30)).toBe('09:30'));
	it('balances across hours', () => expect(addMinutesToTime('09:00', 480)).toBe('17:00'));
	it('wraps at midnight', () => expect(addMinutesToTime('23:30', 60)).toBe('00:30'));
	it('subtracts across midnight', () => expect(addMinutesToTime('00:15', -30)).toBe('23:45'));
});

describe('isoToMinutes', () => {
	it('parses the canonical PT<minutes>M form', () => expect(isoToMinutes('PT480M')).toBe(480));
	it('parses small durations', () => expect(isoToMinutes('PT45M')).toBe(45));
	it('parses zero', () => expect(isoToMinutes('PT0M')).toBe(0));
	it('tolerates an hours component (legacy rows)', () => expect(isoToMinutes('PT1H30M')).toBe(90));
	it('tolerates hours-only', () => expect(isoToMinutes('PT2H')).toBe(120));
	it('degrades malformed input to 0', () => {
		expect(isoToMinutes('45')).toBe(0);
		expect(isoToMinutes('')).toBe(0);
		expect(isoToMinutes('P1DT45M')).toBe(0);
	});
});

describe('minutesToIso', () => {
	it('builds the canonical wire form', () => expect(minutesToIso(480)).toBe('PT480M'));
	it('round-trips with isoToMinutes', () => expect(isoToMinutes(minutesToIso(45))).toBe(45));
});

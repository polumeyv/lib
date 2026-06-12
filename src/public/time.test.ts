import { describe, it, expect } from 'bun:test';
import { Duration } from 'effect';
import { timeToMinutes, minutesToTime, addToTime, isoToDuration, durationToIso, minutesToIso, isoToMinutes } from './time';
import { TimeString, IsoMinutes } from '../schemas/primitives';

// These helpers replaced `@internationalized/date`'s parseTime/Time.add/parseDuration as the one place the
// booking domain does wall-clock math, with Effect Duration as the in-memory length type and the brands
// keeping dates/times/durations from mixing. The wrap/balance cases below are exactly the behaviors the old
// library guaranteed (Time.add balances hours and wraps at midnight; toString zero-pads), pinned so the swap
// is inert.

const t = TimeString.make;

describe('timeToMinutes', () => {
	it('parses HH:MM', () => expect(timeToMinutes(t('09:30'))).toBe(570));
	it('parses midnight', () => expect(timeToMinutes(t('00:00'))).toBe(0));
	it('parses end of day', () => expect(timeToMinutes(t('23:59'))).toBe(1439));
});

describe('minutesToTime', () => {
	it('zero-pads', () => expect(minutesToTime(570)).toBe(t('09:30')));
	it('renders midnight', () => expect(minutesToTime(0)).toBe(t('00:00')));
	it('wraps a full day to midnight', () => expect(minutesToTime(1440)).toBe(t('00:00')));
	it('wraps past midnight', () => expect(minutesToTime(1500)).toBe(t('01:00')));
	it('wraps negative values backward', () => expect(minutesToTime(-30)).toBe(t('23:30')));
});

describe('addToTime', () => {
	it('adds within the hour', () => expect(addToTime(t('09:00'), Duration.minutes(30))).toBe(t('09:30')));
	it('balances across hours', () => expect(addToTime(t('09:00'), Duration.hours(8))).toBe(t('17:00')));
	it('wraps at midnight', () => expect(addToTime(t('23:30'), Duration.hours(1))).toBe(t('00:30')));
	it('subtracts across midnight', () => expect(addToTime(t('00:15'), Duration.minutes(-30))).toBe(t('23:45')));
});

describe('isoToDuration / durationToIso', () => {
	it('decodes the wire form to a Duration', () => expect(Duration.toMinutes(isoToDuration(IsoMinutes.make('PT480M')))).toBe(480));
	it('round-trips through Duration', () => expect(durationToIso(isoToDuration(IsoMinutes.make('PT45M')))).toBe(IsoMinutes.make('PT45M')));
	it('encodes whole-hour Durations onto the minute grid', () => expect(durationToIso(Duration.hours(2))).toBe(IsoMinutes.make('PT120M')));
	it('rejects off-grid Durations at the wire boundary', () => expect(() => durationToIso(Duration.seconds(90))).toThrow());
});

describe('minutesToIso', () => {
	it('builds the canonical wire form', () => expect(minutesToIso(480)).toBe(IsoMinutes.make('PT480M')));
	it('rejects off-grid minutes', () => expect(() => minutesToIso(13)).toThrow());
});

describe('isoToMinutes (lenient legacy reader)', () => {
	it('parses the canonical form', () => expect(isoToMinutes('PT45M')).toBe(45));
	it('tolerates an hours component (legacy rows)', () => expect(isoToMinutes('PT1H30M')).toBe(90));
	it('tolerates hours-only', () => expect(isoToMinutes('PT2H')).toBe(120));
	it('degrades malformed input to 0', () => {
		expect(isoToMinutes('45')).toBe(0);
		expect(isoToMinutes('')).toBe(0);
		expect(isoToMinutes('P1DT45M')).toBe(0);
	});
});

describe('TimeString brand accepts Postgres HH:MM:SS rows via TimeRangeS', () => {
	it('timeToMinutes ignores seconds', () => {
		// TimeRangeS.start carries the same brand with a looser HH:MM(:SS) pattern; minute math drops seconds.
		expect(timeToMinutes('09:30:15' as TimeString)).toBe(570);
	});
});

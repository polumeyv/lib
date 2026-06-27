import { describe, it, expect } from 'bun:test';
import { Duration } from 'effect';
import { addToTime, isoToDuration, durationToIso, minutesToIso } from './time';
import { TimeString, IsoMinutes } from '../schemas/primitives';

// The brand boundary on top of `@polumeyv/utilities`' pure minute math: Effect Duration is the in-memory length
// type and the brands keep dates/times/durations from mixing. The wrap/balance cases pin the behaviors the old
// `@internationalized/date` swap guaranteed (Time.add balances hours and wraps at midnight; toString zero-pads).

const t = TimeString.make;

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

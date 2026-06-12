/**
 * Wall-clock time + duration math over the branded wire types: `TimeString` (ISO `HH:MM`/`HH:MM:SS`)
 * and `IsoMinutes` (`PT<minutes>M`), with Effect `Duration` as the in-memory type for any length of time.
 * Times are minutes-since-midnight underneath — no zones, no instants — so arithmetic balances across
 * hours and wraps at midnight, and the brands keep dates, times, and durations from mixing.
 */
import { Duration } from 'effect';
import { TimeString, IsoMinutes } from '../schemas/primitives';

/** "HH:MM" (or "HH:MM:SS"; seconds ignored — the booking grid is whole minutes) → minutes since midnight. */
export const timeToMinutes = (time: TimeString): number => {
	const [h = 0, m = 0] = time.split(':').map(Number);
	return h * 60 + m;
};

/** Minutes since midnight → "HH:MM", wrapping at midnight in either direction (1440 → "00:00", -30 → "23:30"). */
export const minutesToTime = (minutes: number): TimeString => {
	const min = ((minutes % 1440) + 1440) % 1440;
	return TimeString.make(`${String(Math.floor(min / 60)).padStart(2, '0')}:${String(min % 60).padStart(2, '0')}`);
};

/** A wall-clock time advanced by a `Duration` → "HH:MM", balancing across the hour and wrapping at midnight. */
export const addToTime = (time: TimeString, duration: Duration.Duration): TimeString =>
	minutesToTime(timeToMinutes(time) + Duration.toMinutes(duration));

/** Strict wire duration → `Duration`. The brand guarantees the `PT<minutes>M` form, so this never fails. */
export const isoToDuration = (iso: IsoMinutes): Duration.Duration => Duration.minutes(Number(iso.slice(2, -1)));

/** `Duration` → the canonical wire form `PT<minutes>M`. Throws (via the brand's checks) if the duration
 *  is not whole grid minutes — off-grid lengths must never reach the wire. */
export const durationToIso = (duration: Duration.Duration): IsoMinutes => minutesToIso(Duration.toMinutes(duration));

/** Whole minutes → `PT<minutes>M`, for the editor paths that genuinely work in minute numbers. */
export const minutesToIso = (minutes: number): IsoMinutes => IsoMinutes.make(`PT${minutes}M`);

/** Lenient ISO-8601 duration → whole minutes, for reading values that predate the minutes-only convention:
 *  tolerates `H`/`S` components and degrades malformed input to 0. New code should use {@link isoToDuration}. */
export const isoToMinutes = (iso: string): number => {
	const m = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(iso);
	return m ? Number(m[1] ?? 0) * 60 + Number(m[2] ?? 0) + Math.round(Number(m[3] ?? 0) / 60) : 0;
};

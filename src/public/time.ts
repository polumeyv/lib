/**
 * Brand-typed wall-clock duration math: `TimeString` (ISO `HH:MM`) and `IsoMinutes` (`PT<minutes>M`), with Effect
 * `Duration` as the in-memory length type. The pure, zone-free minute conversion (`timeToMinutes`/`minutesToTime`)
 * lives in `@polumeyv/utilities`; this module is the brand boundary on top of it — it re-brands results and adds the
 * `Duration`/`IsoMinutes` conversions the booking domain needs.
 */
import { Duration } from 'effect';
import { TimeString, IsoMinutes } from '../schemas/primitives';
import { timeToMinutes, minutesToTime } from '@polumeyv/utilities';

/** A wall-clock time advanced by a `Duration` → branded "HH:MM", balancing across the hour and wrapping at midnight. */
export const addToTime = (time: TimeString, duration: Duration.Duration): TimeString =>
	TimeString.make(minutesToTime(timeToMinutes(time) + Duration.toMinutes(duration)));

/** Strict wire duration → `Duration`. The brand guarantees the `PT<minutes>M` form, so this never fails. */
export const isoToDuration = (iso: IsoMinutes): Duration.Duration => Duration.minutes(Number(iso.slice(2, -1)));

/** Whole minutes → `PT<minutes>M`, for the editor paths that genuinely work in minute numbers. */
export const minutesToIso = (minutes: number): IsoMinutes => IsoMinutes.make(`PT${minutes}M`);

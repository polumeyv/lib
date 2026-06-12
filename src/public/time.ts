/**
 * Wall-clock time + duration math over the wire formats: ISO 8601 `HH:MM`/`HH:MM:SS` times
 * ({@link TimeString}) and `PT<minutes>M` durations ({@link IsoMinutes}). Times are minutes-since-midnight
 * underneath — no zones, no instants — so arithmetic balances across hours and wraps at midnight.
 */

/** ISO "HH:MM" (or "HH:MM:SS"; seconds ignored — the booking grid is whole minutes) → minutes since midnight. */
export const timeToMinutes = (time: string): number => {
	const [h = 0, m = 0] = time.split(':').map(Number);
	return h * 60 + m;
};

/** Minutes since midnight → "HH:MM", wrapping at midnight in either direction (1440 → "00:00", -30 → "23:30"). */
export const minutesToTime = (minutes: number): string => {
	const min = ((minutes % 1440) + 1440) % 1440;
	return `${String(Math.floor(min / 60)).padStart(2, '0')}:${String(min % 60).padStart(2, '0')}`;
};

/** "HH:MM" + minutes → "HH:MM", balancing across the hour and wrapping at midnight. */
export const addMinutesToTime = (time: string, minutes: number): string => minutesToTime(timeToMinutes(time) + minutes);

/** ISO 8601 duration → whole minutes. The canonical wire form is `PT<minutes>M`, but `H`/`S` components are
 *  tolerated (rows written before the minutes-only convention); malformed input degrades to 0, matching the
 *  null-tolerant style of the slot helpers. */
export const isoToMinutes = (iso: string): number => {
	const m = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(iso);
	return m ? Number(m[1] ?? 0) * 60 + Number(m[2] ?? 0) + Math.round(Number(m[3] ?? 0) / 60) : 0;
};

/** Whole minutes → the canonical wire duration `PT<minutes>M`. */
export const minutesToIso = (minutes: number): string => `PT${minutes}M`;

/**
 * Shared booking utilities — wire-format helpers for the booking flow.
 *
 * Wire conventions:
 * - Wall-clock dates/times use ISO strings (`YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`) and are
 *   resolved against the business's timezone server-side via `AT TIME ZONE biz.tz`.
 * - Instants (booking records) use full ISO with `Z`.
 * - Slot responses are `{ start, end }` objects with ISO 8601 `HH:MM` wall-clock times.
 */
import { parseTime, parseDate, Time, CalendarDate, CalendarDateTime, toCalendarDateTime, DateFormatter } from '@internationalized/date';

/** Shape returned by GET /book/services/:b_id for each service. */
export type Service = { id: string; type: string; name: string; amount: number; dur: number };

/** An available booking slot — ISO 8601 "HH:MM" wall-clock start/end, as returned by /book/day and /book/month. */
export type Slot = { start: string; end: string };

export const SESSION_TTL = 3 * 60 * 60;

/** Reference day for formatting bare times of day; only the wall-clock time is ever rendered. */
const TIME_EPOCH = new CalendarDate(1970, 1, 1);
const TIME_FMT = new DateFormatter('en-US', { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' });

/** ISO 8601 "HH:MM" wall-clock → a UTC instant on the reference day, ready for TIME_FMT.
 *  (DateFormatter renders JS Dates; pinning the instant and the formatter to UTC keeps the
 *   displayed hour/minute identical to the input on any runtime.) */
const timeToDate = (time: string) => toCalendarDateTime(TIME_EPOCH, parseTime(time)).toDate('UTC');

/** ISO "HH:MM" → "9:30 AM". */
export const formatTimeDisplay = (time: string) => TIME_FMT.format(timeToDate(time));

/** ISO "HH:MM" pair → "9:30 – 10:15 AM" (locale-aware range). */
export const formatTimeRange = (start: string, end: string) => TIME_FMT.formatRange(timeToDate(start), timeToDate(end));

const DATE_FMT = new DateFormatter('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });

/** ISO "YYYY-MM-DD" → "Monday, January 1, 2024". */
export const formatBookingDate = (dateStr: string) => DATE_FMT.format(parseDate(dateStr).toDate('UTC'));

/** Wall-clock components in `tz` → "Monday, January 1, 2024 at 9:30 AM EST".
 *  `CalendarDateTime(...).toDate(tz)` interprets the components as wall-clock time in `tz`. */
export const formatBookingDateTime = (year: number, month: number, day: number, h: number, m: number, tz: string) =>
	new DateFormatter('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZone: tz, timeZoneName: 'short' }).format(
		new CalendarDateTime(year, month, day, h, m).toDate(tz),
	);

/** Format cents to dollars display string. */
export const formatCurrency = (cents: number, decimals: number = 2) => (cents / 100).toFixed(decimals);

// ══════════════════════════════════════════════════════════════════════════════
// TIME SLOTS
// ══════════════════════════════════════════════════════════════════════════════

export type TimeSlot = { value: string; label: string };
export type TimeRange = { start: string; end: string };

/** Non-throwing parse of an ISO 8601 "HH:MM" wall-clock string → Time, or null if malformed. */
function toTime(time: string): Time | null {
	try {
		return parseTime(time);
	} catch {
		return null;
	}
}

/** Sign of (time1 − time2): negative if earlier, 0 if equal or either is malformed, positive if later. */
export function compareTime(time1: string, time2: string): number {
	const a = toTime(time1);
	const b = toTime(time2);
	if (!a || !b) return 0;
	return a.compare(b);
}

export function isTimeInRange(time: string, minTime: string, maxTime: string): boolean {
	return compareTime(time, minTime) >= 0 && compareTime(time, maxTime) <= 0;
}

/** Duration in minutes from startTime to endTime (0 if either is malformed). */
export function getTimeDuration(startTime: string, endTime: string): number {
	const start = toTime(startTime);
	const end = toTime(endTime);
	if (!start || !end) return 0;
	return end.hour * 60 + end.minute - (start.hour * 60 + start.minute);
}

export function formatDuration(minutes: number): string {
	if (minutes < 60) return `${minutes}m`;
	const h = Math.floor(minutes / 60);
	const m = minutes % 60;
	return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

export function generateTimeSlots(startHour: number, endHour: number, interval: number): TimeSlot[] {
	const slots: TimeSlot[] = [];
	const span = (endHour - startHour) * 60;
	// `elapsed` bounds the loop in minutes (so endHour === 24 works); `t` advances via Time.add,
	// which balances across the hour and wraps at midnight — its toString() zero-pads for us.
	let t = new Time(startHour);
	for (let elapsed = 0; elapsed < span; elapsed += interval) {
		const value = t.toString().slice(0, 5);
		slots.push({ value, label: formatTimeDisplay(value) });
		t = t.add({ minutes: interval });
	}
	return slots;
}

export const b_HOURS: TimeSlot[] = generateTimeSlots(9, 17, 60);
export const EXTENDED_HOURS: TimeSlot[] = generateTimeSlots(7, 21, 60);

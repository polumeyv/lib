/**
 * Booking date/time presentation helpers.
 *
 * Wire conventions:
 * - Wall-clock times are ISO 8601 `HH:MM` and rendered against the business timezone where relevant.
 * - Calendar dates are ISO `YYYY-MM-DD`; for both plain dates and plain times we pin the instant and the
 *   formatter to UTC so the displayed value matches the input on any runtime.
 */
import { timeToMinutes } from './time';
import type { DateString, TimeString } from '../schemas/primitives';

/** ISO 8601 "HH:MM" wall-clock → a UTC instant on the epoch day, ready for the UTC formatter. */
const timeToDate = (time: TimeString) => new Date(timeToMinutes(time) * 60_000);

const timeFormatter = new Intl.DateTimeFormat('en-US', { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' });

/** ISO "HH:MM" → "9:30 AM". */
export const formatTimeDisplay = (time: TimeString) => timeFormatter.format(timeToDate(time));

/** ISO "HH:MM" pair → "9:30 – 10:15 AM" (locale-aware range). */
export const formatTimeRange = (start: TimeString, end: TimeString) => timeFormatter.formatRange(timeToDate(start), timeToDate(end));

/** ISO "YYYY-MM-DD" → "Monday, January 1, 2024" (UTC-pinned both sides so the rendered date matches the input).
 *  Pass `options` to change the parts, e.g. `{ month: 'long', day: 'numeric', year: 'numeric' }` to drop the weekday. */
export const formatDateDisplay = (
	date: DateString,
	options: Intl.DateTimeFormatOptions = { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' },
) => new Intl.DateTimeFormat('en-US', { ...options, timeZone: 'UTC' }).format(new Date(`${date}T00:00:00Z`));

/** A `Date` instant rendered in the business `tz` → "Monday, January 1, 2024 at 9:30 AM EST". */
const bookingDateTimeFormatter = (tz: string) =>
	new Intl.DateTimeFormat('en-US', {
		weekday: 'long',
		year: 'numeric',
		month: 'long',
		day: 'numeric',
		hour: 'numeric',
		minute: '2-digit',
		timeZone: tz,
		timeZoneName: 'short',
	});

/** A booking instant (the slot's start) + business `tz` → "Monday, January 1, 2024 at 9:30 AM EST". */
export const formatBookingDateTime = (date: Date, tz: string) => bookingDateTimeFormatter(tz).format(date);

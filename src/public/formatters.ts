/**
 * Booking date/time presentation helpers.
 *
 * Wire conventions:
 * - Wall-clock times are ISO 8601 `HH:MM` and rendered against the business timezone where relevant.
 * - `DateFormatter` renders JS `Date`s; for plain `HH:MM` we pin both the instant and the formatter to
 *   UTC so the displayed hour/minute matches the input on any runtime.
 */
import { parseTime, CalendarDate, toCalendarDateTime, DateFormatter } from '@internationalized/date';

/** ISO 8601 "HH:MM" wall-clock → a UTC instant on the reference day, ready for the UTC formatter. */
const timeToDate = (time: string) => toCalendarDateTime(new CalendarDate(1970, 1, 1), parseTime(time)).toDate('UTC');

const timeFormatter = new DateFormatter('en-US', { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' });

/** ISO "HH:MM" → "9:30 AM". */
export const formatTimeDisplay = (time: string) => timeFormatter.format(timeToDate(time));

/** ISO "HH:MM" pair → "9:30 – 10:15 AM" (locale-aware range). */
export const formatTimeRange = (start: string, end: string) => timeFormatter.formatRange(timeToDate(start), timeToDate(end));

/** A `Date` instant rendered in the business `tz` → "Monday, January 1, 2024 at 9:30 AM EST". */
const bookingDateTimeFormatter = (tz: string) =>
	new DateFormatter('en-US', {
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

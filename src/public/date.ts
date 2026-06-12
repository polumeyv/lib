/**
 * Calendar-date math over the wire format `YYYY-MM-DD` ({@link DateString}), backed by Effect `DateTime`.
 * Dates round-trip through UTC-midnight instants, so month arithmetic clamps into the target month
 * (Jan 31 + 1 month → Feb 28/29) and nothing here ever shifts a date across a zone boundary.
 *
 * These are synchronous display-layer helpers. Server Effect code that needs "today" should read the clock
 * effectfully (`yield* DateTime.now`) and derive the date itself, so it stays TestClock-controllable.
 */
import { DateTime } from 'effect';

const toUtc = (date: string) => DateTime.makeUnsafe(`${date}T00:00:00Z`);

/** Today's calendar date in an IANA `tz` → "YYYY-MM-DD". Throws on an invalid zone id. */
export const todayIn = (tz: string): string => DateTime.formatIsoDate(DateTime.setZoneNamedUnsafe(DateTime.nowUnsafe(), tz));

/** The runtime's IANA time zone, e.g. "America/New_York". */
export const localTimeZone = (): string => new Intl.DateTimeFormat().resolvedOptions().timeZone;

/** "YYYY-MM-DD" ± days → "YYYY-MM-DD", carrying across month/year boundaries. */
export const addDays = (date: string, days: number): string => DateTime.formatIsoDateUtc(DateTime.add(toUtc(date), { days }));

/** "YYYY-MM-DD" ± months → "YYYY-MM-DD", clamping to the target month's last day (Jan 31 + 1 → Feb 28/29). */
export const addMonths = (date: string, months: number): string => DateTime.formatIsoDateUtc(DateTime.add(toUtc(date), { months }));

/** "YYYY-MM-DD" ± years → "YYYY-MM-DD", clamping Feb 29 to Feb 28 in non-leap years. */
export const addYears = (date: string, years: number): string => DateTime.formatIsoDateUtc(DateTime.add(toUtc(date), { years }));

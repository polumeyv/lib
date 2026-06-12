/**
 * Calendar-date math over the branded wire type `DateString` (`YYYY-MM-DD`), backed by Effect `DateTime`.
 * Dates round-trip through UTC-midnight instants, so month arithmetic clamps into the target month
 * (Jan 31 + 1 month → Feb 28/29) and nothing here ever shifts a date across a zone boundary. The brand
 * means a `DateString` can only originate from schema validation or these helpers — never a raw string.
 *
 * These are synchronous display-layer helpers. Server Effect code that needs "today" should read the clock
 * effectfully (`yield* DateTime.now`) and derive the date itself, so it stays TestClock-controllable.
 */
import { DateTime } from 'effect';
import { DateString } from '../schemas/primitives';

const toUtc = (date: DateString) => DateTime.makeUnsafe(`${date}T00:00:00Z`);
const fromUtc = (dt: DateTime.Utc): DateString => DateString.make(DateTime.formatIsoDateUtc(dt));

/** Today's calendar date in an IANA `tz`. Throws on an invalid zone id. */
export const todayIn = (tz: string): DateString => DateString.make(DateTime.formatIsoDate(DateTime.setZoneNamedUnsafe(DateTime.nowUnsafe(), tz)));

/** The runtime's IANA time zone, e.g. "America/New_York". */
export const localTimeZone = (): string => new Intl.DateTimeFormat().resolvedOptions().timeZone;

/** A date ± days, carrying across month/year boundaries. */
export const addDays = (date: DateString, days: number): DateString => fromUtc(DateTime.add(toUtc(date), { days }));

/** A date ± months, clamping to the target month's last day (Jan 31 + 1 → Feb 28/29). */
export const addMonths = (date: DateString, months: number): DateString => fromUtc(DateTime.add(toUtc(date), { months }));

/** A date ± years, clamping Feb 29 to Feb 28 in non-leap years. */
export const addYears = (date: DateString, years: number): DateString => fromUtc(DateTime.add(toUtc(date), { years }));

/** The day-of-month (1–31) of a date. */
export const dayOfMonth = (date: DateString): number => Number(date.slice(8, 10));

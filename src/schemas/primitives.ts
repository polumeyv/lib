/**
 * @module @polumeyv/lib/schemas/primitives
 *
 * ## Tier 1 — building blocks
 *
 * Atomic, single-value schema validations and the small helpers that construct them.
 *
 * **Import rule:** this file imports ONLY `effect/Schema` (and other `effect` tools). It must never
 * import from `./tables` or `./projections` — it is the bottom of the dependency graph both build on.
 *
 * **What belongs here:** any value-shape validated more than once across the monorepo (an email, a uuid,
 * a slug, a phone), so its schema is defined exactly once. Schema-constructor helpers (`varchar(n)`) live
 * here too — they exist solely to avoid re-spelling the same validation at every call site.
 *
 * See `./tables` for how these compose into table rows, and `./projections` for the groupings on top.
 */
import * as S from 'effect/Schema';

/** UUID string. The base for every id column; `UserSub` brands the subset that references `users(sub)`. */
export const Uuid = S.String.check(S.isUUID());
export type Uuid = typeof Uuid.Type;

/**
 * A `users(sub)` reference — the canonical user identifier, built from {@link Uuid}. Brand a column with
 * this ONLY when it points at `users(sub)` (e.g. `sub`, `owner_sub`, `referrer_sub`, `cancelled_by`).
 * Other tables' UUID primary/foreign keys stay plain {@link Uuid} — a business id is not a user.
 */
export const UserSub = Uuid.pipe(S.brand('UserSub'));
export type UserSub = typeof UserSub.Type;

/** `VARCHAR(n)` — a string capped at `n` characters (the only thing the DB validates on a free varchar). */
export const varchar = (n: number) => S.String.check(S.isMaxLength(n));

/** Integer USD cents — the canonical storage/compute unit for money. Brand a money column with this so a whole-dollars
 *  value can't be passed where cents are expected; the dollars↔cents conversion lives in the `Dollars` form codec and the
 *  `@polumeyv/lib/public` money helpers. A pure brand (no extra check) — the DB column already constrains the value, per
 *  the {@link ./tables} convention of leaving integer columns as `S.Number`. */
export const Cents = S.Number.pipe(S.brand('Cents'));
export type Cents = typeof Cents.Type;

/** Basis points — 1/100 of a percent (e.g. the platform fee withheld from a charge via Stripe `application_fee_amount`). */
export const Bps = S.Number.pipe(S.brand('Bps'));
export type Bps = typeof Bps.Type;

export const Email = S.String.pipe(S.check(S.isPattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, { message: 'Please enter a valid email address' })));
export type Email = typeof Email.Type;

export const Phone = S.String.pipe(S.check(S.isPattern(/^\+[1-9]\d{1,14}$/, { message: 'Please enter a valid phone number' })));
export type Phone = typeof Phone.Type;

export const PhoneNA = S.String.pipe(S.check(S.isPattern(/^\+(?:1|52)\d{10}$/, { message: 'Please enter a valid phone number' })));
export type PhoneNA = typeof PhoneNA.Type;

export const Name = S.NonEmptyString.check(S.isMaxLength(60));
export type Name = typeof Name.Type;

export const Slug = S.String.pipe(S.check(S.isPattern(/^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/)));

export const Domain = S.String.pipe(S.check(S.isPattern(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/)));

/** Calendar date, `YYYY-MM-DD`. Branded: construct via the schema (`DateString.make`) or the
 *  `@polumeyv/lib/public` date helpers, never from a raw string. */
export const DateString = S.String.pipe(
	S.check(S.isPattern(/^\d{4}-\d{2}-\d{2}$/, { message: 'Invalid date (expected YYYY-MM-DD)' })),
	S.brand('DateString'),
);
export type DateString = typeof DateString.Type;

/** Calendar month, `YYYY-MM`. */
export const MonthString = S.String.pipe(S.check(S.isPattern(/^\d{4}-\d{2}$/, { message: 'Invalid month (expected YYYY-MM)' })));

/** Wall-clock time, `HH:MM` (24-hour). Shares the `TimeString` brand with {@link TimeRangeS}'s looser
 *  `HH:MM(:SS)` form — both mean "validated wall-clock time"; this strict form is for user input. */
export const TimeString = S.String.pipe(
	S.check(S.isPattern(/^\d{2}:\d{2}$/, { message: 'Invalid time (expected HH:MM)' })),
	S.brand('TimeString'),
);
export type TimeString = typeof TimeString.Type;

/** ISO 8601 wall-clock date-time without zone, `YYYY-MM-DDTHH:MM`. */
export const DateTimeString = S.String.pipe(
	S.check(S.isPattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/, { message: 'Invalid date-time (expected YYYY-MM-DDTHH:MM)' })),
);

/**
 * The booking grid: the smallest unit of time the whole booking domain speaks. Every duration (service length,
 * buffer, open-hours range, generated slot) and every slot start is a multiple of this, so slot arithmetic is exact
 * and times never fall off the `:00/:05/:10…` grid. Enforced wherever a minute value enters the domain.
 */
export const MINUTE_STEP = 5;

/** A non-negative whole-minute duration on the booking grid (a multiple of {@link MINUTE_STEP}). */
export const GridMinutes = S.Int.pipe(
	S.check(S.isGreaterThanOrEqualTo(0), S.isMultipleOf(MINUTE_STEP, { message: `Must be in ${MINUTE_STEP}-minute increments` })),
);
export type GridMinutes = typeof GridMinutes.Type;

/** ISO 8601 minutes duration `PT<minutes>M` (e.g. `PT45M`) on the booking grid — the wire/storage form for any
 *  length, with minutes constrained to a multiple of {@link MINUTE_STEP}. */
export const IsoMinutes = S.String.pipe(
	S.check(S.isPattern(/^PT\d+M$/, { message: 'Invalid duration (expected PT<minutes>M)' })),
	S.check(
		S.makeFilter((s) => Number(s.slice(2, -1)) % MINUTE_STEP === 0, { message: `Duration must be in ${MINUTE_STEP}-minute increments` }),
	),
	S.brand('IsoMinutes'),
);
export type IsoMinutes = typeof IsoMinutes.Type;

/**
 * One open/bookable range: an ISO wall-clock `start` (`HH:MM` or `HH:MM:SS`) plus an ISO-8601 minutes `dur`.
 * The single shape behind a business-hours window, a generated slot, and a held booking — so every consumer
 * does its time math through `@polumeyv/lib/public` (`timeToMinutes` + `isoToMinutes`) off one definition,
 * and Postgres reads `start::time` / `dur::interval` directly.
 */
export const TimeRangeS = S.Struct({
	start: S.String.pipe(
		S.check(S.isPattern(/^\d{2}:\d{2}(:\d{2})?$/, { message: 'Invalid time (expected HH:MM or HH:MM:SS)' })),
		S.brand('TimeString'),
	),
	dur: IsoMinutes,
});
export type TimeRange = typeof TimeRangeS.Type;

export const getHostname = (url: string) => new URL(url.includes('://') ? url : `https://${url}`).hostname;

/** Join a name's first + last into a display name, dropping blank/missing parts (no stray spaces).
 *  Takes the whole name object (e.g. `fullName(user.current.name)`); accepts any record with `f_name`/`l_name`. */
export const fullName = (name?: { f_name?: string | null; l_name?: string | null }) =>
	[name?.f_name, name?.l_name].filter(Boolean).join(' ');

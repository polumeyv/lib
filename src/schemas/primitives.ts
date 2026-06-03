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

export const Email = S.String.pipe(S.check(S.isPattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, { message: 'Please enter a valid email address' })));
export type Email = typeof Email.Type;

export const Phone = S.String.pipe(S.check(S.isPattern(/^\+[1-9]\d{1,14}$/, { message: 'Please enter a valid phone number' })));
export type Phone = typeof Phone.Type;

/** A person-name field: non-empty, ≤60 chars. Reused for first/last name so the shape is declared once. */
export const Name = S.NonEmptyString.check(S.isMaxLength(60));
export type Name = typeof Name.Type;

export const Slug = S.String.pipe(S.check(S.isPattern(/^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/)));

export const Domain = S.String.pipe(S.check(S.isPattern(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/)));

/** Calendar date, `YYYY-MM-DD`. */
export const DateString = S.String.pipe(S.check(S.isPattern(/^\d{4}-\d{2}-\d{2}$/, { message: 'Invalid date (expected YYYY-MM-DD)' })));

/** Calendar month, `YYYY-MM`. */
export const MonthString = S.String.pipe(S.check(S.isPattern(/^\d{4}-\d{2}$/, { message: 'Invalid month (expected YYYY-MM)' })));

/** Wall-clock time, `HH:MM` (24-hour). */
export const TimeString = S.String.pipe(S.check(S.isPattern(/^\d{2}:\d{2}$/, { message: 'Invalid time (expected HH:MM)' })));

/** ISO 8601 wall-clock date-time without zone, `YYYY-MM-DDTHH:MM`. */
export const DateTimeString = S.String.pipe(S.check(S.isPattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/, { message: 'Invalid date-time (expected YYYY-MM-DDTHH:MM)' })));

export const getHostname = (url: string) => new URL(url.includes('://') ? url : `https://${url}`).hostname;

/** Join a name's first + last into a display name, dropping blank/missing parts (no stray spaces).
 *  Takes the whole name object (e.g. `fullName(user.current.name)`); accepts any record with `f_name`/`l_name`. */
export const fullName = (name?: { f_name?: string | null; l_name?: string | null }) => [name?.f_name, name?.l_name].filter(Boolean).join(' ');

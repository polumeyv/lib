/**
 * Shared booking utilities — wire-format helpers for the booking flow.
 *
 * Wire conventions:
 * - Wall-clock dates/times use ISO strings (`YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`) and are
 *   resolved against the business's timezone server-side via `AT TIME ZONE biz.tz`.
 * - Instants (booking records) use full ISO with `Z`.
 * - Slot responses use compact `HHmmHHmm` wall-clock pairs (kept for payload size).
 */
import { Schema, DateTime } from 'effect';

/**
 * uuid_fields ↔ { uuid, fields }
 * Session ID encoding: "abc-123_fnlnem-phnt"
 */
export const Sid = Schema.transform(
	Schema.String.pipe(Schema.pattern(/^[0-9a-f-]+_[a-z0-9]+-[a-z0-9]+$/)),
	Schema.Struct({ uuid: Schema.String, fields: Schema.String }),
	{
		strict: true,
		decode: (s) => {
			const idx = s.indexOf('_');
			return { uuid: s.slice(0, idx), fields: s.slice(idx + 1) };
		},
		encode: ({ uuid, fields }) => `${uuid}_${fields}`,
	},
);

/**
 * "fnlnem-phnt" ↔ { required: string[], optional: string[] }
 */
export const FieldEncoding = Schema.transform(
	Schema.String.pipe(Schema.pattern(/^[a-z0-9]+-[a-z0-9]*$/)),
	Schema.Struct({ required: Schema.Array(Schema.String), optional: Schema.Array(Schema.String) }),
	{
		strict: true,
		decode: (s) => {
			const [reqStr = '', optStr = ''] = s.split('-');
			const split = (v: string) => v.match(/.{2}/g) ?? [];
			return { required: split(reqStr), optional: split(optStr) };
		},
		encode: ({ required, optional }) => required.join('') + '-' + optional.join(''),
	},
);

export const parseSid = (s: string) => Schema.decodeUnknown(Sid)(s);

export const parseFieldEncoding = (s: string) => Schema.decodeUnknown(FieldEncoding)(s);

export const encodeSid = (uuid: string, fields: string): string => `${uuid}_${fields}`;

export const FIELD_VALIDATORS: Record<string, (v: unknown) => boolean> = {
	fn: (v) => typeof v === 'string' && v.length >= 1 && v.length <= 100,
	ln: (v) => typeof v === 'string' && v.length >= 1 && v.length <= 100,
	em: (v) => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
	ph: (v) => typeof v === 'string' && v.length >= 7 && v.length <= 30,
	ad: (v) => typeof v === 'string' && v.length >= 5,
	nt: (v) => typeof v === 'string' && v.length <= 1000,
	pm: () => true,
};

// ══════════════════════════════════════════════════════════════════════════════
// API RESPONSE SHAPES
// ══════════════════════════════════════════════════════════════════════════════

/** Shape returned by GET /book/services/:b_id for each service. */
export type Service = { id: string; type: string; name: string; amount: number; dur: number };

// ══════════════════════════════════════════════════════════════════════════════
// SESSION SUBMISSION
// ══════════════════════════════════════════════════════════════════════════════

/** Schema for the booking session form submission (fn, ln, em). */
export const SessionBody = Schema.Struct({
	fn: Schema.String.pipe(Schema.trimmed(), Schema.minLength(1)),
	ln: Schema.String.pipe(Schema.trimmed(), Schema.minLength(1)),
	em: Schema.String.pipe(Schema.trimmed(), Schema.minLength(1)),
});

export type SessionBody = typeof SessionBody.Type;

// ══════════════════════════════════════════════════════════════════════════════
// FIELD CODES
// ══════════════════════════════════════════════════════════════════════════════

/** Two-letter field codes used in session ID encoding. */
export const FIELD_CODES = {
	fn: 'First name',
	ln: 'Last name',
	em: 'Email',
	ph: 'Phone',
	ad: 'Address',
	nt: 'Notes',
	pm: 'Payment',
} as const;

export type FieldCode = keyof typeof FIELD_CODES;

/** Payment type codes (subtype of pm). */
export const PAYMENT_CODES = {
	p1: 'Fee-based',
	p2: 'Tip-based',
	p3: 'Full prepayment',
	p4: 'Partial / deposit',
} as const;

export type PaymentCode = keyof typeof PAYMENT_CODES;

/** Check if payment is in the required or optional side of the encoding. */
export function getPaymentPosition(encoding: string): 'required' | 'optional' | 'none' {
	const parsed = Schema.decodeUnknownOption(FieldEncoding)(encoding);
	if (parsed._tag === 'None') return 'none';
	if (parsed.value.required.some((c) => c.startsWith('p'))) return 'required';
	if (parsed.value.optional.some((c) => c.startsWith('p'))) return 'optional';
	return 'none';
}

// ══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ══════════════════════════════════════════════════════════════════════════════

export const SESSION_TTL = 3 * 60 * 60;

// ══════════════════════════════════════════════════════════════════════════════
// TIME FORMATTING
// ══════════════════════════════════════════════════════════════════════════════

/** Format HHmm → "h:MM AM/PM" for display. */
export function formatHHmm(hhmm: string): string {
	const h = parseInt(hhmm.slice(0, 2), 10);
	const m = hhmm.slice(2, 4);
	const period = h >= 12 ? 'PM' : 'AM';
	const hour = h % 12 || 12;
	return `${hour}:${m} ${period}`;
}

/** Format a slot string HHmmHHmm → "h:MM AM – h:MM PM" for display. */
export function formatSlotDisplay(slot: string): string {
	return `${formatHHmm(slot.slice(0, 4))} – ${formatHHmm(slot.slice(4, 8))}`;
}

/** Parse "HH:MM" → { hour, minute } or null. */
export function parseTime(time: string): { hour: number; minute: number } | null {
	const match = time.match(/^(\d{1,2}):(\d{2})$/);
	if (!match) return null;
	const hourStr = match[1];
	const minuteStr = match[2];
	if (hourStr === undefined || minuteStr === undefined) return null;
	const hour = parseInt(hourStr, 10);
	const minute = parseInt(minuteStr, 10);
	if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return null;
	return { hour, minute };
}

/** Formats "HH:MM" → "h:MM AM/PM" */
export const formatTimeDisplay = (time: string) =>
	DateTime.unsafeMake(`1970-01-01T${time}`).pipe(DateTime.formatUtc({ locale: 'en-US', hour: 'numeric', minute: '2-digit' }));

/** Formats "YYYY-MM-DD" → "Monday, January 1, 2024" */
export const formatBookingDate = (dateStr: string) =>
	DateTime.unsafeMake(dateStr).pipe(DateTime.removeTime, DateTime.formatUtc({ locale: 'en-US', weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }));

/** Formats "HH:MM" → "h:MM AM/PM ET" */
export const formatBookingTime = (time: string) => `${formatTimeDisplay(time)} ET`;

/** Formats wall-clock components into a full localized date/time string with timezone.
 *  `h`/`m` are WALL-CLOCK time in `tz` (not UTC), so we format them directly rather than
 *  round-tripping through Date.UTC (which would subtract the tz offset and shift the time). */
export const formatBookingDateTime = (year: number, month: number, day: number, h: number, m: number, tz: string) => {
	const date = new Date(year, month - 1, day);
	const weekday = date.toLocaleString('en-US', { weekday: 'long' });
	const monthName = date.toLocaleString('en-US', { month: 'long' });
	const hour12 = h % 12 || 12;
	const ampm = h < 12 ? 'AM' : 'PM';
	const min = String(m).padStart(2, '0');
	const parts = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'short' }).formatToParts(new Date(year, month - 1, day, h, m));
	const tzLabel = parts.find((p) => p.type === 'timeZoneName')?.value ?? '';
	return `${weekday}, ${monthName} ${day}, ${year}, ${hour12}:${min} ${ampm} ${tzLabel}`.trim();
};

/** Format cents to dollars display string. */
export const formatCurrency = (cents: number, decimals: number = 2) => (cents / 100).toFixed(decimals);

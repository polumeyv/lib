/**
 * @module @polumeyv/lib/schemas/tables
 *
 * ## Tier 2 — tables
 *
 * The single source of truth for every database table, mirroring `scripts/init.sql` column-for-column.
 * Each `S.Struct` is the *raw physical row* exactly as Bun's SQL driver returns it — not an app-facing
 * projection.
 *
 * **Import rule:** this file imports only from `./primitives` (building blocks) and `effect/Schema`. It
 * never imports from `./projections`. Everything app-facing (name-mapped views, form inputs, cross-table
 * shapes) is built FROM these tables over in `./projections`.
 *
 * ## DDL → Effect mapping rules
 *  - `NOT NULL` column            → bare type (`S.String`, `S.Number`, …)
 *  - nullable column              → `S.NullOr(...)`  (Bun reads SQL NULL as `null`, never absent)
 *  - a `DEFAULT` does NOT imply non-null: a column without `NOT NULL` is `NullOr` even with a default
 *  - UUID primary key / non-user FK → `Uuid`
 *  - UUID referencing `users(sub)`  → `UserSub` (the branded user identifier)
 *  - `VARCHAR(n)` (unconstrained) → `varchar(n)` (string + isMaxLength)  — DB only validates the length
 *  - FK to a lookup table         → `S.Number` (the raw integer id; name-mapping is a projection concern)
 *  - pg `ENUM` / `CHECK ... IN`   → `S.Literals([...])`  (the DB genuinely constrains the value set)
 *  - `SMALLINT`/`INT`/`BIGINT`/`SERIAL` → `S.Number`
 *  - `DECIMAL`                    → `S.Number` (read sites cast `::float8`; see `businesses.tax_rate`)
 *  - `TIMESTAMP`/`TIMESTAMPTZ`/`DATE` → `S.Date`
 *  - `TSTZRANGE`                  → `S.String` (Bun returns the range literal)
 *  - `POINT`                      → `S.Tuple([S.Number, S.Number])` as `[lat, lng]`
 *  - `BYTEA`                      → `S.Uint8Array`
 *  - `TEXT[]` / `VARCHAR(n)[]`    → `S.Array(...)`
 *  - `JSONB`                      → the fixed app shape where one exists, else `S.Unknown`
 *
 * Where the column is looser than the app's contract (e.g. `addresses.address_type` is a free
 * `VARCHAR(50)` with no CHECK), the canonical schema stays faithful to the DB and the narrowing
 * (to `ADDRESS_TYPE` literals, etc.) lives in the derived projection — never here.
 */
import * as S from 'effect/Schema';
import { Uuid, UserSub, varchar, Email, Phone, Name, TimeRangeS } from './primitives';

// ── pg ENUM types ─────────────────────────────────────────────────────────--
/** `us_timezone` enum. */
export const TIMEZONE = S.Literals([
	'America/New_York',
	'America/Chicago',
	'America/Denver',
	'America/Los_Angeles',
	'America/Phoenix',
	'America/Anchorage',
	'Pacific/Honolulu',
	'America/Puerto_Rico',
]);
export type TIMEZONE = typeof TIMEZONE.Type;

/** `oauth_provider` enum. */
export const OAUTH_PROVIDER = S.Literals(['google']);
export type OAUTH_PROVIDER = typeof OAUTH_PROVIDER.Type;

/** `oauth_status` enum. */
export const OAUTH_STATUS = S.Literals(['active', 'revoked', 'hijacked']);
export type OAUTH_STATUS = typeof OAUTH_STATUS.Type;

/** `cresends.provider_type` enum. */
export const CRESENDS_PROVIDER_TYPE = S.Literals(['smtp', 'google_workspace', 'microsoft_365']);
export type CRESENDS_PROVIDER_TYPE = typeof CRESENDS_PROVIDER_TYPE.Type;

// ── Lookup-table value sets (the seeded `name` values; ids are FKs elsewhere) ─
export const B_TYPE = S.Literals(['salon', 'barbershop', 'spa', 'nails', 'esthetics', 'makeup', 'tattoo', 'other']);
export type BType = typeof B_TYPE.Type;

export const CLIENT_STATUS = S.Literals(['active', 'inactive', 'vip', 'new', 'at_risk']);
export type ClientStatus = typeof CLIENT_STATUS.Type;

export const SERVICE_TYPE = S.Literals(['service', 'addon']);
export type ServiceType = typeof SERVICE_TYPE.Type;

export const BOOKING_STATUS = S.Literals(['pending', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show', 'held']);
export type BookingStatus = typeof BOOKING_STATUS.Type;

export const PAYOUT_SCHEDULE = S.Literals(['daily', 'weekly', 'biweekly', 'monthly']);
export type PayoutSchedule = typeof PAYOUT_SCHEDULE.Type;

export const SERVICE_CATEGORY = S.Literals(['haircut', 'color', 'styling', 'treatment', 'extension', 'nails', 'wax', 'facial', 'makeup', 'massage', 'other']);
export type ServiceCategory = typeof SERVICE_CATEGORY.Type;

// =============================================================================
// IDENTITY / AUTH
// =============================================================================

export const Users = S.Struct({
	sub: UserSub,
	email: Email,
	phone: S.NullOr(Phone), // nullable; CONSTRAINT phone_e164
	f_name: Name,
	l_name: Name,
	stripe_cus_id: S.NullOr(varchar(255)),
	stripe_sub_id: S.NullOr(varchar(255)),
	stripe_acct_id: S.NullOr(varchar(255)),
	locked: S.Boolean,
	terms_acc: S.NullOr(S.Date),
	roles: S.Array(S.String),
});
export type Users = typeof Users.Type;

export const PasskeyCredentials = S.Struct({
	id: varchar(255),
	sub: S.NullOr(UserSub),
	webauthn_user_id: varchar(255),
	public_key: S.Uint8Array,
	counter: S.Number,
	device_type: S.NullOr(varchar(32)),
	backed_up: S.NullOr(S.Boolean), // no NOT NULL
	transports: S.NullOr(S.Array(varchar(255))),
	created_at: S.NullOr(S.Date), // no NOT NULL
});
export type PasskeyCredentials = typeof PasskeyCredentials.Type;

export const OidcAccounts = S.Struct({
	sub: UserSub,
	provider: OAUTH_PROVIDER,
	subject: varchar(255),
	email: S.NullOr(varchar(255)),
	locale: S.NullOr(varchar(10)),
	access_token: S.NullOr(S.String),
	refresh_token: S.NullOr(S.String),
	scopes: S.NullOr(S.String),
	token_expires: S.NullOr(S.Date),
	status: OAUTH_STATUS,
});
export type OidcAccounts = typeof OidcAccounts.Type;

export const RiscEvents = S.Struct({
	jti: varchar(255),
	event_type: varchar(255),
	subject: S.NullOr(varchar(255)),
	received: S.Date,
});
export type RiscEvents = typeof RiscEvents.Type;

export const Oauth2Clients = S.Struct({
	client_id: varchar(64),
	client_secret: S.String,
	redirect_uris: S.Array(S.String),
	scope: S.String,
});
export type Oauth2Clients = typeof Oauth2Clients.Type;

export const Addresses = S.Struct({
	id: Uuid,
	owner_id: Uuid, // polymorphic — a user sub OR a business b_id; stays plain Uuid
	address_type: varchar(50), // free VARCHAR(50) at the DB; app narrows to ADDRESS_TYPE in a projection
	street: varchar(255),
	unit: S.NullOr(varchar(100)),
	city: S.NullOr(varchar(100)),
	state: S.NullOr(varchar(100)),
	zip: S.NullOr(varchar(20)),
	country: S.NullOr(varchar(100)),
	name: S.NullOr(varchar(255)),
	icon: varchar(50),
	is_default: S.Boolean,
	coord: S.NullOr(S.Tuple([S.Number, S.Number])), // POINT → [lat, lng]
	updated: S.Date,
});
export type Addresses = typeof Addresses.Type;

export const BAccess = S.Struct({
	sub: UserSub,
	b_id: Uuid,
	b_role: S.String,
	is_default: S.Boolean,
});
export type BAccess = typeof BAccess.Type;

export const AffiliateCommissions = S.Struct({
	invoice_id: varchar(255),
	referrer_sub: UserSub,
	amount: S.Number,
	transfer_id: varchar(255),
	paid_at: S.Date,
	created_at: S.Date,
});
export type AffiliateCommissions = typeof AffiliateCommissions.Type;

// =============================================================================
// PER-APP USER EXTENSION TABLES
// =============================================================================

export const CrescutsUsers = S.Struct({
	sub: UserSub,
	pref_email: S.Boolean,
	pref_sms: S.Boolean,
	tz: TIMEZONE,
	military: S.Boolean,
	start_of_week: S.Boolean,
	stripe_customer_id: S.NullOr(varchar(255)),
	stripe_subscription_id: S.NullOr(varchar(255)),
	membership_interval: S.NullOr(S.Literals(['month', 'year'])), // CHECK (… IN ('month','year'))
	membership_period_end: S.NullOr(S.Date),
	membership_will_renew: S.Boolean,
	is_uga_student: S.Boolean,
	dob: S.NullOr(S.Date),
	grad_date: S.NullOr(S.Date),
	updated: S.Date,
});
export type CrescutsUsers = typeof CrescutsUsers.Type;

export const PolumeyvPros = S.Struct({
	sub: UserSub,
	pref_email: S.Boolean,
	pref_sms: S.Boolean,
	tz: TIMEZONE,
	military: S.Boolean,
	start_of_week: S.Boolean,
	updated: S.Date,
});
export type PolumeyvPros = typeof PolumeyvPros.Type;

export const CresendsUsers = S.Struct({
	sub: UserSub,
	email_alerts: S.Boolean,
	weekly_report: S.Boolean,
	marketing_emails: S.Boolean,
	referred_by: S.NullOr(UserSub),
	forwarding_urls: S.NullOr(S.Array(S.String)),
	updated: S.Date,
});
export type CresendsUsers = typeof CresendsUsers.Type;

// =============================================================================
// LOOKUP TABLES (seeded; `name` holds the value-set literals above)
// =============================================================================

export const BTypes = S.Struct({ id: S.Number, name: B_TYPE });
export type BTypes = typeof BTypes.Type;

export const ClientStatuses = S.Struct({ id: S.Number, name: CLIENT_STATUS });
export type ClientStatuses = typeof ClientStatuses.Type;

export const ServiceTypes = S.Struct({ id: S.Number, name: SERVICE_TYPE });
export type ServiceTypes = typeof ServiceTypes.Type;

export const BookingStatuses = S.Struct({ id: S.Number, name: BOOKING_STATUS });
export type BookingStatuses = typeof BookingStatuses.Type;

export const PayoutSchedules = S.Struct({ id: S.Number, name: PAYOUT_SCHEDULE });
export type PayoutSchedules = typeof PayoutSchedules.Type;

export const Categories = S.Struct({ id: S.Number, name: SERVICE_CATEGORY });
export type Categories = typeof Categories.Type;

// =============================================================================
// BUSINESS CORE
// =============================================================================

export const Businesses = S.Struct({
	b_id: Uuid,
	owner_sub: UserSub,
	legal_name: varchar(255),
	dba: S.NullOr(varchar(255)),
	tax_id: S.NullOr(varchar(100)),
	license_number: S.NullOr(varchar(255)),
	b_type: S.Number, // INT REFERENCES b_types(id)
	website: S.NullOr(varchar(500)),
	phone: S.NullOr(varchar(50)),
	email: S.NullOr(varchar(255)),
	tz: TIMEZONE,
	status: S.Number, // SMALLINT bitfield: IS_ACTIVE=1, IS_VERIFIED=2, IS_FEATURED=4, IS_SUSPENDED=8
	source: varchar(20),
	listing_id: S.NullOr(varchar(100)),
	verified_at: S.NullOr(S.Date),
	stripe_account_id: S.NullOr(varchar(255)),
	// Booking settings
	allow_online: S.Boolean,
	require_deposit: S.Boolean,
	auto_confirm: S.Boolean,
	require_payment: S.Boolean,
	allow_walkins: S.Boolean,
	send_reminders: S.Boolean,
	allow_cancel: S.Boolean,
	allow_reschedule: S.Boolean,
	deposit_amount: S.Number, // cents
	deposit_is_fixed: S.Boolean,
	cancellation_deadline_hours: S.Number,
	max_advance_value: S.Number,
	max_advance_in_hours: S.Boolean,
	min_advance_value: S.Number,
	min_advance_in_hours: S.Boolean,
	buf: S.Number,
	reminder_hours: S.Number,
	cancellation_policy: S.NullOr(S.String),
	// Financial settings
	tax_enabled: S.Boolean,
	tax_included: S.Boolean,
	tips_enabled: S.Boolean,
	tips_custom: S.Boolean,
	refunds_enabled: S.Boolean,
	refunds_partial: S.Boolean,
	tax_rate: S.Number, // DECIMAL(5,3); read sites cast ::float8 → number
	tip_percentages: S.Array(S.Number), // SMALLINT[]
	refund_deadline_days: S.Number,
	refund_percentage: S.Number,
	payout_schedule: S.Number, // SMALLINT REFERENCES payout_schedules(id)
	minimum_payout: S.Number, // cents
	platform_fee_bps: S.Number, // basis points withheld via application_fee_amount
	charges_enabled: S.Boolean, // cached from Stripe account.updated
	onboarding_complete: S.Boolean, // cached from Stripe account.updated
	payouts_enabled: S.Boolean, // cached from Stripe account.updated
	updated: S.Date,
});
export type Businesses = typeof Businesses.Type;

export const Hours = S.Struct({
	id: Uuid,
	b_id: Uuid,
	week_day: S.Number.check(S.isBetween({ minimum: 1, maximum: 7 })), // CHECK (week_day BETWEEN 1 AND 7)
	// JSONB array of open ranges `{ start: "HH:MM", dur: "PT<minutes>M" }`; gaps are breaks. CHECK enforces array + length ≤ 6.
	ranges: S.Array(TimeRangeS).check(S.isMaxLength(6)),
	updated: S.Date,
});
export type Hours = typeof Hours.Type;

export const Services = S.Struct({
	id: Uuid,
	b_id: Uuid,
	category_id: S.NullOr(S.Number), // INT REFERENCES categories(id)
	type: S.Number, // SMALLINT REFERENCES service_types(id)
	name: varchar(255),
	descr: S.NullOr(S.String),
	amount: S.NullOr(S.Number), // cents (column is nullable — no NOT NULL)
	dur: S.NullOr(S.Number),
	buf: S.Number,
	active: S.Boolean,
	updated: S.Date,
});
export type Services = typeof Services.Type;

export const Products = S.Struct({
	id: Uuid,
	b_id: Uuid,
	name: varchar(255),
	descr: S.NullOr(S.String),
	price: S.NullOr(S.Number), // cents
	stock: S.NullOr(S.Number), // NULL = stock not tracked
	active: S.Boolean,
	updated: S.Date,
});
export type Products = typeof Products.Type;

export const Clients = S.Struct({
	client_id: Uuid,
	b_id: Uuid,
	sub: S.NullOr(UserSub),
	f_name: S.NullOr(varchar(100)),
	l_name: S.NullOr(varchar(100)),
	email: S.NullOr(varchar(255)),
	phone: S.NullOr(varchar(50)),
	company: S.NullOr(varchar(255)),
	status: S.Number, // SMALLINT REFERENCES client_statuses(id)
	notes: S.NullOr(S.String),
	tags: S.NullOr(S.Array(S.String)),
	updated: S.Date,
});
export type Clients = typeof Clients.Type;

export const ProUnavailability = S.Struct({
	id: Uuid,
	b_id: Uuid,
	pro_id: S.NullOr(Uuid),
	time_slot: S.String, // TSTZRANGE
	reason: S.NullOr(S.String),
});
export type ProUnavailability = typeof ProUnavailability.Type;

export const Bookings = S.Struct({
	id: Uuid,
	b_id: Uuid,
	sub: S.NullOr(UserSub), // NULL while held (no guest row yet); set on confirm
	service_id: Uuid,
	pro_id: S.NullOr(Uuid),
	customer_email: S.NullOr(varchar(255)),
	customer_phone: S.NullOr(varchar(50)),
	data: S.Record(S.String, S.Unknown), // held: collected contact fields { fn, ln, em, ph, … }; consumed into the guest on confirm
	cs_id: S.NullOr(varchar(255)), // held: Stripe CheckoutSession id
	time_slot: S.String, // TSTZRANGE
	status: S.Number, // SMALLINT REFERENCES booking_statuses(id)
	amount: S.Number, // cents
	notes: S.NullOr(S.String),
	cancellation_reason: S.NullOr(S.String),
	cancelled_by: S.NullOr(UserSub),
	cancelled: S.NullOr(S.Date),
	completed: S.NullOr(S.Date),
	payment_intent_id: S.NullOr(varchar(255)),
	payment_status: varchar(32), // 'none' | Stripe PI status | 'refunded' | 'disputed'
	platform_fee_amount: S.NullOr(S.Number), // cents
	transfer_id: S.NullOr(varchar(255)),
	updated: S.Date,
	reminder_sent_at: S.NullOr(S.Date), // added via ALTER TABLE
});
export type Bookings = typeof Bookings.Type;

export const StripeCustomers = S.Struct({
	sub: UserSub,
	stripe_customer_id: varchar(255),
});
export type StripeCustomers = typeof StripeCustomers.Type;

// =============================================================================
// GUESTS
// (Booking holds are no longer a separate table — a hold is a `bookings` row with status `held`; see `Bookings` above.)
// =============================================================================

export const Guests = S.Struct({
	guest_id: Uuid,
	email: varchar(255),
	phone: S.NullOr(varchar(50)),
	f_name: S.NullOr(varchar(100)),
	l_name: S.NullOr(varchar(100)),
	booking_count: S.Number,
	last_booking: S.NullOr(S.Date),
	updated: S.Date,
});
export type Guests = typeof Guests.Type;

// =============================================================================
// VIEW: bookings_v (status as name, range bounds as text, joined service dur)
// =============================================================================

export const BookingsV = S.Struct({
	id: Uuid,
	b_id: Uuid,
	sub: UserSub,
	service_id: Uuid,
	pro_id: S.NullOr(Uuid),
	customer_email: S.NullOr(varchar(255)),
	customer_phone: S.NullOr(varchar(50)),
	time_slot: S.String,
	status: S.NullOr(BOOKING_STATUS), // bs.name via LEFT JOIN booking_statuses
	amount: S.Number,
	notes: S.NullOr(S.String),
	cancellation_reason: S.NullOr(S.String),
	cancelled_by: S.NullOr(UserSub),
	cancelled: S.NullOr(S.Date),
	completed: S.NullOr(S.Date),
	updated: S.Date,
	start_time: S.String, // lower(time_slot)::text
	end_time: S.String, // upper(time_slot)::text
	dur: S.NullOr(S.Number), // s.dur via LEFT JOIN services
});
export type BookingsV = typeof BookingsV.Type;

// =============================================================================
// cresends.* (PowerDNS + cresends dashboard). Managed largely by PowerDNS;
// JSONB blobs are left as `S.Unknown` since no app-side shape is fixed.
// =============================================================================

export const CustomSequencers = S.Struct({
	id: Uuid,
	sub: UserSub,
	name: varchar(50),
	columns: S.Array(S.Unknown), // JSONB NOT NULL DEFAULT '[]'
	format: varchar(4),
	created_at: S.NullOr(S.Date),
});
export type CustomSequencers = typeof CustomSequencers.Type;

export const Domains = S.Struct({
	id: S.Number, // SERIAL
	name: varchar(255),
	master: S.NullOr(varchar(128)),
	last_check: S.NullOr(S.Number),
	type: S.String,
	notified_serial: S.NullOr(S.Number), // BIGINT
	account: S.NullOr(varchar(40)),
	options: S.NullOr(S.String),
	catalog: S.NullOr(S.String),
	sub: S.NullOr(UserSub),
	provider: CRESENDS_PROVIDER_TYPE,
	registrar: S.NullOr(varchar(50)),
	registrar_domain_id: S.NullOr(varchar(255)),
	ms_verification_txt: S.NullOr(varchar(255)),
	expires_at: S.NullOr(S.Date),
	display_names: S.NullOr(S.Array(S.Unknown)), // JSONB DEFAULT '[]'
	mailboxes: S.NullOr(S.Array(S.Unknown)), // JSONB DEFAULT '[]'
	ns_check: S.NullOr(S.Unknown), // JSONB DEFAULT NULL
	provisioned: S.NullOr(S.Boolean), // no NOT NULL
	created_at: S.NullOr(S.Date),
});
export type Domains = typeof Domains.Type;

export const Records = S.Struct({
	id: S.Number, // BIGSERIAL
	domain_id: S.NullOr(S.Number),
	name: S.NullOr(varchar(255)),
	type: S.NullOr(varchar(10)),
	content: S.NullOr(varchar(65535)),
	ttl: S.NullOr(S.Number),
	prio: S.NullOr(S.Number),
	disabled: S.NullOr(S.Boolean),
	ordername: S.NullOr(varchar(255)),
	auth: S.NullOr(S.Boolean),
});
export type Records = typeof Records.Type;

export const DomainMetadata = S.Struct({
	id: S.Number,
	domain_id: S.NullOr(S.Number),
	kind: S.NullOr(varchar(32)),
	content: S.NullOr(S.String),
});
export type DomainMetadata = typeof DomainMetadata.Type;

export const Cryptokeys = S.Struct({
	id: S.Number,
	domain_id: S.NullOr(S.Number),
	flags: S.Number,
	active: S.NullOr(S.Boolean),
	published: S.NullOr(S.Boolean),
	content: S.NullOr(S.String),
});
export type Cryptokeys = typeof Cryptokeys.Type;

export const Tsigkeys = S.Struct({
	id: S.Number,
	name: S.NullOr(varchar(255)),
	algorithm: S.NullOr(varchar(50)),
	secret: S.NullOr(varchar(255)),
});
export type Tsigkeys = typeof Tsigkeys.Type;

export const Comments = S.Struct({
	id: S.Number,
	domain_id: S.NullOr(S.Number),
	name: varchar(255),
	type: varchar(10),
	modified_at: S.Number,
	account: S.NullOr(varchar(40)),
	comment: S.String,
});
export type Comments = typeof Comments.Type;

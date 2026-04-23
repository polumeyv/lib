import { Schema } from 'effect';

// Shared schemas
export const slug = Schema.String.pipe(
	Schema.minLength(1),
	Schema.maxLength(100),
	Schema.pattern(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
);

// Enums
export const B_TYPE = Schema.Literal('salon', 'barbershop', 'spa', 'nails', 'esthetics', 'makeup', 'tattoo', 'other');
export type BType = typeof B_TYPE.Type;

export const CLIENT_STATUS = Schema.Literal('active', 'inactive', 'vip', 'new', 'at_risk');
export type ClientStatus = typeof CLIENT_STATUS.Type;

export const SERVICE_TYPE = Schema.Literal('service', 'addon');
export type ServiceType = typeof SERVICE_TYPE.Type;

export const AVAILABILITY_TYPE = Schema.Literal('recurring', 'specific_date', 'flexible', 'blocked');
export type AvailabilityType = typeof AVAILABILITY_TYPE.Type;

export const SLOT_STATUS = Schema.Literal('available', 'booked', 'blocked', 'unavailable', 'held', 'cancelled', 'completed');
export type SlotStatus = typeof SLOT_STATUS.Type;

export const BOOKING_STATUS = Schema.Literal('pending', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show');
export type BookingStatus = typeof BOOKING_STATUS.Type;

export const REVIEW_STATUS = Schema.Literal('active', 'deleted', 'hidden');
export type ReviewStatus = typeof REVIEW_STATUS.Type;

export const MODERATION_STATUS = Schema.Literal('pending', 'approved', 'rejected');
export type ModerationStatus = typeof MODERATION_STATUS.Type;

export const PAYOUT_SCHEDULE = Schema.Literal('daily', 'weekly', 'biweekly', 'monthly');
export type PayoutSchedule = typeof PAYOUT_SCHEDULE.Type;

export const SUBSCRIPTION_STATUS = Schema.Literal('trialing', 'active', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', 'unpaid', 'paused');
export type SubscriptionStatus = typeof SUBSCRIPTION_STATUS.Type;

export const SUBSCRIPTION_TIER = Schema.Literal('starter', 'professional', 'enterprise');
export type SubscriptionTier = typeof SUBSCRIPTION_TIER.Type;

export const TEAM_ROLE = Schema.Literal('staff', 'manager', 'owner');
export type TeamRole = typeof TEAM_ROLE.Type;

export const BUSINESS_CATEGORY = Schema.Literal('hair', 'nails', 'skin', 'body', 'grooming', 'makeup', 'wellness', 'advanced', 'other');
export type BusinessCategory = typeof BUSINESS_CATEGORY.Type;

export const CALENDAR_EVENT_TYPE = Schema.Literal('appointment', 'blocked', 'break', 'event');
export type CalendarEventType = typeof CALENDAR_EVENT_TYPE.Type;

export const APPOINTMENT_LABEL = Schema.Literal('vip', 'new_client', 'recurring', 'first_time', 'priority', 'follow_up', 'consultation', 'walk_in');
export type AppointmentLabel = typeof APPOINTMENT_LABEL.Type;

export const PAYOUT_STATUS = Schema.Literal('pending', 'in_transit', 'paid', 'failed', 'cancelled');
export type PayoutStatus = typeof PAYOUT_STATUS.Type;

export const BANK_ACCOUNT_TYPE = Schema.Literal('checking', 'savings');
export type BankAccountType = typeof BANK_ACCOUNT_TYPE.Type;

export const NOTIFICATION_TYPE = Schema.Literal(
	'booking_created',
	'booking_confirmation',
	'booking_confirmed',
	'booking_cancellation',
	'booking_cancelled',
	'booking_completed',
	'booking_rescheduled',
	'booking_no_show',
	'booking_reminder',
	'review_created',
	'review_thankyou',
	'review_response',
	'review_request',
	'business_update',
	'business_approved',
	'business_rejected',
	'payment_received',
	'payment_confirmation',
	'payment_failed',
	'subscription_created',
	'subscription_cancelled',
	'service_update',
	'system_announcement',
	'welcome',
	'promotional',
	'alert',
	'custom',
);
export type NotificationType = typeof NOTIFICATION_TYPE.Type;

export const SERVICE_CATEGORY = Schema.Literal('haircut', 'color', 'styling', 'treatment', 'extension', 'nails', 'wax', 'facial', 'makeup', 'massage', 'other');
export type ServiceCategory = typeof SERVICE_CATEGORY.Type;

// Display names
export const BUSINESS_CATEGORY_INFO: Record<BusinessCategory, { name: string; description: string }> = {
	hair: { name: 'Hair Care', description: 'Cuts, color, treatments' },
	nails: { name: 'Nail Services', description: 'Manicure, pedicure, nail art' },
	skin: { name: 'Skin Care', description: 'Facials, peels, treatments' },
	body: { name: 'Body Care', description: 'Massages, scrubs, waxing' },
	grooming: { name: 'Grooming', description: 'Brows, lashes, beard' },
	makeup: { name: 'Makeup', description: 'Application, lessons' },
	wellness: { name: 'Wellness', description: 'Aromatherapy, reflexology' },
	advanced: { name: 'Advanced', description: 'Microneedling, LED therapy' },
	other: { name: 'Other', description: 'Other services' },
};

/** All business categories with their info for UI display */
export const BUSINESS_CATEGORIES = BUSINESS_CATEGORY.literals.map((c) => BUSINESS_CATEGORY_INFO[c]);

// Business Core
export const ProBusinesses = Schema.Struct({
	b_id: Schema.String,
	owner_sub: Schema.String,
	legal_name: Schema.String,
	dba: Schema.optional(Schema.String),
	descr: Schema.optional(Schema.String),
	tax_id: Schema.NullOr(Schema.String),
	license_number: Schema.NullOr(Schema.String),
	b_type: B_TYPE,
	website: Schema.optional(Schema.String),
	phone: Schema.optional(Schema.String),
	email: Schema.optional(Schema.String),
	slug,
	status: Schema.Number,
	verified_at: Schema.NullOr(Schema.DateFromSelf),
	stripe_account_id: Schema.NullOr(Schema.String), // Stripe Connect account ID (acct_xxx)
	updated: Schema.DateFromSelf,
});
export type ProBusinessesType = typeof ProBusinesses.Type;

export const ProBookingSettings = Schema.Struct({
	b_id: Schema.String,
	allow_online: Schema.Boolean,
	require_deposit: Schema.Boolean,
	auto_confirm: Schema.Boolean,
	require_payment: Schema.Boolean,
	allow_walkins: Schema.Boolean,
	send_reminders: Schema.Boolean,
	allow_cancel: Schema.Boolean,
	allow_reschedule: Schema.Boolean,
	deposit_amount: Schema.Number, // cents
	deposit_is_fixed: Schema.Boolean,
	cancellation_deadline_hours: Schema.Number,
	max_advance_days: Schema.Number,
	min_advance_hours: Schema.Number,
	buf: Schema.Number,
	reminder_hours: Schema.Number,
	cancellation_policy: Schema.optional(Schema.String),
	updated: Schema.DateFromSelf,
});
export type ProBookingSettingsType = typeof ProBookingSettings.Type;

export const ProFinancialSettings = Schema.Struct({
	b_id: Schema.String,
	tax_enabled: Schema.Boolean,
	tax_included: Schema.Boolean,
	tips_enabled: Schema.Boolean,
	tips_custom: Schema.Boolean,
	refunds_enabled: Schema.Boolean,
	refunds_partial: Schema.Boolean,
	currency: Schema.String,
	tax_rate: Schema.Number,
	tip_percentages: Schema.mutable(Schema.Array(Schema.Number)),
	invoice_prefix: Schema.String,
	invoice_next: Schema.Number,
	invoice_due_days: Schema.Number,
	invoice_notes: Schema.optional(Schema.String),
	refund_deadline_days: Schema.Number,
	payout_schedule: PAYOUT_SCHEDULE,
	minimum_payout: Schema.Number, // cents
	updated: Schema.DateFromSelf,
});
export type ProFinancialSettingsType = typeof ProFinancialSettings.Type;

export const ProAddresses = Schema.Struct({
	owner_id: Schema.String,
	address_type: Schema.String,
	street: Schema.String,
	unit: Schema.NullOr(Schema.String),
	city: Schema.NullOr(Schema.String),
	state: Schema.NullOr(Schema.String),
	zip: Schema.NullOr(Schema.String),
	country: Schema.NullOr(Schema.String),
	name: Schema.NullOr(Schema.String),
	is_default: Schema.Boolean,
	coord: Schema.NullOr(Schema.Tuple(Schema.Number, Schema.Number)), // [lat, lng]
	updated: Schema.DateFromSelf,
});
export type ProAddressesType = typeof ProAddresses.Type;

export const ProHours = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	week_day: Schema.Number,
	open_time: Schema.NullOr(Schema.String),
	close_time: Schema.NullOr(Schema.String),
	closed: Schema.Boolean,
	break_start: Schema.NullOr(Schema.String),
	break_end: Schema.NullOr(Schema.String),
	updated: Schema.DateFromSelf,
});
export type ProHoursType = typeof ProHours.Type;

// Services / Catalog
export const ProServices = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	category_id: Schema.NullOr(Schema.Number),
	type: SERVICE_TYPE,
	name: Schema.String,
	descr: Schema.NullOr(Schema.String),
	amount: Schema.Number, // cents
	dur: Schema.Number,
	buf: Schema.NullOr(Schema.Number),
	active: Schema.Boolean,
	updated: Schema.DateFromSelf,
});
export type ProServicesType = typeof ProServices.Type;

// Clients
export const ProClients = Schema.Struct({
	client_id: Schema.String,
	b_id: Schema.String,
	sub: Schema.NullOr(Schema.String),
	f_name: Schema.String,
	l_name: Schema.optional(Schema.String),
	email: Schema.optional(Schema.String),
	phone: Schema.optional(Schema.String),
	company: Schema.optional(Schema.String),
	status: CLIENT_STATUS,
	notes: Schema.optional(Schema.String),
	tags: Schema.optional(Schema.Array(Schema.String)),
	updated: Schema.DateFromSelf,
});
export type ProClientsType = typeof ProClients.Type;

// Availability & Time Slots
// Composite key: (b_id, pro_id, week_day, specific_date, start_time)
export const ProAvailability = Schema.Struct({
	b_id: Schema.String,
	pro_id: Schema.NullOr(Schema.String),
	type: AVAILABILITY_TYPE,
	week_day: Schema.NullOr(Schema.Number),
	specific_date: Schema.NullOr(Schema.String),
	start_time: Schema.String,
	end_time: Schema.String,
	available: Schema.Boolean,
	is_recurring: Schema.Boolean,
	reason: Schema.NullOr(Schema.String),
	notes: Schema.NullOr(Schema.String),
	updated: Schema.DateFromSelf,
});
export type ProAvailabilityType = typeof ProAvailability.Type;

export const ProTimeSlots = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	pro_id: Schema.NullOr(Schema.String),
	service_id: Schema.NullOr(Schema.String),
	time_slot: Schema.String,
	status: SLOT_STATUS,
	booked_by: Schema.NullOr(Schema.String),
	held_until: Schema.NullOr(Schema.DateFromSelf),
	unavailable_reason: Schema.NullOr(Schema.String),
	updated: Schema.DateFromSelf,
});
export type ProTimeSlotsType = typeof ProTimeSlots.Type;

// Bookings
export const ProBookings = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	sub: Schema.String,
	service_id: Schema.String,
	pro_id: Schema.NullOr(Schema.String),
	customer_email: Schema.NullOr(Schema.String),
	customer_phone: Schema.NullOr(Schema.String),
	time_slot: Schema.String,
	status: BOOKING_STATUS,
	amount: Schema.NullOr(Schema.Number), // cents
	notes: Schema.NullOr(Schema.String),
	cancellation_reason: Schema.NullOr(Schema.String),
	cancelled_by: Schema.NullOr(Schema.String),
	cancelled: Schema.NullOr(Schema.DateFromSelf),
	completed: Schema.NullOr(Schema.DateFromSelf),
	updated: Schema.DateFromSelf,
});
export type ProBookingsType = typeof ProBookings.Type;

export const ProBookingsView = Schema.extend(ProBookings, Schema.Struct({
	start_time: Schema.String,
	dur: Schema.NullOr(Schema.Number),
}));
export type ProBookingsViewType = typeof ProBookingsView.Type;

// Calendar
export const ProCalendarEvents = Schema.Struct({
	event_id: Schema.String,
	b_id: Schema.String,
	pro_id: Schema.optional(Schema.String),
	title: Schema.String,
	descr: Schema.optional(Schema.String),
	event_type: Schema.String,
	time_slot: Schema.String,
	all_day: Schema.Boolean,
	recurring_rule: Schema.optional(Schema.String),
	color: Schema.optional(Schema.String),
	updated: Schema.DateFromSelf,
});
export type ProCalendarEventsType = typeof ProCalendarEvents.Type;

export const ProCalendarEventsView = Schema.extend(ProCalendarEvents, Schema.Struct({
	start_time: Schema.String,
	end_time: Schema.String,
}));
export type ProCalendarEventsViewType = typeof ProCalendarEventsView.Type;

// Booking Page
export const ProPageTemplates = Schema.Struct({
	template_id: Schema.String,
	b_id: Schema.String,
	name: Schema.String,
	is_active: Schema.Boolean,
	primary_color: Schema.String,
	accent_color: Schema.String,
	palette_type: Schema.String,
	theme_mode: Schema.String,
	logo_url: Schema.optional(Schema.String),
	d_name: Schema.optional(Schema.String),
	descr: Schema.optional(Schema.String),
	welcome_message: Schema.optional(Schema.String),
	contact_phone: Schema.optional(Schema.String),
	contact_email: Schema.optional(Schema.String),
	instagram_url: Schema.optional(Schema.String),
	facebook_url: Schema.optional(Schema.String),
	tiktok_url: Schema.optional(Schema.String),
	website_url: Schema.optional(Schema.String),
	display_flags: Schema.Number,
	send_confirmation_email: Schema.Boolean,
	send_reminder_email: Schema.Boolean,
	send_reminder_sms: Schema.Boolean,
	require_terms_acceptance: Schema.Boolean,
	show_privacy_policy: Schema.Boolean,
	terms_url: Schema.optional(Schema.String),
	updated: Schema.DateFromSelf,
});
export type ProPageTemplatesType = typeof ProPageTemplates.Type;

export const ProBookingRoutes = Schema.Struct({
	route_id: Schema.String,
	b_id: Schema.String,
	parent_id: Schema.optional(Schema.String),
	name: Schema.String,
	slug,
	descr: Schema.optional(Schema.String),
	is_active: Schema.Boolean,
	sort_order: Schema.Number,
	updated: Schema.DateFromSelf,
});
export type ProBookingRoutesType = typeof ProBookingRoutes.Type;

// Reviews
export const ProReviews = Schema.Struct({
	review_id: Schema.String,
	id: Schema.String,
	b_id: Schema.String,
	sub: Schema.String,
	customer_email: Schema.NullOr(Schema.String),
	rating: Schema.Number,
	comment: Schema.NullOr(Schema.String),
	response: Schema.NullOr(Schema.String),
	response_date: Schema.NullOr(Schema.DateFromSelf),
	verified: Schema.Boolean,
	status: REVIEW_STATUS,
	moderation_status: MODERATION_STATUS,
	moderation_notes: Schema.NullOr(Schema.String),
	moderated_by: Schema.NullOr(Schema.String),
	moderated: Schema.NullOr(Schema.DateFromSelf),
	updated: Schema.DateFromSelf,
});
export type ProReviewsType = typeof ProReviews.Type;

export const ProReviewVotes = Schema.Struct({
	review_id: Schema.String,
	sub: Schema.String,
	helpful: Schema.Boolean,
});
export type ProReviewVotesType = typeof ProReviewVotes.Type;

// Subscriptions
export const ProSubscriptionPlans = Schema.Struct({
	id: Schema.String,
	stripe_price_id: Schema.String,
	tier: SUBSCRIPTION_TIER,
	amount: Schema.Number, // cents
	currency: Schema.String,
	yearly: Schema.Boolean,
	trial_days: Schema.Number,
	is_active: Schema.Boolean,
});
export type ProSubscriptionPlansType = typeof ProSubscriptionPlans.Type;

export const ProSubscriptions = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	stripe_subscription_id: Schema.String,
	plan_id: Schema.String,
	status: SUBSCRIPTION_STATUS,
	current_period_end: Schema.NullOr(Schema.DateFromSelf),
	cancel_at_period_end: Schema.Boolean,
	canceled_at: Schema.NullOr(Schema.DateFromSelf),
});
export type ProSubscriptionsType = typeof ProSubscriptions.Type;

/** Subscription with joined plan and status data */
export const ProSubscriptionsView = Schema.extend(ProSubscriptions, Schema.Struct({
	tier_name: SUBSCRIPTION_TIER,
	plan_name: Schema.String,
	amount: Schema.Number, // cents
	yearly: Schema.Boolean,
}));
export type ProSubscriptionsViewType = typeof ProSubscriptionsView.Type;

export const ProStripeCustomers = Schema.Struct({
	sub: Schema.String,
	stripe_customer_id: Schema.String,
});
export type ProStripeCustomersType = typeof ProStripeCustomers.Type;

// Team Management
export const ProTeamMembers = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	sub: Schema.NullOr(Schema.String),
	email: Schema.String,
	f_name: Schema.optional(Schema.String),
	l_name: Schema.optional(Schema.String),
	phone: Schema.optional(Schema.String),
	role: TEAM_ROLE,
	title: Schema.optional(Schema.String),
	bio: Schema.optional(Schema.String.pipe(Schema.maxLength(400))),
	color: Schema.optional(Schema.String),
	is_active: Schema.Boolean,
	can_receive_bookings: Schema.Boolean,
	commission_rate: Schema.optional(Schema.Number),
	hourly_rate: Schema.optional(Schema.Number), // cents
	updated: Schema.DateFromSelf,
});
export type ProTeamMembersType = typeof ProTeamMembers.Type;

export const ProTeamInvites = Schema.Struct({
	invite_id: Schema.String,
	b_id: Schema.String,
	email: Schema.String,
	role: TEAM_ROLE,
	invited_by: Schema.String,
	token: Schema.String,
	expires: Schema.DateFromSelf,
});
export type ProTeamInvitesType = typeof ProTeamInvites.Type;

export const ProTeamSchedules = Schema.Struct({
	id: Schema.String,
	member_id: Schema.String,
	b_id: Schema.String,
	week_day: Schema.Number,
	start_time: Schema.NullOr(Schema.String),
	end_time: Schema.NullOr(Schema.String),
	is_available: Schema.Boolean,
	break_start: Schema.NullOr(Schema.String),
	break_end: Schema.NullOr(Schema.String),
	updated: Schema.DateFromSelf,
});
export type ProTeamSchedulesType = typeof ProTeamSchedules.Type;

export const ProTeamTimeOff = Schema.Struct({
	id: Schema.String,
	member_id: Schema.String,
	b_id: Schema.String,
	start_date: Schema.String,
	end_date: Schema.String,
	reason: Schema.NullOr(Schema.String),
	approved: Schema.Boolean,
	approved_by: Schema.NullOr(Schema.String),
});
export type ProTeamTimeOffType = typeof ProTeamTimeOff.Type;

export const ProTeamServices = Schema.Struct({
	member_id: Schema.String,
	service_id: Schema.String,
	custom_price: Schema.NullOr(Schema.Number), // cents
	custom_duration: Schema.NullOr(Schema.Number),
	is_active: Schema.Boolean,
});
export type ProTeamServicesType = typeof ProTeamServices.Type;

// Analytics & Settings
export const ProAnalyticsCache = Schema.Struct({
	b_id: Schema.String,
	period: Schema.String,
	data: Schema.Record({ key: Schema.String, value: Schema.Unknown }),
	computed: Schema.DateFromSelf,
	expires: Schema.DateFromSelf,
});
export type ProAnalyticsCacheType = typeof ProAnalyticsCache.Type;

export const ProNotificationSettings = Schema.Struct({
	b_id: Schema.String,
	email_new_booking: Schema.Boolean,
	email_booking_cancelled: Schema.Boolean,
	email_booking_reminder: Schema.Boolean,
	email_review_received: Schema.Boolean,
	email_daily_summary: Schema.Boolean,
	email_weekly_report: Schema.Boolean,
	sms_new_booking: Schema.Boolean,
	sms_booking_cancelled: Schema.Boolean,
	push_enabled: Schema.Boolean,
	quiet_hours_start: Schema.NullOr(Schema.String),
	quiet_hours_end: Schema.NullOr(Schema.String),
	updated: Schema.DateFromSelf,
});
export type ProNotificationSettingsType = typeof ProNotificationSettings.Type;

export const ProNotifications = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	type: NOTIFICATION_TYPE,
	title: Schema.String,
	message: Schema.String,
	action_url: Schema.NullOr(Schema.String),
	read: Schema.Boolean,
});
export type ProNotificationsType = typeof ProNotifications.Type;

export const ProSavedViews = Schema.Struct({
	view_id: Schema.String,
	b_id: Schema.String,
	sub: Schema.String,
	view_type: Schema.String,
	name: Schema.String,
	filters: Schema.Record({ key: Schema.String, value: Schema.Unknown }),
	is_default: Schema.Boolean,
	updated: Schema.DateFromSelf,
});
export type ProSavedViewsType = typeof ProSavedViews.Type;

export const ProActivityLog = Schema.Struct({
	id: Schema.String,
	b_id: Schema.String,
	sub: Schema.NullOr(Schema.String),
	action: Schema.String,
	entity_type: Schema.NullOr(Schema.String),
	entity_id: Schema.NullOr(Schema.String),
	details: Schema.NullOr(Schema.Record({ key: Schema.String, value: Schema.Unknown })),
	ip_address: Schema.NullOr(Schema.String),
});
export type ProActivityLogType = typeof ProActivityLog.Type;


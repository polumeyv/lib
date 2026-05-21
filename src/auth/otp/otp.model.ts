import { Data, Schema } from 'effect';
import { BaseUser, UserSub } from '../model';
import { Email } from '@polumeyv/lib/public/types';

/** Branded string representing an AES-GCM encrypted, base64url-encoded verify token. */
export const SealedToken = Schema.String.pipe(Schema.brand('SealedToken'));

export const InputEmailSchema = Schema.Struct({ email: Email });

export const makeOtpSchema = (codeLen: number) =>
	Schema.Struct({
		email: Email,
		token: SealedToken,
		code: Schema.Union(
			Schema.Literal('resend_'),
			Schema.String.pipe(Schema.pattern(new RegExp(`^\\d{${codeLen}}$`), { message: () => `Code must be ${codeLen} digits` })),
		),
	});

/**
 * Tagged return for an OTP session state.
 *  - `token`: the sealed verify token. `null` is the OIDC signal — the email is already linked to an
 *    OIDC provider, so the OTP step is skipped and the caller routes to the link flow instead of
 *    code entry. A session is never returned tokenless for any other reason (cooldown / max-sends
 *    states still carry a real or sentinel token), so `token === null` uniquely means "has OIDC".
 *  - `countdown`: resend cooldown in seconds — `null` = ready to send, `-1` = max sends reached,
 *    positive = still cooling down.
 */
export class OtpSession extends Data.TaggedClass('OtpSession')<{
	token: typeof SealedToken.Type | null;
	email: typeof Email.Type;
	countdown: number | null;
	hasOidc: boolean;
}> {}

/** Successful OTP verification. `sub` is `null` for a brand-new email (no `users` row yet) — the
 *  caller starts signup; a real `sub` means an existing user and the caller establishes a session. */
export class AuthenticatedUser extends Data.TaggedClass('AuthenticatedUser')<{ sub: typeof UserSub.Type | null; email: typeof Email.Type; link: boolean }> {}

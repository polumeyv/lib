import { Context, Effect, Layer, Data } from 'effect';
import { Postgres } from './postgres';
import type { Email, UserSub, UserName, UserIdentity } from '@polumeyv/lib/schemas';

// shared
export type UserLookup = Data.TaggedEnum<{
	Absent: {}; // no user → fresh signup
	PermLocked: {}; // user exists, locked out
	Found: { sub: UserSub; has_oidc: boolean }; // user, not locked
}>;
export const { Absent, PermLocked, Found, $match: matchLookup } = Data.taggedEnum<UserLookup>();

export class BaseUserRepository extends Context.Service<BaseUserRepository>()('BaseUserRepository', {
	make: Effect.gen(function* () {
		const pg = yield* Postgres;

		// A name is a single indexed point lookup — not worth caching, so read straight from Postgres.
		const getName = (sub: UserSub) =>
			pg.one((sql) => sql<UserName[]>`SELECT f_name, l_name FROM users WHERE sub = ${sub}`);

		const updateName = (sub: UserSub, data: UserName) => pg.use((sql) => sql`UPDATE users SET ${sql(data)} WHERE sub = ${sub}`);

		return {
			getName,
			updateName,
			lookupUser: (email: Email) =>
				pg
					.one(
						(sql) => sql<(UserIdentity & { locked: boolean; has_oidc: boolean })[]>`
				SELECT u.sub, u.locked, oa.sub IS NOT NULL AS has_oidc
				FROM users u LEFT JOIN oidc_accounts oa ON oa.sub = u.sub
				WHERE u.email = ${email}`,
					)
					.pipe(
						Effect.map(({ locked, sub, has_oidc }) => (locked ? PermLocked() : Found({ sub, has_oidc }))),
						Effect.catchTag('NoSuchElementError', () => Effect.succeed(Absent())),
					),

			lockUser: (sub: UserSub) => Effect.asVoid(pg.use((sql) => sql`UPDATE users SET locked = TRUE WHERE sub = ${sub}`)),
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make);
}

import { Context, Effect, Layer, Array as Arr, Data, Option } from 'effect';
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
			pg
				.use((sql) => sql<UserName[]>`SELECT f_name, l_name FROM users WHERE sub = ${sub}`)
				.pipe(Effect.flatMap((rows) => Effect.fromOption(Arr.head(rows))));

		const updateName = (sub: UserSub, data: UserName) => pg.use((sql) => sql`UPDATE users SET ${sql(data)} WHERE sub = ${sub}`);

		return {
			getName,
			updateName,
			lookupUser: (email: Email) =>
				pg
					.use(
						(sql) => sql<(UserIdentity & { locked: boolean; has_oidc: boolean })[]>`
				SELECT u.sub, u.locked, oa.sub IS NOT NULL AS has_oidc
				FROM users u LEFT JOIN oidc_accounts oa ON oa.sub = u.sub
				WHERE u.email = ${email}`,
					)
					.pipe(
						Effect.map(Arr.head),
						Effect.map(
							Option.match({
								onNone: () => Absent(),
								onSome: ({ locked, sub, has_oidc }) => (locked ? PermLocked() : Found({ sub, has_oidc })),
							}),
						),
					),

			lockUser: (sub: UserSub) => Effect.asVoid(pg.use((sql) => sql`UPDATE users SET locked = TRUE WHERE sub = ${sub}`)),
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make);
}

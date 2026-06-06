import { Context, Effect, Layer, Result } from 'effect';
import { Postgres, firstOrFail } from './postgres';
import { Email, type UserSub, UserName, type AuthPayload } from '@polumeyv/lib/schemas';

export class BaseUserRepository extends Context.Service<BaseUserRepository>()('BaseUserRepository', {
	make: Effect.gen(function* () {
		const pg = yield* Postgres;

		// A name is a single indexed point lookup — not worth caching, so read straight from Postgres.
		const getName = (sub: UserSub) =>
			pg.use((sql) => sql<[typeof UserName.Type]>`SELECT f_name, l_name FROM users WHERE sub = ${sub}`).pipe(firstOrFail);

		const updateName = (sub: UserSub, data: typeof UserName.Type) =>
			pg.use((sql) => sql`UPDATE users SET ${sql(data, 'f_name', 'l_name')} WHERE sub = ${sub}`);

		return {
			getCustomerFromDb: (sub: UserSub) =>
				Effect.map(
					pg.use((sql) => sql<{ stripe_cus_id: string | null; email: string }[]>`SELECT stripe_cus_id, email FROM users WHERE sub = ${sub}`).pipe(firstOrFail),
					(row): Result.Result<string, string> => (row.stripe_cus_id != null ? Result.succeed(row.stripe_cus_id) : Result.fail(row.email)),
				),
			getName,
			updateName,
			/** Fetch the `AuthPayload` (identity + terms-accepted flag) for a `sub`. Fails `NoSuchElementError` if absent. */
			getAuthPayload: (sub: UserSub) =>
				pg.use((sql) => sql<[AuthPayload]>`SELECT sub, email, (terms_acc IS NOT NULL) AS terms_acc FROM users WHERE sub = ${sub}`).pipe(firstOrFail),

			getSubByEmail: (email: typeof Email.Type) =>
				pg.use((sql) => sql<{ sub: typeof UserSub.Type; locked: boolean }[]>`SELECT sub, locked FROM users WHERE email = ${email}`).pipe(Effect.map((r) => r[0]!)),
			getSubByEmailWithOidc: (email: typeof Email.Type) =>
				pg.use((sql) => sql<{ sub: typeof UserSub.Type; locked: boolean; has_oidc: boolean; terms_acc: boolean }[]>`
					SELECT u.sub, u.locked, oa.sub IS NOT NULL AS has_oidc, u.terms_acc IS NOT NULL AS terms_acc
					FROM users u LEFT JOIN oidc_accounts oa ON oa.sub = u.sub
					WHERE u.email = ${email}
				`).pipe(Effect.map((r) => r[0]!)),

			lockUser: (sub: UserSub) => pg.use((sql) => sql`UPDATE users SET locked = TRUE WHERE sub = ${sub}`),
			deleteBySub: (sub: UserSub) =>
				Effect.tap(
					pg.use((sql) => sql`DELETE FROM users WHERE sub = ${sub}`),
					() => Effect.annotateLogs(Effect.logWarning('Account deleted'), { sub }),
				),
		};
	}),
}) {
	static readonly layer = Layer.effect(this, this.make);
}

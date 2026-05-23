import { Effect, Schema, Either } from 'effect';
import { Postgres, Redis } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { type UserSub, UserTable, AuthPayload, UserName } from './model';

const NameJson = Schema.parseJson(UserName);
const NAME_CACHE_TTL = 84_000;

export class BaseUserRepository extends Effect.Service<BaseUserRepository>()('BaseUserRepository', {
	effect: Effect.gen(function* () {
		const pg = yield* Postgres;
		const redis = yield* Redis;

		const getName = (sub: UserSub) =>
			Effect.andThen(
				redis.use((c) => c.get(`name:${sub}`)),
				(json) =>
					json
						? Schema.decode(NameJson)(json)
						: Effect.tap(
								pg.first<[typeof UserName.Type]>((sql) => sql`SELECT f_name, l_name FROM users WHERE sub = ${sub}`, { onNull: 'fail' }),
								(data) => Effect.andThen(Schema.encode(NameJson)(data), (encoded) => redis.use((c) => c.setex(`name:${sub}`, NAME_CACHE_TTL, encoded))),
							),
			);

		const updateName = (sub: UserSub, data: typeof UserName.Type) =>
			Effect.andThen(Schema.encode(NameJson)(data), (json) =>
				Effect.all([
					pg.use((sql) => sql`UPDATE users SET ${sql(data, 'f_name', 'l_name')} WHERE sub = ${sub}`),
					redis.use((c) => c.setex(`name:${sub}`, NAME_CACHE_TTL, json)),
				]),
			);

		return {
			getCustomerFromDb: (sub: UserSub) =>
				Effect.map(
					pg.first((sql) => sql`SELECT stripe_cus_id, email FROM users WHERE sub = ${sub}`, { onNull: 'fail' }),
					(row) => Either.fromNullable(row.stripe_cus_id, () => row.email),
				),
			getName,
			updateName,
			/** Fetch the `AuthPayload` (identity + terms-accepted flag) for a `sub`. Fails `NoSuchElementException` if absent. */
			getAuthPayload: (sub: UserSub) =>
				pg.first<[typeof AuthPayload.Type]>((sql) => sql`SELECT sub, email, (terms_acc IS NOT NULL) AS terms_acc FROM users WHERE sub = ${sub}`, { onNull: 'fail' }),

			getSubByEmail: (email: typeof Email.Type) =>
				pg.first((sql) => sql<{ sub: typeof UserSub.Type; locked: boolean }[]>`SELECT sub, locked FROM users WHERE email = ${email}`),
			getSubByEmailWithOidc: (email: typeof Email.Type) =>
				pg.first(
					(sql) => sql<{ sub: typeof UserSub.Type; locked: boolean; has_oidc: boolean }[]>`
					SELECT u.sub, u.locked, oa.sub IS NOT NULL AS has_oidc
					FROM users u LEFT JOIN oidc_accounts oa ON oa.sub = u.sub
					WHERE u.email = ${email}
				`,
				),

			lockUser: (sub: UserSub) => pg.use((sql) => sql`UPDATE users SET locked = TRUE WHERE sub = ${sub}`),
			acceptTerms: (sub: UserSub) => pg.use((sql) => sql`UPDATE users SET terms_acc = NOW() WHERE sub = ${sub}`),
			deleteBySub: (sub: UserSub) =>
				Effect.tap(
					pg.use((sql) => sql`DELETE FROM users WHERE sub = ${sub}`),
					() => Effect.annotateLogs(Effect.logWarning('Account deleted'), { sub }),
				),
		};
	}),
	dependencies: [],
}) {}

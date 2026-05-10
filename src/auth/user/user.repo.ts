import { Effect, Option, Schema } from 'effect';
import { Postgres, Redis } from '@polumeyv/lib/server';
import { Email, UserName } from '@polumeyv/lib/public/types';
import { UserSub } from '../model';

const NameJson = Schema.parseJson(UserName);
const NAME_CACHE_TTL = 84_000;

export class BaseUserRepository extends Effect.Service<BaseUserRepository>()('BaseUserRepository', {
	effect: Effect.gen(function* () {
		const pg = yield* Postgres;
		const redis = yield* Redis;

		const getName = (sub: typeof UserSub.Type) =>
			Effect.andThen(
				redis.use((c) => c.get(`name:${sub}`)),
				(json) =>
					json
						? Schema.decode(NameJson)(json)
						: Effect.tap(
								Effect.andThen(
									pg.first<[typeof UserName.Type]>((sql) => sql`SELECT f_name, l_name FROM users WHERE sub = ${sub}`),
									Effect.fromNullable,
								),
								(data) => Effect.andThen(Schema.encode(NameJson)(data), (encoded) => redis.use((c) => c.setex(`name:${sub}`, NAME_CACHE_TTL, encoded))),
							),
			);

		const updateName = (sub: typeof UserSub.Type, data: typeof UserName.Type) =>
			Effect.andThen(Schema.encode(NameJson)(data), (json) =>
				Effect.all([pg.use((sql) => sql`UPDATE users SET ${sql(data, 'f_name', 'l_name')} WHERE sub = ${sub}`), redis.use((c) => c.setex(`name:${sub}`, NAME_CACHE_TTL, json))]),
			);

		return {
			getName,
			updateName,
			getSubByEmail: (email: typeof Email.Type) =>
				Effect.map(
					pg.first((sql) => sql<{ sub: typeof UserSub.Type; locked: boolean; terms_acc: Date | null }[]>`SELECT sub, locked, terms_acc FROM users WHERE email = ${email}`),
					Option.fromNullable,
				),
			getSubByEmailWithOidc: (email: typeof Email.Type) =>
				Effect.map(
					pg.first(
						(sql) => sql<{ sub: typeof UserSub.Type; locked: boolean; terms_acc: Date | null; has_oidc: boolean }[]>`
					SELECT u.sub, u.locked, u.terms_acc, oa.sub IS NOT NULL AS has_oidc
					FROM users u LEFT JOIN oidc_accounts oa ON oa.sub = u.sub
					WHERE u.email = ${email}
				`,
					),
					Option.fromNullable,
				),

			lockUser: (sub: typeof UserSub.Type) => pg.use((sql) => sql`UPDATE users SET locked = TRUE WHERE sub = ${sub}`),
			acceptTerms: (sub: typeof UserSub.Type) => pg.use((sql) => sql`UPDATE users SET terms_acc = NOW() WHERE sub = ${sub}`),
			deleteBySub: (sub: typeof UserSub.Type) =>
				Effect.tap(
					pg.use((sql) => sql`DELETE FROM users WHERE sub = ${sub}`),
					() => Effect.annotateLogs(Effect.logWarning('Account deleted'), { sub }),
				),
		};
	}),
	dependencies: [],
}) {}

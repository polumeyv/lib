import { Effect, Layer, Option } from 'effect';
import { Redis } from '@polumeyv/lib/server';
import { Email } from '@polumeyv/lib/public/types';
import { AuthConfig, AuthConfigDefaults } from '../config';
import { BaseUserRepository } from '../user/user.repo';
import { OidcAuthFlow } from '../oauth/auth-flow';
import { OtpService, OtpAlerts, OtpKeyConfig } from './otp.service';
import { HasOidc } from './otp.model';
import { UserSub } from '../model';

const EMAIL = Email.make('test@example.com');
const SUB = UserSub.make('00000000-0000-0000-0000-000000000001');

const store = new Map<string, Map<string,string>>();
const existsKeys = new Set(['has_oidc:test@example.com']);

const FakeRedis = Layer.succeed(Redis, Redis.of({
  use: ((fn: any) => {
    const client: any = {
      hgetall: (k: string) => { console.log('hgetall', k); return Promise.resolve(Object.fromEntries(store.get(k) ?? new Map())); },
      hset: () => Promise.resolve(0),
      hsetex: (k: string, _m: string, _t: number, _kw: string, n: number, ...kvs: string[]) => { console.log('hsetex', k, kvs); const h = store.get(k) ?? new Map(); for (let i=0;i<n*2;i+=2) h.set(kvs[i]!, kvs[i+1]!); store.set(k,h); return Promise.resolve('OK'); },
      unlink: () => Promise.resolve(0),
      exists: (k: string) => { const r = existsKeys.has(k) ? 1 : 0; console.log('exists', k, '=>', r); return Promise.resolve(r); },
    };
    return Effect.promise(async () => fn(client));
  }) as any
}));

const FakeUsers = Layer.succeed(BaseUserRepository, BaseUserRepository.of({
  getSubByEmail: () => { console.log('getSubByEmail'); return Effect.succeed(Option.some({ sub: SUB, locked: false, terms_acc: null })); },
  getSubByEmailWithOidc: () => { console.log('getSubByEmailWithOidc'); return Effect.succeed(Option.some({ sub: SUB, locked: false, terms_acc: null, has_oidc: true })); },
  lockUser: () => Effect.void,
} as never));

const FakeAlerts = Layer.succeed(OtpAlerts, { sendVerificationCode: () => Effect.void });
const FakeOidc = Layer.succeed(OidcAuthFlow, {} as never);

const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
const JWK_RAW = JSON.stringify(await crypto.subtle.exportKey('jwk', key));

const layer = Layer.provide(
  OtpService.DefaultWithoutDependencies,
  Layer.mergeAll(
    FakeRedis,
    FakeUsers,
    FakeAlerts,
    FakeOidc,
    Layer.succeed(AuthConfig, { ...AuthConfigDefaults, cryptoKey: 'unused' }),
    Layer.succeed(OtpKeyConfig, { raw: JWK_RAW }),
  ),
);

const result = await Effect.runPromise(Effect.scoped(Effect.provide(
  Effect.flatMap(OtpService, (otp) => otp.initAndSend(EMAIL)),
  layer,
)));

console.log('result tag:', (result as any)._tag);
console.log('is HasOidc:', result instanceof HasOidc);

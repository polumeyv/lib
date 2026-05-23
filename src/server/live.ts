/**
 * @module @polumeyv/utils/server/live
 *
 * Server-only entry exposing the Bun-runtime service factories (`makePostgres`, `makeRedis`).
 * These pull the `bun` builtin, so they live behind a dedicated entry the main `./server` barrel
 * does not re-export — keeping the barrel (and the tags it exposes) safe to import from any
 * client-reachable graph. Import this only from layer construction (`$lib/server/db.ts`, the API
 * runtime), never from `.remote.ts` or component code.
 */
export { makeRedis } from './redis.live';
export { makePostgres } from './postgres.live';
export { makeS3 } from './s3.live';

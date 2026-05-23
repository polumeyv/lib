/**
 * @module @polumeyv/utils/server/s3.live
 *
 * The Bun-runtime half of the S3 service: the `makeS3` factory that constructs a live `S3Client`.
 * Kept separate from `./s3` (which holds the bun-free `S3` tag + `S3Error`) so the tag can be imported
 * from client-reachable graphs without dragging the `bun` builtin into the client bundle. Only
 * server-only layer construction imports this entry.
 *
 * The bucket/region (and any credentials) come from the consuming app's env — passed in here, never
 * read from `$env` inside the lib.
 */
import { S3Client, type S3Options } from 'bun';
import { Effect } from 'effect';
import { S3, S3Error } from './s3';
import { makeUse } from './use';

export const makeS3 = (options: S3Options) => Effect.sync(() => S3.of({ use: makeUse(new S3Client(options), S3Error, 'S3') }));

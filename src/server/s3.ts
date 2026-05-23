/**
 * @module @polumeyv/utils/server/s3
 *
 * Effect-based S3 client using Bun's native `S3Client`.
 *
 * Exports:
 *  - `S3`      — Context tag
 *  - `S3Error` — Tagged error
 *  - `makeS3`  — Factory: `(options) => Effect<S3>` (from `./s3.live`)
 *
 * The `S3` service exposes a single `use` that runs any command against the raw client, mirroring
 * `Postgres`/`Redis`. Domain logic (avatar keys, downloads, etc.) lives in the consumer and is built
 * on top of `use`.
 *
 * @example
 * ```ts
 * const s3 = yield* S3;
 * const url = yield* s3.use((c) => c.presign('avatars/123.jpg', { method: 'PUT', expiresIn: 300 }));
 * ```
 */
import type { S3Client } from 'bun';
import { Context, Data, Effect } from 'effect';
import type { HttpStatusError } from '@polumeyv/lib/error';

export class S3Error extends Data.TaggedError('S3Error')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() {
		return 503 as const;
	}
}

interface S3Impl {
	use: <T>(fn: (client: S3Client) => T) => Effect.Effect<Awaited<T>, S3Error, never>;
}

export class S3 extends Context.Tag('S3')<S3, S3Impl>() {}

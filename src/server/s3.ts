/**
 * @module @polumeyv/utils/server/s3
 *
 * Effect-based S3 client using Bun's native `S3Client`.
 *
 * Exports:
 *  - `S3`       — Context tag
 *  - `S3Error`  — Tagged error
 *  - `makeS3`   — Factory: `(config) => Effect<S3>`
 *
 * @example
 * ```ts
 * // App layer construction
 * Layer.succeed(S3, makeS3({ accessKeyId, secretAccessKey, bucket, region }))
 *
 * // Usage in a service
 * const s3 = yield* S3;
 * yield* s3.use((c) => c.write('key', data, { type: 'image/jpeg' }));
 * yield* s3.use((c) => c.delete('key'));
 * const url = s3.presign('key', { method: 'PUT', expiresIn: 300 });
 * ```
 */
import { S3Client } from 'bun';
import { Context, Data, Effect } from 'effect';
import type { HttpStatusError } from './error';

export class S3Error extends Data.TaggedError('S3Error')<{ cause?: unknown; message?: string }> implements HttpStatusError {
	get statusCode() { return 500 as const; }
}

export interface S3Config {
	bucket: string;
	region: string;
	// Omit to let Bun's S3Client pick up creds from the AWS chain
	// (env → ~/.aws/credentials → EC2 instance profile / IMDS).
	accessKeyId?: string;
	secretAccessKey?: string;
}

interface S3Impl {
	use: <T>(fn: (client: InstanceType<typeof S3Client>) => T) => Effect.Effect<Awaited<T>, S3Error, never>;
	presign: InstanceType<typeof S3Client>['presign'];
}

export class S3 extends Context.Tag('S3')<S3, S3Impl>() {}

export const makeS3 = (config: S3Config) => {
	const client = new S3Client(config);
	return S3.of({
		use: (fn) =>
			Effect.flatMap(
				Effect.try({
					try: () => fn(client),
					catch: (e) => new S3Error({ cause: e, message: 'Synchronous Error in S3.use' }),
				}),
				(result) =>
					result instanceof Promise
						? Effect.tryPromise({
								try: () => result,
								catch: (e) => new S3Error({ cause: e, message: 'Asynchronous Error in S3.use' }),
							})
						: Effect.succeed(result),
			),
		presign: client.presign.bind(client),
	});
};

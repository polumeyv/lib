/** Path-style S3 object URL (path-style handles bucket names with dots). */
export const s3Url = (key: string, bucket: string, region: string) => `https://s3.${region}.amazonaws.com/${bucket}/${key}`;

/** S3 object key for a user's avatar — single source of truth for the read URL and the S3 write/delete paths. */
export const avatarKey = (sub: string): string => `avatars/${sub}.jpg`;

/** Public URL of a user's avatar. Apps pass their `$env/static/public` bucket/region (see each app's `$lib/avatar`). */
export const avatarUrl = (sub: string, bucket: string, region: string) => s3Url(avatarKey(sub), bucket, region);

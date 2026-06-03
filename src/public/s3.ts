/** Path-style S3 object URL (path-style handles bucket names with dots). */
export const s3Url = (key: string, bucket: string, region: string) => `https://s3.${region}.amazonaws.com/${bucket}/${key}`;

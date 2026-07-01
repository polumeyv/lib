/**
 * @module @polumeyv/lib/schemas/primitives
 *
 * The schema primitives moved to `@polumeyv/utilities/schema-primitives` so `@polumeyv/ui` (which must never import
 * `@polumeyv/lib`) can share them. Re-exported here so `@polumeyv/lib/schemas`, this `@polumeyv/lib/schemas/primitives`
 * subpath, and the in-repo `./tables`/`./projections`/`./composites` imports keep resolving unchanged. New code can
 * import from `@polumeyv/utilities/schema-primitives` directly.
 */
export * from '@polumeyv/utilities/schema-primitives';

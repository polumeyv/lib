export class RefillingTokenBucket<K> {
	private storage = new Map<K, { count: number; refilledAt: number }>();
	private readonly refillIntervalMs: number;

	constructor(
		public readonly max: number,
		refillIntervalSeconds: number,
	) {
		this.refillIntervalMs = refillIntervalSeconds * 1000;
	}

	consume(key: K, cost: number): boolean {
		const now = Date.now();
		const bucket = this.storage.get(key);

		if (!bucket) return (this.storage.set(key, { count: this.max - cost, refilledAt: now }), true);

		bucket.count = Math.min(bucket.count + (((now - bucket.refilledAt) / this.refillIntervalMs) | 0), this.max);
		bucket.refilledAt = now;

		return bucket.count >= cost && ((bucket.count -= cost), true);
	}
}

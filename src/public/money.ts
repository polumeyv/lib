/**
 * Brand-typed money math — the one home for fee/tip rounding policy. Currency *presentation* (`formatUSD`) is pure
 * and lives in `@polumeyv/utilities`.
 */
import type { Bps, Cents } from '../schemas/primitives';

/** Platform fee withheld from a base charge: `bps` basis points of `base` cents, rounded to whole cents. The single
 *  basis-point rounding policy (previously inlined in `connectSplit`). */
export const feeFromBps = (base: number, bps: Bps): Cents => Math.round((base * bps) / 10_000) as Cents;

/** A tip of `pct` percent on `amount` cents, rounded to whole cents. The single tip rounding policy (previously
 *  re-spelled per call in the booking prepay step). */
export const tipFromPct = (amount: number, pct: number): Cents => Math.round((amount * pct) / 100) as Cents;

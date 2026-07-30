/**
 * Operating-mode autonomy ladder — the EDGE-SHARED, request-time subset (Phase 2.5b).
 *
 * This lives in policy-core (dependency-free: no DB/IO/clock) so the SAME gate runs
 * at the backend authorize gate, the agent-side guard, and the MCP-side guard via the
 * generated `policy-core.mjs` mirrors — an operating mode denies/escalates identically
 * everywhere. The trust → mode RESOLVER (bands, hysteresis, coverage cap) is a
 * SERVER-side concern (it needs the signed Trust Index) and deliberately lives OUTSIDE
 * policy-core, in `@/features/agent-identity/operating-mode.ts`.
 *
 *   AUTONOMOUS  → acts freely (no added bias)
 *   SUPERVISED  → a human confirms HIGH-consequence actions (risk ≥ high, or spend ≥ cap)
 *   RESTRICTED  → a human confirms EVERY value-bearing action
 *   READ_ONLY   → value-bearing actions are denied outright (reads still allowed)
 */

export type OperatingMode = 'autonomous' | 'supervised' | 'restricted' | 'read_only';

/** Higher = more autonomy. Drives most-restrictive-wins combination + up/down direction. */
export const MODE_RANK: Record<OperatingMode, number> = {
  read_only: 0,
  restricted: 1,
  supervised: 2,
  autonomous: 3,
};

/** Rungs ordered least → most autonomy (index === rank). */
export const MODES_BY_RANK: readonly OperatingMode[] = ['read_only', 'restricted', 'supervised', 'autonomous'];

export function isOperatingMode(v: unknown): v is OperatingMode {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(MODE_RANK, v);
}

/** Coerce an unknown/legacy value to a safe mode — defaults to the LEAST-restrictive AUTONOMOUS
 * (a null column on a pre-2.5 row, or a stripped bundle sibling, therefore imposes no bias). */
export function asOperatingMode(v: unknown): OperatingMode {
  return isOperatingMode(v) ? v : 'autonomous';
}

/** The more restrictive (lower-rank) of two modes. */
export function moreRestrictive(a: OperatingMode, b: OperatingMode): OperatingMode {
  return MODE_RANK[a] <= MODE_RANK[b] ? a : b;
}

/** Default spend threshold above which SUPERVISED escalates. A conservative default posture;
 * making it per-agent configurable is a follow-up (configurable weights/thresholds). */
export const SUPERVISED_AMOUNT_CAP = 100;

const RISK_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
function riskAtOrAboveHigh(riskLevel: unknown): boolean {
  const r = typeof riskLevel === 'string' ? RISK_RANK[riskLevel.toLowerCase()] : undefined;
  return r !== undefined && r >= RISK_RANK.high;
}

export interface ModeGateContext {
  amount?: number;
  riskLevel?: 'low' | 'medium' | 'high' | 'critical' | string | null;
}

export interface ModeGateResult {
  decision: 'allow' | 'escalate' | 'block';
  reasonCode: string | null;
}

/**
 * The per-request bias an operating mode imposes. `allow` = no constraint (the
 * deterministic evaluation stands); `escalate` = route to a human; `block` = deny.
 * Only VALUE-BEARING actions (amount > 0) are constrained — a zero-amount read
 * passes every rung, so a READ_ONLY agent can still look things up, it just cannot
 * spend. `escalate` here is a FLOOR: the caller combines it most-restrictive-wins
 * with the rule/mandate verdict, so a rule block still outranks a mode escalate.
 */
export function operatingModeGate(mode: OperatingMode | null | undefined, ctx: ModeGateContext): ModeGateResult {
  const m = asOperatingMode(mode);
  const valueBearing = (ctx.amount ?? 0) > 0;
  if (!valueBearing || m === 'autonomous') return { decision: 'allow', reasonCode: null };
  switch (m) {
    case 'read_only':
      return { decision: 'block', reasonCode: 'MODE_READ_ONLY' };
    case 'restricted':
      return { decision: 'escalate', reasonCode: 'MODE_RESTRICTED_REVIEW' };
    case 'supervised':
      return riskAtOrAboveHigh(ctx.riskLevel) || (ctx.amount ?? 0) >= SUPERVISED_AMOUNT_CAP
        ? { decision: 'escalate', reasonCode: 'MODE_SUPERVISED_REVIEW' }
        : { decision: 'allow', reasonCode: null };
    default:
      return { decision: 'allow', reasonCode: null };
  }
}

import type { EvaluationContext } from './types.js';

/**
 * Atom library — the code-defined predicates that DB policies compose by id.
 * Keeping implementations in code (vs storing executable rules) is the safe,
 * Sovereign-forward shape: tenants configure WHICH atoms apply, not arbitrary code.
 *
 * Every predicate is a PURE boolean check over (context, config): no clock, no
 * IO, no randomness. This is what makes a verdict reproducible and independently
 * verifiable at the edge (spec §6.3).
 */

const RISK_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export const ATOM_REGISTRY: Record<string, (ctx: EvaluationContext, config?: any) => boolean> = {
  'data-source-not-approved': (c, cfg) =>
    !!c.dataSourceId && !(((cfg?.approved as string[]) ?? []).includes(String(c.dataSourceId))),
  'consent-missing': (c) => c.consent === false,
  'risk-at-or-above': (c, cfg) => {
    const have = RISK_RANK[String(c.riskLevel)];
    const need = RISK_RANK[String(cfg?.level ?? 'high')];
    return have !== undefined && need !== undefined && have >= need;
  },
  'amount-over': (c, cfg) => typeof c.amount === 'number' && c.amount > Number(cfg?.limit ?? 0),
  // Total budget: cumulativeSpend is a SERVER-derived, signed-last context field (never
  // shadowable by the agent's itinerary), so this compares already-spent + this amount.
  'cumulative-over': (c, cfg) => (Number(c.cumulativeSpend ?? 0) + Number(c.amount ?? 0)) > Number(cfg?.limit ?? 0),
  // Fires if any configured term appears in the prompt and/or output text.
  // Used to govern agent responses on content (prohibited claims, sensitive advice).
  'text-matches': (c, cfg) => {
    const hay = `${c.prompt ?? ''}\n${c.output ?? ''}`.toLowerCase();
    const terms = ((cfg?.terms as string[]) ?? []).map((t) => String(t).toLowerCase());
    return terms.some((t) => t.length > 0 && hay.includes(t));
  },
  // --- Compliance atoms. Allow-list atoms fire when the context field is PRESENT
  //     and NOT allowed (consistent with data-source-not-approved: a missing field
  //     does not fire — the atom's requiredContext documents what to supply). ---
  'jurisdiction-not-allowed': (c, cfg) => notInAllowList(c.jurisdiction, cfg?.allowed),
  'data-residency-violation': (c, cfg) => notInAllowList(c.dataResidency, cfg?.allowedRegions),
  'model-not-allowed': (c, cfg) => notInAllowList(c.model, cfg?.allowed),
  'tool-not-allowed': (c, cfg) => notInAllowList(c.tool, cfg?.allowed),
  'pii-present': (c) => c.piiPresent === true,
  'rate-limit-exceeded': (c, cfg) => typeof c.callCount === 'number' && c.callCount > Number(cfg?.max ?? 0),
  // Trust guidance (MetaMynd Trust Index / HCS-28). Fires when the counterparty's trust score is
  // below a soft REVIEW line — intended to author an ESCALATE (route to a human), NOT a hard block.
  // The score is server-derived (signed-last) so the agent's itinerary can't fake it; when no score
  // is present (e.g. no counterparty resolved) the atom simply does not fire — no guidance.
  'hol-trust-below-review': (c, cfg) =>
    typeof c.holTrustScore === 'number' && c.holTrustScore < Number(cfg?.reviewBelow ?? 60),
};

/** True when `value` is a non-empty string that is NOT in the (case-insensitive) allow-list. */
function notInAllowList(value: unknown, allowList: unknown): boolean {
  const v = value != null ? String(value).toLowerCase().trim() : '';
  const allowed = (Array.isArray(allowList) ? allowList : []).map((x) => String(x).toLowerCase().trim());
  return v !== '' && allowed.length > 0 && !allowed.includes(v);
}

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
  // Deny-by-default primitive for value-moving actions. Fires on ABSENCE (like the
  // evidence atoms below, and unlike `amount-over`) OR on a NEGATIVE amount: true when
  // the context carries no usable amount, or one that cannot be trusted for capping —
  // the gate cannot tell how much value the call would move, so a spend cap authored
  // next to it would silently never fire. `amount-over` only ever fires on `> limit`,
  // so a negative amount clears every positive cap by construction, and on a system
  // that tracks committed spend ADDITIVELY (reserved += amount), a negative claim can
  // net-reduce what's already committed rather than add to it — the same "cap never
  // fires" failure as a missing amount, reached from the other side of zero. Zero
  // itself is NOT covered here: a genuine $0 action (a read, a no-op) is a valid,
  // known amount, not an unknown one. Author this with BLOCK as the FIRST rule of a
  // spend policy; the cap that follows then only ever judges a known, non-negative
  // number. Opt-in: only a rule that keys it runs it, so actions that carry no amount
  // by nature are unaffected. The public authorize endpoint's own schema already
  // rejects a negative amount before it reaches this atom (defense in depth, not the
  // only layer) — this is what closes the same gap for paths that schema doesn't
  // cover: the local/harness evaluator and the platform's own MCP tool policies.
  'amount-unknown': (c) => !(typeof c.amount === 'number' && Number.isFinite(c.amount) && c.amount >= 0),
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
  // --- Evidence-quality atoms (SAFR §24). Unlike the allow-list atoms, these fire on ABSENCE:
  //     a REQUIRE semantic — "the action must be backed by this evidence; if it isn't, fire"
  //     (author with escalate/block). Opt-in: they only run when a rule keys them. ---
  // Fires when any REQUIRED evidence type is not among the attested `evidenceTypes` (missing
  // evidence — including none supplied at all → all required missing → fires).
  'evidence-requirement': (c, cfg) => {
    const required = ((cfg?.required as string[]) ?? []).map((t) => String(t).toLowerCase().trim()).filter(Boolean);
    if (required.length === 0) return false; // nothing required → nothing to enforce
    const have = new Set((Array.isArray(c.evidenceTypes) ? c.evidenceTypes : []).map((t) => String(t).toLowerCase().trim()));
    return required.some((r) => !have.has(r));
  },
  // Fires when a required minimum confidence (min > 0) is not met — the attested confidence is
  // below it, or absent (a required confidence that was never supplied fails the bar). A min of
  // 0 / unset is no requirement and never fires.
  'evidence-confidence-below': (c, cfg) => {
    const min = Number(cfg?.min ?? 0);
    if (!(min > 0)) return false;
    return typeof c.evidenceConfidence !== 'number' || c.evidenceConfidence < min;
  },
  // Trust guidance (MetaMynd Trust Index / HCS-28). Fires when the counterparty's trust score is
  // below a soft REVIEW line — intended to author an ESCALATE (route to a human), NOT a hard block.
  // The score is server-derived (signed-last) so the agent's itinerary can't fake it; when no score
  // is present (e.g. no counterparty resolved) the atom simply does not fire — no guidance.
  'hol-trust-below-review': (c, cfg) =>
    typeof c.holTrustScore === 'number' && c.holTrustScore < Number(cfg?.reviewBelow ?? 60),
};

/**
 * True when `value` is a non-empty string that is NOT in the (case-insensitive) allow-list.
 *
 * An EMPTY allow-list fires on any non-empty value — "nothing is approved yet" — matching
 * `data-source-not-approved`'s own behavior and this file's own header comment above
 * ("Allow-list atoms fire when the context field is PRESENT and NOT allowed"). A previous
 * version required `allowed.length > 0` before firing at all, which silently inverted that:
 * an unconfigured allow-list meant EVERYTHING was permitted rather than nothing, for
 * `jurisdiction-not-allowed`, `data-residency-violation`, `model-not-allowed` and
 * `tool-not-allowed`. Confirmed via the real simulation engine against
 * `tool-boundary-baseline`'s own seeded config (`allowed: []`, deliberately empty per that
 * set's remediation text "so that nothing passes unexamined") that the old behavior let
 * every tool/model through — the opposite of what was promised.
 */
function notInAllowList(value: unknown, allowList: unknown): boolean {
  const v = value != null ? String(value).toLowerCase().trim() : '';
  if (v === '') return false;
  const allowed = (Array.isArray(allowList) ? allowList : []).map((x) => String(x).toLowerCase().trim());
  return !allowed.includes(v);
}

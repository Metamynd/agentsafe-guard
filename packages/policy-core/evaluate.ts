/**
 * The composed deterministic evaluation (spec §6, §7.5 steps 7–9).
 *
 * `evaluate(rulePacks, mandate, context) → Verdict` is the single entry point a
 * guard uses to compute a verdict locally, and it is the exact pure core the
 * backend gate runs after its stateful pre-checks (principal/owner verified, key
 * verified, signature, freshness/nonce). Those stateful checks are NOT part of
 * policy-core — they need IO. What lives here is the reproducible part:
 *
 *   Authority (is there standing to ask at all?)
 *     →  Standards rules  →  SOP rules  →  Mandate evaluation
 *
 * combined by the most-restrictive-wins precedence (block > escalate > allow).
 * Given identical inputs, every conformant implementation returns the identical
 * verdict (spec §6.3) — this is what makes edge / cross-party evaluation trustless.
 */

import { evaluateBoundStandards, type StandardDocument } from './standards-rules.js';
import { evaluateMandate, isAuthorityFailure } from './mandate-eval.js';
import type { Mandate, MandateRequest } from './mandate.types.js';
import type { EvaluationContext, PolicyDecision, Verdict } from './types.js';

/** Restrictiveness ordering — higher wins, so combination is order-independent.
 * Containment (decommission > suspend/quarantine) > block > escalate > observe
 * (permit-but-flag) > allow. `decommission` outranks the rule-firable containment
 * effects even though a rule/atom can never actually produce it (owner/admin-only).
 * Keep this identical to standards-rules.ts's PRECEDENCE. */
const PRECEDENCE: Record<PolicyDecision, number> = { allow: 0, observe: 1, escalate: 2, block: 3, suspend: 4, quarantine: 5, decommission: 6 };

/** A bound rule pack: a Standard or SOP document keyed for provenance. */
export interface RulePack {
  standardKey: string;
  document: StandardDocument | null | undefined;
}

export interface EvaluateInput {
  /** Enforced Standards the agent is bound to (spec §5.2). */
  standards?: RulePack[];
  /** Active SOPs assigned to the agent. */
  sops?: RulePack[];
  /** The agent's mandate (ODRL capability). Omit to skip the mandate layer. */
  mandate?: Mandate;
  /** Context the Standards/SOP atoms evaluate against (signed fields already applied last). */
  context: EvaluationContext;
  /** The resolved ODRL request (mm:* operand values). Omit when `mandate` is omitted. */
  mandateRequest?: MandateRequest;
}

/**
 * Compose the three deterministic layers into one Verdict. `authorizationId`,
 * `remaining`, and `proofRef` are stateful concerns owned by the gate, so they
 * are null here — a local guard uses this to decide allow/block/escalate before
 * committing to the (stateful) gate round-trip.
 */
export function evaluate(input: EvaluateInput): Verdict {
  let decision: PolicyDecision = 'allow';
  let reasonCode: string | null = 'AUTHORIZED';

  const consider = (d: PolicyDecision, code: string | null) => {
    if (PRECEDENCE[d] > PRECEDENCE[decision]) {
      decision = d;
      reasonCode = code;
    }
  };

  // Authority goes FIRST rather than last, and it goes in through `consider` like
  // everything else.
  //
  // The three layers combine most-restrictive-wins, which is order-independent for the
  // DECISION but not for the REASON: a rule block and a mandate block tie, and `consider`
  // keeps the incumbent on a tie, so whichever layer ran first named the cause. Running
  // the rules first therefore made an expired mandate, or an action never granted, report
  // whichever rule the amount happened to trip — see `isAuthorityFailure` for the case
  // that surfaced it.
  //
  // Seeding the accumulator fixes the reason without touching the decision, which matters:
  // a short-circuit return here would have been strictly worse than the bug. A Standard
  // whose molecule says `suspend` or `quarantine` is MORE restrictive than an authority
  // block, and on the gate that verdict is what persists containment on the agent.
  // Returning early would have quietly downgraded a containment to a one-call refusal.
  //
  // So: authority names the refusal on a tie, containment still outranks it, and every
  // other mandate outcome is still folded in LAST — an in-scope request whose cap is
  // tripped by both an SOP and the mandate still reports the SOP, the more specific and
  // more editable of the two.
  const m = input.mandate && input.mandateRequest ? evaluateMandate(input.mandate, input.mandateRequest) : null;
  const authority = m !== null && isAuthorityFailure(m);
  if (m && authority) consider(m.decision, m.reasonCode);

  const std = evaluateBoundStandards(input.standards ?? [], input.context);
  if (std.decision !== 'allow') consider(std.decision, std.reasonCode ?? 'STANDARD_RULE');

  const sop = evaluateBoundStandards(input.sops ?? [], input.context);
  if (sop.decision !== 'allow') consider(sop.decision, sop.reasonCode ?? 'SOP_RULE');

  if (m && !authority && m.decision !== 'allow') consider(m.decision, m.reasonCode);

  return { decision, reasonCode, authorizationId: null, remaining: null, proofRef: null };
}

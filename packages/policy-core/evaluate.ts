/**
 * The composed deterministic evaluation (spec §6, §7.5 steps 7–9).
 *
 * `evaluate(rulePacks, mandate, context) → Verdict` is the single entry point a
 * guard uses to compute a verdict locally, and it is the exact pure core the
 * backend gate runs after its stateful pre-checks (principal/owner verified, key
 * verified, signature, freshness/nonce). Those stateful checks are NOT part of
 * policy-core — they need IO. What lives here is the reproducible part:
 *
 *   Standards rules  →  SOP rules  →  Mandate evaluation
 *
 * combined by the most-restrictive-wins precedence (block > escalate > allow).
 * Given identical inputs, every conformant implementation returns the identical
 * verdict (spec §6.3) — this is what makes edge / cross-party evaluation trustless.
 */

import { evaluateBoundStandards, type StandardDocument } from './standards-rules.js';
import { evaluateMandate } from './mandate-eval.js';
import type { Mandate, MandateRequest } from './mandate.types.js';
import type { EvaluationContext, PolicyDecision, Verdict } from './types.js';

/** Restrictiveness ordering — higher wins, so combination is order-independent.
 * Containment (suspend/quarantine) > block > escalate > observe (permit-but-flag) >
 * allow. Keep this identical to standards-rules.ts's PRECEDENCE. */
const PRECEDENCE: Record<PolicyDecision, number> = { allow: 0, observe: 1, escalate: 2, block: 3, suspend: 4, quarantine: 5 };

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

  const std = evaluateBoundStandards(input.standards ?? [], input.context);
  if (std.decision !== 'allow') consider(std.decision, std.reasonCode ?? 'STANDARD_RULE');

  const sop = evaluateBoundStandards(input.sops ?? [], input.context);
  if (sop.decision !== 'allow') consider(sop.decision, sop.reasonCode ?? 'SOP_RULE');

  if (input.mandate && input.mandateRequest) {
    const m = evaluateMandate(input.mandate, input.mandateRequest);
    if (m.decision !== 'allow') consider(m.decision, m.reasonCode);
  }

  return { decision, reasonCode, authorizationId: null, remaining: null, proofRef: null };
}

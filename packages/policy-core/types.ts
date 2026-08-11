/**
 * policy-core — shared deterministic policy types.
 *
 * This module is the single source of truth for the MAGP evaluation model
 * (spec §6). It is DEPENDENCY-FREE by design: no DB, no IO, no `@hashgraph/sdk`,
 * no clock, no LLM. The same code is imported by the backend authorize gate, the
 * agent-side guard, and (Phase 2) the MCP-side guard, so any party computes an
 * identical verdict from identical inputs (spec §3.5, §6.3).
 */

/**
 * A policy decision — the same vocabulary the evidence rail records.
 *
 * Two values PERMIT execution: `allow` and `observe`. `observe` (SAFR §11) permits
 * the action but flags it — the gate still records an evidence event and emits
 * telemetry, so the action is executed under monitoring and available for later
 * review. It outranks `allow` in the most-restrictive-wins precedence (a flag
 * survives an otherwise-allow verdict) but is outranked by any deny/escalate (a
 * human-review or block need always wins over a mere flag).
 *
 * Every other value DENIES execution (fail-safe). `escalate` additionally routes to
 * the human-approval queue. `suspend`/`quarantine` are containment effects: a
 * terminal deny that also marks the event as a containment-level signal in the audit
 * trail (distinct from a plain `block`) and drives the agent's containment lifecycle
 * (deny all further actions until reinstated).
 */
export type PolicyDecision = 'allow' | 'observe' | 'block' | 'escalate' | 'suspend' | 'quarantine';

/**
 * The context an action is evaluated against (spec §6.4). It is the union of the
 * signed request fields and a caller-supplied context object. Sensitive fields
 * (prompt/output) are NOT persisted here — they are passed to the evidence rail
 * for hashing.
 */
export interface EvaluationContext {
  action: string;
  ownerId?: string | null; // tenant scope (a tenant policy overrides global)
  agentId?: number | null;
  agentDid?: string | null;
  workerId?: string;
  dataSourceId?: string | null;
  riskLevel?: 'low' | 'medium' | 'high' | 'critical';
  consent?: boolean;
  amount?: number;
  cumulativeSpend?: number; // SERVER-derived: already-committed spend for the mandate (never agent-supplied)
  // Compliance-atom context (supplied by the agent at authorize time; see each
  // atom's requiredContext in the atom catalog).
  jurisdiction?: string | null; // e.g. 'US', 'MY'
  dataResidency?: string | null; // processing region, e.g. 'eu', 'ap-southeast'
  model?: string | null; // the LLM model the agent used
  tool?: string | null; // the tool/function the agent is invoking
  piiPresent?: boolean; // caller-flagged: the action involves PII
  callCount?: number; // rolling call count for rate limiting
  // Evidence-quality context (SAFR §24) — the agent ATTESTS to the evidence backing this action.
  // `evidenceTypes` = the kinds of evidence gathered (e.g. 'kyc', 'source-doc', 'signature');
  // `evidenceConfidence` = a 0–1 confidence in that evidence. Read by the evidence-requirement /
  // evidence-confidence-below atoms so a rule can escalate an under-evidenced action.
  evidenceTypes?: string[];
  evidenceConfidence?: number;
  [key: string]: unknown;
}

/**
 * The verdict returned by the authorize protocol (spec §6.5). On `allow`,
 * `authorizationId` is a fresh identifier and `remaining` is the residual budget.
 * On non-allow, `authorizationId` and `proofRef` are null.
 */
export interface Verdict {
  decision: PolicyDecision;
  reasonCode: string | null;
  authorizationId: string | null;
  remaining: number | null;
  proofRef: string | null;
}

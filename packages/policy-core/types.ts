/**
 * policy-core — shared deterministic policy types.
 *
 * This module is the single source of truth for the MAGP evaluation model
 * (spec §6). It is DEPENDENCY-FREE by design: no DB, no IO, no `@hashgraph/sdk`,
 * no clock, no LLM. The same code is imported by the backend authorize gate, the
 * agent-side guard, and (Phase 2) the MCP-side guard, so any party computes an
 * identical verdict from identical inputs (spec §3.5, §6.3).
 */

/** A policy decision — the same vocabulary the evidence rail records. */
export type PolicyDecision = 'allow' | 'block' | 'escalate';

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
  // Compliance-atom context (supplied by the agent at authorize time; see each
  // atom's requiredContext in the atom catalog).
  jurisdiction?: string | null; // e.g. 'US', 'MY'
  dataResidency?: string | null; // processing region, e.g. 'eu', 'ap-southeast'
  model?: string | null; // the LLM model the agent used
  tool?: string | null; // the tool/function the agent is invoking
  piiPresent?: boolean; // caller-flagged: the action involves PII
  callCount?: number; // rolling call count for rate limiting
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

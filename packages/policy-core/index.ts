/**
 * policy-core — the dependency-free deterministic policy evaluator shared by the
 * backend authorize gate, the agent-side guard, and (Phase 2) the MCP-side guard.
 *
 * Zero runtime dependencies: no DB, no IO, no `@hashgraph/sdk`, no clock, no LLM.
 * Given identical inputs, every importer computes an identical verdict (spec §6.3).
 * Signature verification is intentionally NOT here — it needs the key material,
 * not the evaluator; policy-core only builds the canonical message (§7.3).
 */

// Types
export type { PolicyDecision, EvaluationContext, Verdict } from './types.js';

// Atoms
export { ATOM_REGISTRY } from './atom-registry.js';
export {
  ATOM_SPECS,
  CATALOGUED_ATOMS,
  requiredContextFor,
  type AtomSpec,
  type AtomConfigField,
  type AtomConfigType,
} from './atom-catalog.js';

// Standards / SOP rules engine
export {
  moleculeFires,
  moleculeUnverifiable,
  requiredContextOf,
  CONTEXT_UNVERIFIABLE,
  evaluateStandardRules,
  evaluateBoundStandards,
  validateMolecules,
  type Combinator,
  type FireDecision,
  type RuleAtom,
  type Molecule,
  type StandardDocument,
  type StandardRuleResult,
  type ValidationIssue,
} from './standards-rules.js';

// Mandate (ODRL) evaluator + budget helpers
export {
  evaluateMandate,
  isAuthorityFailure,
  authorityFailure,
  remainingBudget,
  canAuthorize,
  applyHold,
  applyCapture,
  releaseHold,
  sumEventField,
} from './mandate-eval.js';
export type {
  MandateDecision,
  Operator,
  Constraint,
  Permission,
  Prohibition,
  Mandate,
  MandateRequest,
  MandateResult,
  BudgetState,
} from './mandate.types.js';

// Composed evaluation + canonical message + context construction
export { evaluate, type EvaluateInput, type RulePack } from './evaluate.js';
export { buildAuthMessage, buildLegacyAuthMessageV1, type AuthMessageFields } from './canonical.js';
export { buildLocalDecisionMessage, type LocalDecisionMessageFields } from './canonical.js';
export { buildCheckpointAnchorMessage, type CheckpointAnchorMessageFields } from './checkpoint-anchor.js';
export { applySignedLast } from './context.js';
// Trusted context provenance (spec §6.4.3)
export {
  buildRuleContext,
  provenanceOf,
  meetsProvenance,
  isProvenance,
  normalizeRiskLevel,
  maxRisk,
  riskFloorFor,
  contextFieldProblem,
  PROVENANCE_KEY,
  PROVENANCE_LEVELS,
  PROVENANCE_RANK,
  RISK_LEVELS,
  ATOM_DEFAULT_REQUIRED_CONTEXT,
  type ContextProvenance,
  type ProvenanceMap,
  type RiskLevel,
  type RuleContextSources,
} from './provenance.js';

// Operating-mode autonomy ladder — request-time gate (edge-shared; Phase 2.5b)
export {
  operatingModeGate,
  asOperatingMode,
  isOperatingMode,
  moreRestrictive,
  MODE_RANK,
  MODES_BY_RANK,
  SUPERVISED_AMOUNT_CAP,
  type OperatingMode,
  type ModeGateContext,
  type ModeGateResult,
} from './operating-mode.js';

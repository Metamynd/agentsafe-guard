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
export { buildAuthMessage, type AuthMessageFields } from './canonical.js';
export { applySignedLast } from './context.js';

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

import { ATOM_REGISTRY } from './atom-registry.js';
import { ATOM_SPECS, type AtomConfigField } from './atom-catalog.js';
import type { EvaluationContext, PolicyDecision } from './types.js';

/**
 * The Standards rules engine — the DETERMINISTIC runtime gate.
 *
 * Taxonomy (atoms → molecules → standard):
 *  - Atom     = one code-defined predicate + its config (a pure boolean check).
 *  - Molecule = a set of atoms combined with all/any/none → one decision.
 *  - Standard = metadata + a set of molecules (the `standard.documentJson`).
 *
 * Evaluation is a PURE function of (molecules, context): no clock, no I/O, no
 * randomness, and — critically — no LLM. AI drafts atoms at AUTHORING time; the
 * runtime only executes compiled predicates from ATOM_REGISTRY. Combined with
 * version-pinning + content-hash + HCS anchor, a decision is fully reproducible
 * and auditable from the anchored standard. This is what makes the agent gate
 * deterministic (spec §6).
 */

/** How a molecule combines its atoms. */
export type Combinator = 'all' | 'any' | 'none';
/** What a molecule fires when satisfied (never 'allow' — non-firing = allow). */
export type FireDecision = 'block' | 'escalate';

/** An atom: a reference to a code-defined predicate + its config. */
export interface RuleAtom {
  id: string;
  predicate: string; // a key of ATOM_REGISTRY
  config?: Record<string, unknown>;
}

/** A molecule: atoms combined by a boolean operator, firing a decision when satisfied. */
export interface Molecule {
  id: string;
  name?: string;
  description?: string;
  combinator: Combinator; // all = AND, any = OR, none = NOT-any
  atoms: RuleAtom[];
  decision: FireDecision;
  reasonCode: string;
}

/** The enforceable content of a standard (stored in `standard.documentJson`). */
export interface StandardDocument {
  key?: string;
  title?: string;
  version?: number;
  description?: string;
  molecules?: Molecule[];
  [k: string]: unknown; // freeform reference fields allowed alongside molecules
}

export interface StandardRuleResult {
  decision: PolicyDecision; // 'allow' | 'block' | 'escalate'
  reasonCode: string | null;
  firedMoleculeId: string | null;
  standardKey: string | null;
}

/** Restrictiveness ordering — higher wins, so evaluation is order-independent. */
const PRECEDENCE: Record<PolicyDecision, number> = { allow: 0, escalate: 1, block: 2 };

/** Evaluate a single atom. An unknown predicate never fires (validation rejects it at authoring). */
function atomFires(atom: RuleAtom, ctx: EvaluationContext): boolean {
  const pred = ATOM_REGISTRY[atom.predicate];
  if (!pred) return false;
  try {
    return !!pred(ctx, atom.config);
  } catch (err) {
    // A predicate that throws on this context is treated as not-firing here; the
    // molecule's combinator (esp. `none`) still resolves deterministically. Log it
    // so a mis-authored/buggy atom is discoverable rather than silently weakening
    // enforcement forever.
    console.warn(
      `[standards] atom '${atom.predicate}' threw during evaluation (treated as not-firing):`,
      err instanceof Error ? err.message : err,
    );
    return false;
  }
}

/** Whether a molecule fires against the context, per its combinator. */
export function moleculeFires(m: Molecule, ctx: EvaluationContext): boolean {
  if (!m.atoms || m.atoms.length === 0) return false; // an empty molecule never gates
  const results = m.atoms.map((a) => atomFires(a, ctx));
  switch (m.combinator) {
    case 'all':
      return results.every(Boolean);
    case 'any':
      return results.some(Boolean);
    case 'none':
      return !results.some(Boolean);
    default:
      return false;
  }
}

/**
 * Evaluate one standard's molecules. Most-restrictive firing molecule wins
 * (block > escalate > allow); iteration is over the pinned document's stable
 * molecule order, so the outcome is deterministic. Non-firing → allow.
 */
export function evaluateStandardRules(
  molecules: Molecule[] | undefined,
  ctx: EvaluationContext,
  standardKey: string | null = null,
): StandardRuleResult {
  let best: { decision: FireDecision; reasonCode: string; id: string } | null = null;
  for (const m of molecules ?? []) {
    if (moleculeFires(m, ctx)) {
      if (!best || PRECEDENCE[m.decision] > PRECEDENCE[best.decision]) {
        best = { decision: m.decision, reasonCode: m.reasonCode, id: m.id };
      }
    }
  }
  if (!best) return { decision: 'allow', reasonCode: null, firedMoleculeId: null, standardKey };
  return { decision: best.decision, reasonCode: best.reasonCode, firedMoleculeId: best.id, standardKey };
}

/**
 * Evaluate the union of the standards an agent is bound to. The single most-
 * restrictive decision across every bound standard wins — one blocking molecule
 * anywhere blocks the action.
 */
export function evaluateBoundStandards(
  standards: { standardKey: string; document: StandardDocument | null | undefined }[],
  ctx: EvaluationContext,
): StandardRuleResult {
  let best: StandardRuleResult = { decision: 'allow', reasonCode: null, firedMoleculeId: null, standardKey: null };
  for (const s of standards) {
    const r = evaluateStandardRules(s.document?.molecules, ctx, s.standardKey);
    if (PRECEDENCE[r.decision] > PRECEDENCE[best.decision]) best = r;
  }
  return best;
}

// --- Authoring-time validation (also used to validate AI-drafted rules) ---

export interface ValidationIssue {
  moleculeId: string;
  message: string;
}

/** Whether a config value matches a declared field type. */
function configValueValid(field: AtomConfigField, value: unknown): boolean {
  switch (field.type) {
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'string':
      return typeof value === 'string';
    case 'string[]':
      return Array.isArray(value) && value.every((v) => typeof v === 'string');
    case 'enum':
      return typeof value === 'string' && (field.options ?? []).includes(value);
    default:
      return true;
  }
}

/**
 * Validate an atom's config against its declared schema: required fields present,
 * every provided field the right type. Catches a typo like `{ limit: "abc" }` that
 * would otherwise coerce to NaN and silently make the molecule never fire.
 */
function validateAtomConfig(predicate: string, config: Record<string, unknown> | undefined): string[] {
  const spec = ATOM_SPECS.find((s) => s.predicate === predicate);
  if (!spec) return []; // unknown predicate is reported separately
  const errors: string[] = [];
  const cfg = config ?? {};
  for (const field of spec.config) {
    const present = cfg[field.key] !== undefined && cfg[field.key] !== null;
    if (!present) {
      if (field.required) errors.push(`atom '${predicate}' missing required config '${field.key}'`);
      continue;
    }
    if (!configValueValid(field, cfg[field.key])) {
      errors.push(`atom '${predicate}' config '${field.key}' must be a ${field.type}`);
    }
  }
  return errors;
}

/**
 * Validate a document's molecules for publishing: every atom must reference a
 * known predicate, combinators/decisions must be valid, and reason codes present.
 * This is the guard that keeps AI-drafted or hand-authored rules from becoming a
 * standard unless they are executable.
 */
export function validateMolecules(molecules: Molecule[] | undefined): { ok: boolean; issues: ValidationIssue[] } {
  const issues: ValidationIssue[] = [];
  for (const m of molecules ?? []) {
    if (!m.id) issues.push({ moleculeId: '(missing id)', message: 'molecule is missing an id' });
    if (!['all', 'any', 'none'].includes(m.combinator)) {
      issues.push({ moleculeId: m.id, message: `invalid combinator '${m.combinator}' (all|any|none)` });
    }
    if (!['block', 'escalate'].includes(m.decision)) {
      issues.push({ moleculeId: m.id, message: `invalid decision '${m.decision}' (block|escalate)` });
    }
    if (!m.reasonCode) issues.push({ moleculeId: m.id, message: 'molecule is missing a reasonCode' });
    if (!m.atoms || m.atoms.length === 0) {
      issues.push({ moleculeId: m.id, message: 'molecule has no atoms' });
    }
    for (const a of m.atoms ?? []) {
      if (!ATOM_REGISTRY[a.predicate]) {
        issues.push({ moleculeId: m.id, message: `unknown atom predicate '${a.predicate}'` });
        continue;
      }
      for (const err of validateAtomConfig(a.predicate, a.config)) {
        issues.push({ moleculeId: m.id, message: err });
      }
    }
  }
  return { ok: issues.length === 0, issues };
}

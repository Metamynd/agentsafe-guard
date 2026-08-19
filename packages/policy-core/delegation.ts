/**
 * Agent-to-agent delegation — the narrowing invariant, as pure logic.
 *
 * Mandates run principal → agent. There is no sub-delegation and no on-behalf-of chain,
 * yet a supervisor agent narrowing authority for a worker agent is the defining shape of a
 * multi-agent harness. The two rules that make such a chain safe are:
 *
 *   1. A delegated mandate may only ever NARROW its parent, never widen it.
 *   2. The chain terminates at a bounded depth.
 *
 * Both are gate concerns, so they live here in policy-core beside the evaluator rather
 * than in a service — the same rules have to hold whether a delegation is checked at
 * issuance, re-checked at the gate, or evaluated at the edge by a guard.
 *
 * WHAT NARROWING MEANS, precisely. A child is narrower when every request its parent would
 * refuse, the child also refuses. That gives an asymmetric rule per operator, and the
 * asymmetry is where the bugs live:
 *
 *   lteq / lt   a lower ceiling is narrower          child ≤ parent
 *   gteq / gt   a higher floor is narrower           child ≥ parent
 *   isAnyOf     a SMALLER allow-list is narrower     child ⊆ parent
 *   isNoneOf    a LARGER deny-list is narrower       child ⊇ parent
 *   before      an earlier deadline is narrower      child ≤ parent
 *   after       a later start is narrower            child ≥ parent
 *   eq          only the same value is narrower      child = parent
 *
 * And the rule that is easiest to miss: a parent constraint the child simply OMITS is a
 * widening. A child that drops the parent's spend cap has more authority than its parent,
 * which is exactly the escalation this whole check exists to prevent.
 *
 * Fail-closed throughout. An operator, an operand or a shape this code cannot compare is
 * refused rather than waved through — an unverifiable narrowing claim is not a narrowing.
 */

import type { Constraint, Mandate, Operator, Permission } from './mandate.types.js';

/**
 * How deep a delegation chain may go.
 *
 * Three: a principal's agent may delegate to a worker, and that worker to one more. Beyond
 * that, an on-behalf-of chain stops being a harness and becomes a place for authority to
 * get lost — and every hop is another party who must be trusted to have narrowed honestly.
 * A bound also makes cycle detection unnecessary at evaluation time.
 */
export const MAX_DELEGATION_DEPTH = 3;

export type DelegationRefusal =
  | 'DEPTH_EXCEEDED'
  | 'ACTION_NOT_IN_PARENT'
  | 'CONSTRAINT_DROPPED'
  | 'CONSTRAINT_WIDENED'
  | 'VALIDITY_WIDENED'
  | 'PROHIBITION_DROPPED'
  | 'UNCOMPARABLE';

export interface DelegationVerdict {
  ok: boolean;
  refusal: DelegationRefusal | null;
  /** Which operand or action failed, so a rejection is actionable rather than a shrug. */
  detail: string | null;
}

const ok = (): DelegationVerdict => ({ ok: true, refusal: null, detail: null });
const no = (refusal: DelegationRefusal, detail: string): DelegationVerdict => ({ ok: false, refusal, detail });

const num = (v: unknown): number | null => {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
};

const time = (v: unknown): number | null => {
  if (typeof v !== 'string') return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
};

const set = (v: unknown): string[] | null => (Array.isArray(v) ? v.map((x) => String(x)) : null);

/**
 * Is the child's constraint at least as restrictive as the parent's, for the same operand
 * and operator?
 *
 * Returns null when the pair cannot be compared at all, which the caller treats as a
 * refusal. Comparing a `lteq` against an `isAnyOf` on the same operand is not a narrowing
 * question with an answer — it is two different claims, and permitting it would let a
 * child swap a cap it cannot satisfy for a list it can.
 */
export function constraintNarrows(parent: Constraint, child: Constraint): boolean | null {
  if (parent.operator !== child.operator) return null;

  const operator: Operator = parent.operator;
  switch (operator) {
    case 'lteq':
    case 'lt': {
      const p = num(parent.rightOperand);
      const c = num(child.rightOperand);
      return p === null || c === null ? null : c <= p;
    }
    case 'gteq':
    case 'gt': {
      const p = num(parent.rightOperand);
      const c = num(child.rightOperand);
      return p === null || c === null ? null : c >= p;
    }
    case 'isAnyOf':
    case 'isPartOf': {
      // A smaller allow-list is narrower: everything the child permits, the parent did too.
      const p = set(parent.rightOperand);
      const c = set(child.rightOperand);
      return p === null || c === null ? null : c.every((v) => p.includes(v));
    }
    case 'isNoneOf': {
      // Inverted: a LARGER deny-list is narrower. Getting this backwards would let a child
      // delete its parent's exclusions and call the result a narrowing.
      const p = set(parent.rightOperand);
      const c = set(child.rightOperand);
      return p === null || c === null ? null : p.every((v) => c.includes(v));
    }
    case 'before': {
      const p = time(parent.rightOperand);
      const c = time(child.rightOperand);
      return p === null || c === null ? null : c <= p;
    }
    case 'after': {
      const p = time(parent.rightOperand);
      const c = time(child.rightOperand);
      return p === null || c === null ? null : c >= p;
    }
    case 'eq':
      // Only the identical value is as narrow; anything else is a different permission.
      return parent.rightOperand === child.rightOperand;
    case 'neq':
      return parent.rightOperand === child.rightOperand;
    default:
      return null;
  }
}

/** Every permission in a mandate that targets this action. */
function permissionsFor(mandate: Mandate, target: string): Permission[] {
  return (mandate.permission ?? []).filter((p) => (p.target ?? mandate.target) === target);
}

/**
 * Does one permission narrow another?
 *
 * Every parent constraint must be MET by a child constraint on the same operand — dropping
 * one is a widening, not a simplification. Extra child constraints the parent never had
 * are fine: they can only remove authority.
 */
function permissionNarrows(parent: Permission, child: Permission): DelegationVerdict {
  for (const pc of parent.constraint ?? []) {
    const matches = (child.constraint ?? []).filter((cc) => cc.leftOperand === pc.leftOperand);
    if (matches.length === 0) {
      return no('CONSTRAINT_DROPPED', pc.leftOperand);
    }
    // Any one matching child constraint that narrows is enough — a child may express the
    // same restriction more than once.
    let narrowed = false;
    let comparable = false;
    for (const cc of matches) {
      const verdict = constraintNarrows(pc, cc);
      if (verdict === null) continue;
      comparable = true;
      if (verdict) {
        narrowed = true;
        break;
      }
    }
    if (!comparable) return no('UNCOMPARABLE', `${pc.leftOperand} (${pc.operator})`);
    if (!narrowed) return no('CONSTRAINT_WIDENED', pc.leftOperand);
  }
  return ok();
}

/**
 * May `child` be delegated from `parent`?
 *
 * `depth` is the child's position in the chain: 1 for the first delegation from a
 * principal-issued mandate.
 */
export function delegationVerdict(parent: Mandate, child: Mandate, depth: number): DelegationVerdict {
  if (!Number.isFinite(depth) || depth < 1 || depth > MAX_DELEGATION_DEPTH) {
    return no('DEPTH_EXCEEDED', `depth ${depth} exceeds ${MAX_DELEGATION_DEPTH}`);
  }

  // Validity: the child may not outlive its parent, nor start before it.
  const pFrom = time(parent.validFrom);
  const cFrom = time(child.validFrom);
  if (pFrom !== null && (cFrom === null || cFrom < pFrom)) return no('VALIDITY_WIDENED', 'validFrom');
  const pUntil = time(parent.validUntil);
  const cUntil = time(child.validUntil);
  if (pUntil !== null && (cUntil === null || cUntil > pUntil)) return no('VALIDITY_WIDENED', 'validUntil');

  // Every action the child permits must be one the parent permitted, and narrowed.
  const childPermissions = child.permission ?? [];
  if (childPermissions.length === 0) return ok(); // a mandate granting nothing cannot widen

  for (const cp of childPermissions) {
    const target = cp.target ?? child.target;
    if (!target) return no('UNCOMPARABLE', 'permission has no target');
    const candidates = permissionsFor(parent, target);
    if (candidates.length === 0) return no('ACTION_NOT_IN_PARENT', target);

    // The child narrows if ANY parent permission for this action covers it — a parent may
    // grant one action through several permissions, and satisfying one is enough.
    let best: DelegationVerdict | null = null;
    let covered = false;
    for (const pp of candidates) {
      const verdict = permissionNarrows(pp, cp);
      if (verdict.ok) {
        covered = true;
        break;
      }
      best = best ?? verdict;
    }
    if (!covered) return best ?? no('CONSTRAINT_WIDENED', target);
  }

  // A prohibition is authority REMOVED, so the child must keep every one of the parent's.
  // Dropping one would let a delegated agent do what its delegator was forbidden.
  for (const pp of parent.prohibition ?? []) {
    const target = pp.target ?? parent.target;
    const kept = (child.prohibition ?? []).some((cp) => (cp.target ?? child.target) === target);
    if (!kept) return no('PROHIBITION_DROPPED', String(target));
  }

  return ok();
}

/** Convenience for callers that only need the boolean. */
export function narrows(parent: Mandate, child: Mandate, depth = 1): boolean {
  return delegationVerdict(parent, child, depth).ok;
}

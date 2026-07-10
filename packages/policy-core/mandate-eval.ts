/**
 * Pure ODRL-style mandate evaluator — no DB / IO, so it is fully unit-testable.
 * The service resolves stateful operands (e.g. cumulative spend) from replayed
 * on-chain events and passes them in `request.values`; this module only decides.
 *
 * Evaluation is a pure, deterministic function of (mandate, request), so a
 * counterparty can independently recompute the decision. See design §3.4.
 */

import type {
  BudgetState,
  Constraint,
  Mandate,
  MandateRequest,
  MandateResult,
  Operator,
  Permission,
  Prohibition,
} from './mandate.types.js';

const toNum = (v: unknown): number => (typeof v === 'number' ? v : Number(v));
const toArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
const toTime = (v: unknown): number => Date.parse(String(v)); // deterministic; not Date.now()

/**
 * The fixed operator set. Comparisons against an unresolved (undefined) or
 * non-numeric operand fail closed (NaN comparisons are false), so a missing
 * value never accidentally grants a permission.
 */
const OPERATORS: Record<Operator, (left: unknown, right: unknown) => boolean> = {
  eq: (l, r) => l === r,
  neq: (l, r) => l !== r,
  lt: (l, r) => toNum(l) < toNum(r),
  lteq: (l, r) => toNum(l) <= toNum(r),
  gt: (l, r) => toNum(l) > toNum(r),
  gteq: (l, r) => toNum(l) >= toNum(r),
  isAnyOf: (l, r) => toArray(r).includes(l),
  isNoneOf: (l, r) => !toArray(r).includes(l),
  isPartOf: (l, r) => toArray(r).includes(l),
  before: (l, r) => toTime(l) < toTime(r),
  after: (l, r) => toTime(l) > toTime(r),
};

/** Map well-known operands to stable reason codes; fall back to a generic code. */
const REASON_BY_OPERAND: Record<string, string> = {
  'mm:payAmount': 'SPEND_LIMIT_EXCEEDED',
  'mm:cumulativeSpend': 'SPEND_LIMIT_EXCEEDED',
  'mm:merchant': 'MERCHANT_NOT_ALLOWED',
  'mm:route': 'ROUTE_NOT_ALLOWED',
  'mm:counterparty': 'COUNTERPARTY_NOT_ALLOWED',
};

function reasonFor(constraint: Constraint | undefined): string {
  if (!constraint) return 'CONSTRAINT_FAILED';
  return REASON_BY_OPERAND[constraint.leftOperand] ?? `CONSTRAINT_FAILED:${constraint.leftOperand}`;
}

function constraintSatisfied(c: Constraint, req: MandateRequest): boolean {
  const op = OPERATORS[c.operator];
  if (!op) return false; // unknown operator -> fail closed
  const left = Object.prototype.hasOwnProperty.call(req.values, c.leftOperand)
    ? req.values[c.leftOperand]
    : undefined;
  return op(left, c.rightOperand);
}

function targetOf(rule: Permission | Prohibition, mandate: Mandate): string | undefined {
  return rule.target ?? mandate.target;
}

/**
 * Evaluate a mandate against a single authorization request.
 *
 * Order: (1) validity window, (2) prohibitions win, (3) a matching permission
 * whose constraints ALL hold grants `allow`; otherwise the first failing
 * constraint's `onFail` (default 'block') decides.
 */
export function evaluateMandate(mandate: Mandate, req: MandateRequest): MandateResult {
  const now = toTime(req.now);

  // 1. Validity window.
  if (mandate.validFrom && now < toTime(mandate.validFrom)) {
    return { decision: 'block', reasonCode: 'MANDATE_NOT_YET_VALID', matched: { kind: 'expiry' } };
  }
  if (mandate.validUntil && now > toTime(mandate.validUntil)) {
    return { decision: 'block', reasonCode: 'MANDATE_EXPIRED', matched: { kind: 'expiry' } };
  }

  // 2. Prohibitions win. A prohibition fires when ALL its constraints hold
  //    (no constraints = an unconditional prohibition for that target).
  for (const p of mandate.prohibition ?? []) {
    if (targetOf(p, mandate) !== req.target) continue;
    const fires = (p.constraint ?? []).every((c) => constraintSatisfied(c, req));
    if (fires) {
      return {
        decision: p.enforcement ?? 'block',
        reasonCode: p.reasonCode ?? 'PROHIBITED',
        matched: { kind: 'prohibition', target: p.target },
      };
    }
  }

  // 3. Permissions for this target.
  const perms = (mandate.permission ?? []).filter((p) => targetOf(p, mandate) === req.target);
  if (perms.length === 0) {
    return {
      decision: 'block',
      reasonCode: 'NO_PERMISSION_FOR_ACTION',
      matched: { kind: 'no-permission', target: req.target },
    };
  }

  // A permission grants when ALL its constraints hold (no constraints = always).
  for (const p of perms) {
    const failing = (p.constraint ?? []).find((c) => !constraintSatisfied(c, req));
    if (!failing) return { decision: 'allow', reasonCode: 'AUTHORIZED' };
  }

  // None granted — report the first failing constraint of the first permission.
  const firstFail = (perms[0].constraint ?? []).find((c) => !constraintSatisfied(c, req));
  return {
    decision: firstFail?.onFail ?? 'block',
    reasonCode: reasonFor(firstFail),
    matched: { kind: 'permission', target: perms[0].target, constraint: firstFail },
  };
}

// ---------------------------------------------------------------------------
// Budget helpers — cumulative-spend enforcement across the two-phase
// authorize(hold) -> capture(commit) flow. All pure.
// ---------------------------------------------------------------------------

/** Remaining spendable budget: cap minus already-spent minus outstanding holds. */
export function remainingBudget(b: BudgetState): number {
  return Math.max(0, b.cap - b.spent - b.held);
}

export function canAuthorize(b: BudgetState, amount: number): boolean {
  return amount >= 0 && amount <= remainingBudget(b);
}

/** Place a hold for an authorized-but-not-yet-captured amount. */
export function applyHold(b: BudgetState, amount: number): BudgetState {
  return { ...b, held: b.held + amount };
}

/** Commit the actually-charged amount: move it from held to spent. */
export function applyCapture(b: BudgetState, amount: number): BudgetState {
  return { cap: b.cap, spent: b.spent + amount, held: Math.max(0, b.held - amount) };
}

/** Release a hold without charging (e.g. the booking failed). */
export function releaseHold(b: BudgetState, amount: number): BudgetState {
  return { ...b, held: Math.max(0, b.held - amount) };
}

/**
 * Sum a numeric field over events of a given type — the pure kernel behind the
 * `mm:cumulativeSpend` resolver, which the service feeds with replayed events.
 */
export function sumEventField(
  events: { type: string; payload: Record<string, unknown> }[],
  type: string,
  field: string,
): number {
  return events
    .filter((e) => e.type === type)
    .reduce((acc, e) => acc + (typeof e.payload[field] === 'number' ? (e.payload[field] as number) : 0), 0);
}

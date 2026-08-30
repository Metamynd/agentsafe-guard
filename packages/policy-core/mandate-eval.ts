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

/**
 * Whether `c` holds against `req`.
 *
 * A constraint stamped with a `unit` (payAmount/cumulativeSpend are always issued with one
 * — see issueMandate) is a threshold denominated in THAT currency; a bare numeric
 * comparison treats a 100000 JPY cap and a 100000 USD request as identically "at the
 * limit," letting an attacker clear a cap by orders of magnitude just by naming a
 * cheaper-looking currency (or, letting a value-based PROHIBITION be dodged the same way —
 * see below). `mm:currency` is signed-last context (see authorize()), so it can't be
 * spoofed via an unsigned itinerary field. Compared case-insensitively: currency codes are
 * conventionally uppercase, but a legitimately-lowercase 'usd' must still count as a match
 * rather than being treated as a mismatch (which would itself be exploitable — see below).
 *
 * `strict` governs how a MISMATCHED (or unreadable) currency resolves, because "satisfied"
 * means opposite things depending on which rule reads it:
 *   - A PERMISSION requires every constraint to be PROVEN true to grant. An unverifiable
 *     currency must not count as proof — fail closed by treating it as NOT satisfied
 *     (`strict: true`).
 *   - A PROHIBITION requires every constraint to be PROVEN true to FIRE (block). Reusing
 *     the same "unverifiable → not satisfied" rule here fails OPEN: `every()` would then
 *     skip firing the prohibition entirely, so a value-based prohibition like
 *     `payAmount gteq 1000 unit USD` is silently dodged by declaring any other currency —
 *     including a case difference before the fix above. An unverifiable currency must
 *     instead count as NOT ruling the dangerous condition out — fail closed the OTHER way,
 *     by treating it as satisfied (`strict: false`), so the prohibition still fires.
 */
function constraintSatisfied(c: Constraint, req: MandateRequest, strict: boolean): boolean {
  const op = OPERATORS[c.operator];
  if (!op) return false; // unknown operator -> fail closed
  const left = Object.prototype.hasOwnProperty.call(req.values, c.leftOperand)
    ? req.values[c.leftOperand]
    : undefined;
  if (!c.unit) return op(left, c.rightOperand);
  const currency = req.values['mm:currency'];
  const unitMatches = typeof currency === 'string' && currency.toUpperCase() === c.unit.toUpperCase();
  return unitMatches ? op(left, c.rightOperand) : !strict;
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
/**
 * Did this evaluation fail for want of AUTHORITY, rather than for breaking a rule?
 *
 * The distinction is the whole point. `expiry` and `no-permission` mean the agent had no
 * standing to ask at all, and neither answer depends on the amount, the merchant or
 * anything else about the request. `permission` (a constraint on a granted target) and
 * `prohibition` are statements about HOW a granted action may be performed — the same
 * class of thing a Standard or an SOP says, and rightly ranked alongside them.
 *
 * This exists because of a precedence bug worth remembering. The rule layers were
 * evaluated before the mandate, and a rule block and a mandate block tie on
 * restrictiveness, so whichever ran first kept the reason code. An agent asking to raise
 * its own spend limit to $100,000 therefore got back `SOP_SPEND_CAP` — because a
 * spend-cap rule fired on the amount — while the identical call at $1 got
 * `NO_PERMISSION_FOR_ACTION`. Both blocked, so nothing was unsafe, and the verdict was
 * still wrong in the way that matters: it says a larger cap would have let an agent
 * rewrite its own authority. It would not. A developer reading the reason code cannot know
 * that, and an auditor reading the evidence trail would credit the wrong control with
 * having held.
 *
 * So an authority failure is returned as the reason, ahead of any rule. Nothing a rule
 * says about how an action may be performed can be why an action nobody authorised failed.
 */
export function isAuthorityFailure(result: MandateResult): boolean {
  return result.matched?.kind === 'expiry' || result.matched?.kind === 'no-permission';
}

/**
 * The authority failure for this target, or null if the mandate grants standing to ask.
 *
 * For callers that have a target but not yet a resolved operand map — the gate asks this
 * before it has replayed cumulative spend. Safe to ask early precisely because an
 * authority answer cannot depend on operands: an expired mandate grants nothing, and a
 * target with no permission has no constraints to satisfy.
 *
 * Deliberately delegates to `evaluateMandate` rather than re-deriving the answer, so the
 * order between expiry, prohibitions and permissions is guaranteed by the one evaluator
 * instead of being restated — and stays guaranteed when that order next changes.
 *
 * Narrowed to `block` because every authority failure is one: having no standing to ask is
 * not a thing a human approver can resolve, so it is never an escalate. Callers that
 * return a narrower decision union get to keep it.
 */
export function authorityFailure(
  mandate: Mandate,
  target: string,
  now: string,
): (MandateResult & { decision: 'block' }) | null {
  const result = evaluateMandate(mandate, { target, now, values: {} });
  return isAuthorityFailure(result) ? { ...result, decision: 'block' } : null;
}

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
    const fires = (p.constraint ?? []).every((c) => constraintSatisfied(c, req, false));
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
    const failing = (p.constraint ?? []).find((c) => !constraintSatisfied(c, req, true));
    if (!failing) return { decision: 'allow', reasonCode: 'AUTHORIZED' };
  }

  // None granted — report the first failing constraint of the first permission.
  const firstFail = (perms[0].constraint ?? []).find((c) => !constraintSatisfied(c, req, true));
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

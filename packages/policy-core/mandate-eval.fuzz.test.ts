import { describe, it } from 'vitest';
import fc from 'fast-check';
import { evaluateMandate } from './mandate-eval.js';
import type { Constraint, Mandate, MandateDecision, MandateRequest, Operator } from './mandate.types.js';

/**
 * Property-based fuzzing for the constraint evaluator, complementing the example-based
 * tests in mandate-eval.test.ts. Those tests encode SPECIFIC known-attack shapes (a
 * particular currency, a particular amount); this file instead asserts INVARIANTS that
 * must hold for every input in a space fast-check explores automatically — including
 * shrunk minimal counterexamples if one is found. This is the second half of the
 * currency-unit regression (see constraintSatisfied's own comment in mandate-eval.ts):
 * the 0.3.3 bug and its fix were both about ONE input; the invariant below is about ALL
 * of them.
 */

const NOW = '2026-08-01T09:00:00Z';
const OPERATORS: Operator[] = ['eq', 'neq', 'lt', 'lteq', 'gt', 'gteq'];
const TARGET = 'mm:test-action';

function prohibitionMandate(constraint: Constraint): Mandate {
  return {
    target: TARGET,
    prohibition: [{ target: TARGET, constraint: [constraint] }],
    // An unconditional permission so a NON-firing prohibition falls through to 'allow'
    // rather than 'no-permission' — otherwise "did the prohibition fire?" can't be read
    // off the decision alone.
    permission: [{ target: TARGET }],
  };
}

function permissionMandate(constraint: Constraint): Mandate {
  return { target: TARGET, permission: [{ target: TARGET, constraint: [constraint] }] };
}

function req(values: Record<string, unknown>): MandateRequest {
  return { target: TARGET, now: NOW, values };
}

function prohibitionFires(constraint: Constraint, values: Record<string, unknown>): boolean {
  return evaluateMandate(prohibitionMandate(constraint), req(values)).matched?.kind === 'prohibition';
}

function permissionGrants(constraint: Constraint, values: Record<string, unknown>): boolean {
  return evaluateMandate(permissionMandate(constraint), req(values)).decision === 'allow';
}

/** Re-case a fixed string randomly (same characters, arbitrary upper/lower per position). */
const recasedVariantOf = (s: string) =>
  fc.array(fc.boolean(), { minLength: s.length, maxLength: s.length }).map((flags) =>
    s
      .split('')
      .map((ch, i) => (flags[i] ? ch.toUpperCase() : ch.toLowerCase()))
      .join(''),
  );

const currencyArb = fc.constantFrom('USD', 'EUR', 'GBP', 'JPY');
const operatorArb = fc.constantFrom(...OPERATORS);
const amountArb = fc.integer({ min: -1_000_000, max: 1_000_000 });

/** A value that could plausibly show up where a currency is expected, but never matches. */
const unrelatedCurrencyLikeArb = fc.oneof(
  fc.constantFrom('CAD', 'AUD', 'CHF', 'INR', ''),
  fc.integer(),
  fc.boolean(),
  fc.constant(undefined),
  fc.constant(null),
  fc.array(fc.string()),
);

describe('constraintSatisfied (via evaluateMandate) — unit/currency invariants', () => {
  it('a unit-bearing PROHIBITION fires regardless of amount whenever the currency does not verifiably match', () => {
    fc.assert(
      fc.property(currencyArb, operatorArb, amountArb, amountArb, unrelatedCurrencyLikeArb, (unit, operator, left, right, badCurrency) => {
        // badCurrency is drawn from values that never equal `unit` case-insensitively.
        fc.pre(String(badCurrency ?? '').toUpperCase() !== unit);
        const constraint: Constraint = { leftOperand: 'mm:payAmount', operator, rightOperand: right, unit };
        const fires = prohibitionFires(constraint, { 'mm:payAmount': left, 'mm:currency': badCurrency });
        return fires === true; // must ALWAYS fire — an unverifiable currency must never rule the danger out
      }),
    );
  });

  it('a unit-bearing PERMISSION never grants whenever the currency does not verifiably match', () => {
    fc.assert(
      fc.property(currencyArb, operatorArb, amountArb, amountArb, unrelatedCurrencyLikeArb, (unit, operator, left, right, badCurrency) => {
        fc.pre(String(badCurrency ?? '').toUpperCase() !== unit);
        const constraint: Constraint = { leftOperand: 'mm:payAmount', operator, rightOperand: right, unit };
        const grants = permissionGrants(constraint, { 'mm:payAmount': left, 'mm:currency': badCurrency });
        return grants === false; // must NEVER grant — an unverifiable currency must never count as proof
      }),
    );
  });

  it('currency matching is case-insensitive: any re-casing of the correct currency behaves identically to the canonical case', () => {
    fc.assert(
      fc.property(
        currencyArb.chain((unit) => fc.tuple(fc.constant(unit), recasedVariantOf(unit))),
        operatorArb,
        amountArb,
        amountArb,
        ([unit, recased], operator, left, right) => {
          const constraint: Constraint = { leftOperand: 'mm:payAmount', operator, rightOperand: right, unit };
          const canonical = prohibitionFires(constraint, { 'mm:payAmount': left, 'mm:currency': unit });
          const viaRecased = prohibitionFires(constraint, { 'mm:payAmount': left, 'mm:currency': recased });
          return canonical === viaRecased;
        },
      ),
    );
  });

  it('once the currency verifiably matches, the outcome equals the plain operator comparison, independent of strict/permission-vs-prohibition', () => {
    fc.assert(
      fc.property(currencyArb, operatorArb, amountArb, amountArb, (unit, operator, left, right) => {
        const constraint: Constraint = { leftOperand: 'mm:payAmount', operator, rightOperand: right, unit };
        const values = { 'mm:payAmount': left, 'mm:currency': unit };
        const fires = prohibitionFires(constraint, values);
        const grants = permissionGrants(constraint, values);
        const plain = plainOperator(operator, left, right);
        // A matching currency removes the fail-closed carve-out entirely: prohibition fires
        // iff the plain comparison holds, and permission grants iff it holds too — the two
        // rules only ever disagreed because of the unit/currency branch, never here.
        return fires === plain && grants === plain;
      }),
    );
  });
});

function plainOperator(op: Operator, l: number, r: number): boolean {
  switch (op) {
    case 'eq':
      return l === r;
    case 'neq':
      return l !== r;
    case 'lt':
      return l < r;
    case 'lteq':
      return l <= r;
    case 'gt':
      return l > r;
    case 'gteq':
      return l >= r;
    default:
      throw new Error(`unexpected operator in fixture: ${op}`);
  }
}

/**
 * Arbitrary, structurally-plausible mandates and requests — not aimed at any specific
 * bug, just at the general soundness properties every mandate must have: the evaluator
 * must never throw on well-typed-but-otherwise-arbitrary input, and must always return a
 * decision from the fixed vocabulary with a non-empty reason code. A throw or an
 * out-of-vocabulary decision would surface as an unhandled 500 in the real authorize()
 * path — the one place this evaluator is actually called from a live request.
 */
const DECISIONS: MandateDecision[] = ['allow', 'observe', 'block', 'escalate', 'suspend', 'quarantine', 'decommission'];
const operandArb = fc.constantFrom('mm:payAmount', 'mm:cumulativeSpend', 'mm:merchant', 'mm:route', 'mm:counterparty', 'mm:unknownOperand');
const rightOperandArb = fc.oneof(fc.integer(), fc.string(), fc.array(fc.string(), { maxLength: 3 }), fc.constant(undefined), fc.boolean());
const constraintArb: fc.Arbitrary<Constraint> = fc.record({
  leftOperand: operandArb,
  operator: fc.oneof(operatorArb, fc.constantFrom('isAnyOf', 'isNoneOf', 'isPartOf', 'before', 'after'), fc.string()) as fc.Arbitrary<Operator>,
  rightOperand: rightOperandArb,
  unit: fc.option(currencyArb, { nil: undefined }),
});
const permissionArb: fc.Arbitrary<Mandate['permission']> = fc.array(
  fc.record({ target: fc.constant(TARGET), constraint: fc.array(constraintArb, { maxLength: 3 }) }),
  { maxLength: 2 },
);
const prohibitionArb: fc.Arbitrary<Mandate['prohibition']> = fc.array(
  fc.record({ target: fc.constant(TARGET), constraint: fc.array(constraintArb, { maxLength: 3 }) }),
  { maxLength: 2 },
);
const valuesArb = fc.dictionary(
  operandArb,
  fc.oneof(fc.integer(), fc.string(), fc.constant(undefined), fc.constant(null)),
);

describe('evaluateMandate — general robustness', () => {
  it('never throws and always returns a known decision + non-empty reason code, for arbitrary mandate/request shapes', () => {
    fc.assert(
      fc.property(permissionArb, prohibitionArb, valuesArb, (permission, prohibition, values) => {
        const mandate: Mandate = { target: TARGET, permission, prohibition };
        const result = evaluateMandate(mandate, req(values));
        return DECISIONS.includes(result.decision) && typeof result.reasonCode === 'string' && result.reasonCode.length > 0;
      }),
    );
  });

  it('is pure/deterministic: identical (mandate, request) always yields an identical result', () => {
    fc.assert(
      fc.property(permissionArb, prohibitionArb, valuesArb, (permission, prohibition, values) => {
        const mandate: Mandate = { target: TARGET, permission, prohibition };
        const r1 = evaluateMandate(structuredClone(mandate), req(structuredClone(values)));
        const r2 = evaluateMandate(structuredClone(mandate), req(structuredClone(values)));
        return JSON.stringify(r1) === JSON.stringify(r2);
      }),
    );
  });
});

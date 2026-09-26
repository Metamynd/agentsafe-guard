import { describe, expect, it } from 'vitest';
import { evaluateMandate } from './mandate-eval.js';
import { documentEnforcesJurisdiction, evaluateBoundStandards, type StandardDocument } from './standards-rules.js';
import type { Mandate } from './mandate.types.js';

/** Milestone 2a in policy-core: the jurisdiction reason codes, and the "an enforced jurisdiction rule is bound" signal. */
const mandate = (operand = 'mm:jurisdiction'): Mandate =>
  ({ target: 'a', permission: [{ target: 'a', action: 'execute', constraint: [{ leftOperand: operand, operator: 'isAnyOf', rightOperand: ['DE', 'SG'] }] }] }) as Mandate;
const judge = (values: Record<string, unknown>, operand?: string) => evaluateMandate(mandate(operand), { target: 'a', now: '2026-09-27T00:00:00.000Z', values });

describe('the allowed-jurisdictions constraint names its failure', () => {
  it('a value outside the list is JURISDICTION_NOT_ALLOWED', () => {
    expect(judge({ 'mm:jurisdiction': 'US' })).toMatchObject({ decision: 'block', reasonCode: 'JURISDICTION_NOT_ALLOWED' });
    expect(judge({ jurisdiction: 'US' }, 'jurisdiction')).toMatchObject({ decision: 'block', reasonCode: 'JURISDICTION_NOT_ALLOWED' });
  });
  it('no value (absent, undefined, null, empty) is JURISDICTION_REQUIRED', () => {
    for (const values of [{}, { 'mm:jurisdiction': undefined }, { 'mm:jurisdiction': null }, { 'mm:jurisdiction': '' }]) {
      expect(judge(values)).toMatchObject({ decision: 'block', reasonCode: 'JURISDICTION_REQUIRED' });
    }
  });
  it('a value on the list passes', () => {
    expect(judge({ 'mm:jurisdiction': 'SG' }).decision).toBe('allow');
  });
});

const doc = (decision: 'block' | 'escalate' | 'observe', predicate = 'jurisdiction-not-allowed'): StandardDocument => ({
  molecules: [{ id: 'm', combinator: 'any', atoms: [{ id: 'x', predicate, config: { allowed: ['DE'] } }], decision, reasonCode: 'R' }],
});

describe('documentEnforcesJurisdiction / evaluateBoundStandards.jurisdictionRequired', () => {
  it('a molecule that can refuse on jurisdiction-not-allowed enforces it; an observe-only one does not', () => {
    expect(documentEnforcesJurisdiction(doc('block'))).toBe(true);
    expect(documentEnforcesJurisdiction(doc('escalate'))).toBe(true);
    expect(documentEnforcesJurisdiction(doc('observe'))).toBe(false);
    expect(documentEnforcesJurisdiction(doc('block', 'model-not-allowed'))).toBe(false);
    expect(documentEnforcesJurisdiction(null)).toBe(false);
  });
  it('is flagged on the combined result (whatever fired), and absent otherwise so existing results are unchanged', () => {
    expect(evaluateBoundStandards([{ standardKey: 's', document: doc('block') }], {} as never)).toEqual({ decision: 'allow', reasonCode: null, firedMoleculeId: null, standardKey: null, jurisdictionRequired: true });
    expect(evaluateBoundStandards([{ standardKey: 's', document: doc('block') }], { jurisdiction: 'US' } as never)).toMatchObject({ decision: 'block', reasonCode: 'R', jurisdictionRequired: true });
    expect(evaluateBoundStandards([{ standardKey: 's', document: doc('observe') }], {} as never)).not.toHaveProperty('jurisdictionRequired');
    expect(evaluateBoundStandards([], {} as never)).not.toHaveProperty('jurisdictionRequired');
  });
});

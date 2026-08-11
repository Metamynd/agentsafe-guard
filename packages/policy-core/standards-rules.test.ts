import { describe, it, expect } from 'vitest';
import {
  moleculeFires,
  evaluateStandardRules,
  evaluateBoundStandards,
  validateMolecules,
  type Molecule,
} from './standards-rules.js';
import type { EvaluationContext } from './types.js';

const ctx = (over: Partial<EvaluationContext>): EvaluationContext => ({ action: 'test', ...over });

const spendMolecule: Molecule = {
  id: 'spend',
  combinator: 'any',
  atoms: [{ id: 'a1', predicate: 'amount-over', config: { limit: 100 } }],
  decision: 'block',
  reasonCode: 'SPEND_LIMIT_EXCEEDED',
};

describe('molecule combinators', () => {
  const m = (combinator: Molecule['combinator']): Molecule => ({
    id: 'm',
    combinator,
    decision: 'block',
    reasonCode: 'X',
    atoms: [
      { id: 'a', predicate: 'amount-over', config: { limit: 100 } }, // true when amount>100
      { id: 'b', predicate: 'consent-missing' }, // true when consent===false
    ],
  });

  it('all = AND: fires only when every atom fires', () => {
    expect(moleculeFires(m('all'), ctx({ amount: 200, consent: false }))).toBe(true);
    expect(moleculeFires(m('all'), ctx({ amount: 200, consent: true }))).toBe(false);
  });
  it('any = OR: fires when at least one atom fires', () => {
    expect(moleculeFires(m('any'), ctx({ amount: 200, consent: true }))).toBe(true);
    expect(moleculeFires(m('any'), ctx({ amount: 10, consent: true }))).toBe(false);
  });
  it('none = NOT-any: fires when no atom fires', () => {
    expect(moleculeFires(m('none'), ctx({ amount: 10, consent: true }))).toBe(true);
    expect(moleculeFires(m('none'), ctx({ amount: 200, consent: true }))).toBe(false);
  });
  it('an empty molecule never fires', () => {
    expect(moleculeFires({ id: 'e', combinator: 'all', atoms: [], decision: 'block', reasonCode: 'X' }, ctx({}))).toBe(false);
  });
});

describe('evaluateStandardRules', () => {
  it('allows when nothing fires', () => {
    expect(evaluateStandardRules([spendMolecule], ctx({ amount: 50 })).decision).toBe('allow');
  });
  it('blocks with the firing molecule reason', () => {
    const r = evaluateStandardRules([spendMolecule], ctx({ amount: 500 }));
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('SPEND_LIMIT_EXCEEDED');
    expect(r.firedMoleculeId).toBe('spend');
  });
  it('most-restrictive wins regardless of order (block over escalate)', () => {
    const escalate: Molecule = {
      id: 'esc',
      combinator: 'any',
      atoms: [{ id: 'r', predicate: 'risk-at-or-above', config: { level: 'high' } }],
      decision: 'escalate',
      reasonCode: 'RISK',
    };
    const c = ctx({ amount: 500, riskLevel: 'critical' });
    expect(evaluateStandardRules([escalate, spendMolecule], c).decision).toBe('block');
    expect(evaluateStandardRules([spendMolecule, escalate], c).decision).toBe('block');
  });
  it('is deterministic — identical inputs give identical output', () => {
    const c = ctx({ amount: 500 });
    expect(evaluateStandardRules([spendMolecule], c)).toEqual(evaluateStandardRules([spendMolecule], c));
  });
});

describe('evaluateBoundStandards (union across an agent’s standards)', () => {
  it('one blocking molecule anywhere blocks the action', () => {
    const r = evaluateBoundStandards(
      [
        { standardKey: 'ok-std', document: { molecules: [] } },
        { standardKey: 'spend-std', document: { molecules: [spendMolecule] } },
      ],
      ctx({ amount: 500 }),
    );
    expect(r.decision).toBe('block');
    expect(r.standardKey).toBe('spend-std');
  });
  it('allows when no bound standard fires', () => {
    expect(
      evaluateBoundStandards([{ standardKey: 'spend-std', document: { molecules: [spendMolecule] } }], ctx({ amount: 1 }))
        .decision,
    ).toBe('allow');
  });
});

describe('compliance atoms', () => {
  const fires = (predicate: string, config: Record<string, unknown>, over: Partial<EvaluationContext>) =>
    moleculeFires(
      { id: 'm', combinator: 'any', decision: 'block', reasonCode: 'X', atoms: [{ id: 'a', predicate, config }] },
      ctx(over),
    );

  it('jurisdiction-not-allowed: fires only when present and off the allow-list (case-insensitive)', () => {
    expect(fires('jurisdiction-not-allowed', { allowed: ['US', 'MY'] }, { jurisdiction: 'DE' })).toBe(true);
    expect(fires('jurisdiction-not-allowed', { allowed: ['US', 'MY'] }, { jurisdiction: 'us' })).toBe(false);
    expect(fires('jurisdiction-not-allowed', { allowed: ['US'] }, {})).toBe(false); // missing → does not fire
  });
  it('data-residency-violation: fires when region not allowed', () => {
    expect(fires('data-residency-violation', { allowedRegions: ['eu'] }, { dataResidency: 'us-east' })).toBe(true);
    expect(fires('data-residency-violation', { allowedRegions: ['eu'] }, { dataResidency: 'EU' })).toBe(false);
  });
  it('model-not-allowed: fires when the model is off the approved list', () => {
    expect(fires('model-not-allowed', { allowed: ['claude-sonnet-5'] }, { model: 'gpt-4.1' })).toBe(true);
    expect(fires('model-not-allowed', { allowed: ['claude-sonnet-5'] }, { model: 'claude-sonnet-5' })).toBe(false);
  });
  it('tool-not-allowed: fires when the tool is not approved', () => {
    expect(fires('tool-not-allowed', { allowed: ['search'] }, { tool: 'wire-transfer' })).toBe(true);
    expect(fires('tool-not-allowed', { allowed: ['search', 'wire-transfer'] }, { tool: 'wire-transfer' })).toBe(false);
  });
  it('pii-present: fires only when explicitly flagged', () => {
    expect(fires('pii-present', {}, { piiPresent: true })).toBe(true);
    expect(fires('pii-present', {}, { piiPresent: false })).toBe(false);
    expect(fires('pii-present', {}, {})).toBe(false);
  });
  it('rate-limit-exceeded: fires when callCount exceeds max', () => {
    expect(fires('rate-limit-exceeded', { max: 100 }, { callCount: 150 })).toBe(true);
    expect(fires('rate-limit-exceeded', { max: 100 }, { callCount: 50 })).toBe(false);
  });
});

describe('validateMolecules', () => {
  it('accepts a well-formed molecule', () => {
    expect(validateMolecules([spendMolecule]).ok).toBe(true);
  });
  it('rejects an unknown atom predicate', () => {
    const bad: Molecule = { ...spendMolecule, atoms: [{ id: 'a', predicate: 'not-a-real-atom' }] };
    const r = validateMolecules([bad]);
    expect(r.ok).toBe(false);
    expect(r.issues[0].message).toMatch(/unknown atom predicate/);
  });
  it('rejects a config value of the wrong type (would silently never fire)', () => {
    const bad: Molecule = {
      ...spendMolecule,
      atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 'abc' } }],
    };
    const r = validateMolecules([bad]);
    expect(r.ok).toBe(false);
    expect(r.issues.some((i) => /config 'limit' must be a number/.test(i.message))).toBe(true);
  });
  it('rejects a missing required config field', () => {
    const bad: Molecule = { ...spendMolecule, atoms: [{ id: 'a', predicate: 'amount-over', config: {} }] };
    const r = validateMolecules([bad]);
    expect(r.ok).toBe(false);
    expect(r.issues.some((i) => /missing required config 'limit'/.test(i.message))).toBe(true);
  });
  it('accepts a valid enum / string[] config', () => {
    const ok: Molecule = {
      id: 'm',
      combinator: 'any',
      decision: 'escalate',
      reasonCode: 'RISK',
      atoms: [
        { id: 'a1', predicate: 'risk-at-or-above', config: { level: 'high' } },
        { id: 'a2', predicate: 'jurisdiction-not-allowed', config: { allowed: ['US', 'MY'] } },
      ],
    };
    expect(validateMolecules([ok]).ok).toBe(true);
  });
  it('rejects an enum value outside its options', () => {
    const bad: Molecule = {
      ...spendMolecule,
      atoms: [{ id: 'a', predicate: 'risk-at-or-above', config: { level: 'extreme' } }],
    };
    expect(validateMolecules([bad]).ok).toBe(false);
  });

  it('rejects an invalid combinator and a missing reasonCode', () => {
    const bad = { id: 'm', combinator: 'xor', atoms: [{ id: 'a', predicate: 'consent-missing' }], decision: 'block', reasonCode: '' } as unknown as Molecule;
    const r = validateMolecules([bad]);
    expect(r.ok).toBe(false);
    expect(r.issues.some((i) => /invalid combinator/.test(i.message))).toBe(true);
    expect(r.issues.some((i) => /reasonCode/.test(i.message))).toBe(true);
  });
});

// Evidence-quality controls end-to-end through the rule engine (SAFR §24, Phase-4 PR-3):
// an author composes the evidence atoms into a molecule that ESCALATES an under-evidenced action.
describe('evidence-quality molecule (SAFR §24)', () => {
  const evidenceMolecule: Molecule = {
    id: 'evidence-gate',
    combinator: 'any', // escalate if evidence is missing OR confidence is low
    atoms: [
      { id: 'req', predicate: 'evidence-requirement', config: { required: ['kyc'] } },
      { id: 'conf', predicate: 'evidence-confidence-below', config: { min: 0.8 } },
    ],
    decision: 'escalate',
    reasonCode: 'EVIDENCE_INSUFFICIENT',
  };

  it('escalates a well-formed action that lacks the required evidence', () => {
    const r = evaluateStandardRules([evidenceMolecule], ctx({ evidenceTypes: [], evidenceConfidence: 0.9 }));
    expect(r).toMatchObject({ decision: 'escalate', reasonCode: 'EVIDENCE_INSUFFICIENT' });
  });
  it('escalates when confidence is below the bar even with the evidence present', () => {
    const r = evaluateStandardRules([evidenceMolecule], ctx({ evidenceTypes: ['kyc'], evidenceConfidence: 0.5 }));
    expect(r.decision).toBe('escalate');
  });
  it('allows a fully-evidenced, high-confidence action', () => {
    const r = evaluateStandardRules([evidenceMolecule], ctx({ evidenceTypes: ['kyc'], evidenceConfidence: 0.95 }));
    expect(r.decision).toBe('allow');
  });
});

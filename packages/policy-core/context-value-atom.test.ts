import { describe, expect, it } from 'vitest';
import {
  ATOM_REGISTRY,
  buildRuleContext,
  contextRiskSignals,
  contextValueAt,
  evaluate,
  evaluateBoundStandards,
  evaluateStandardRules,
  normalizeContextToken,
  validateMolecules,
  type Molecule,
} from './index.js';

/**
 * Owner-keyed context values (pre-beta rerun 6, NF-RISK-SELF). For a non-financial action the only escalation input was
 * the riskLevel the agent declares about itself: {riskLevel:'low', target:'record-B', op:'delete-all'} ran unreviewed.
 * These atoms let the owner key a rule on WHAT is being done, so the agent's self-label no longer decides.
 */
const inList = ATOM_REGISTRY['context-value-in'];
const notInList = ATOM_REGISTRY['context-value-not-in'];
const DELETE = { field: 'op', values: ['delete', 'delete-all', 'purge'] };

const reviewDeletes: Molecule = {
  id: 'deletes-need-review',
  combinator: 'any',
  atoms: [{ id: 'a1', predicate: 'context-value-in', config: DELETE }],
  decision: 'escalate',
  reasonCode: 'OPERATION_NEEDS_APPROVAL',
};
// The starter "high-risk review" every onboarded agent gets (onboarding.provision.ts).
const riskReview: Molecule = {
  id: 'review',
  combinator: 'any',
  atoms: [{ id: 'a2', predicate: 'risk-at-or-above', config: { level: 'high' } }],
  decision: 'escalate',
  reasonCode: 'RISK_REVIEW',
};

describe('context-value-in (deny-list)', () => {
  it('fires on a listed operation whatever riskLevel the agent declares', () => {
    expect(inList({ action: 'records', op: 'delete-all', riskLevel: 'low' }, DELETE)).toBe(true);
    expect(inList({ action: 'records', op: 'read', riskLevel: 'critical' }, DELETE)).toBe(false);
  });

  it('is not fooled by case, whitespace, width, separators or invisible characters', () => {
    for (const op of ['DELETE-ALL', ' delete-all ', 'Delete_All', 'delete all', 'ｄｅｌｅｔｅ－ａｌｌ', 'delete​-all', 'de­lete-all', 'delete‐all']) {
      expect(inList({ action: 'x', op }, DELETE), JSON.stringify(op)).toBe(true);
    }
  });

  it('folds Cyrillic and Greek look-alikes (NFKC alone would not: a Cyrillic е is a different letter)', () => {
    const cyrillicE = 'dеlete-all'; // Cyrillic е
    expect(cyrillicE.normalize('NFKC')).not.toBe('delete-all');
    expect(inList({ action: 'x', op: cyrillicE }, DELETE)).toBe(true);
    expect(inList({ action: 'x', op: 'DЕLETE' }, DELETE)).toBe(true); // Cyrillic Е, upper case
    expect(inList({ action: 'x', op: 'purgε' }, DELETE)).toBe(true); // Greek ε
    expect(normalizeContextToken('руrge')).toBe('pyrge'); // folds letter by letter; no false "purge"
  });

  it("match: 'contains' catches a listed verb inside a longer operation name", () => {
    const cfg = { field: 'op', values: ['delete'], match: 'contains' };
    for (const op of ['bulk_delete', 'deleteAll', 'DELETE-ALL-RECORDS']) expect(inList({ action: 'x', op }, cfg), op).toBe(true);
    expect(inList({ action: 'x', op: 'bulk_delete' }, { field: 'op', values: ['delete'] })).toBe(false); // exact by default
  });

  it('reads a dot path through own properties only, and never a dotted key', () => {
    const cfg = { field: 'params.op', values: ['delete-all'] };
    expect(inList({ action: 'x', params: { op: 'delete-all' } }, cfg)).toBe(true);
    // The agent cannot pick which of two places the rule reads: a literal "params.op" key is not addressable.
    expect(inList({ action: 'x', 'params.op': 'read', params: { op: 'delete-all' } }, cfg)).toBe(true);
    expect(inList({ action: 'x', 'params.op': 'delete-all' }, cfg)).toBe(false);
    expect(contextValueAt({ a: Object.create({ inherited: 'delete' }) }, 'a.inherited')).toBeUndefined();
    expect(contextValueAt({}, '__proto__.constructor')).toBeUndefined();
  });

  it('type confusion fails closed: a list fires if any element is listed; an object or nested list is malformed and fires', () => {
    expect(inList({ action: 'x', op: ['read', 'delete'] }, DELETE)).toBe(true);
    expect(inList({ action: 'x', op: ['read', 'list'] }, DELETE)).toBe(false);
    expect(inList({ action: 'x', op: { verb: 'delete' } }, DELETE)).toBe(true);
    expect(inList({ action: 'x', op: [['delete']] }, DELETE)).toBe(true);
    expect(inList({ action: 'x', op: 42 }, { field: 'op', values: ['42'] })).toBe(true); // a number is compared as text
  });

  it("an absent field passes by default and FIRES with missing: 'fire'", () => {
    for (const op of [undefined, null, '', '   ', []]) {
      expect(inList({ action: 'x', op }, DELETE), JSON.stringify(op)).toBe(false);
      expect(inList({ action: 'x', op }, { ...DELETE, missing: 'fire' }), JSON.stringify(op)).toBe(true);
    }
  });

  it('actions scopes the rule to the named actions', () => {
    const cfg = { ...DELETE, missing: 'fire', actions: ['records.write'] };
    expect(inList({ action: 'records.write', op: 'delete' }, cfg)).toBe(true);
    expect(inList({ action: 'records.write' }, cfg)).toBe(true);
    expect(inList({ action: 'weather.read', op: 'delete' }, cfg)).toBe(false);
    expect(inList({ action: 'weather.read' }, cfg)).toBe(false);
  });

  it('an unconfigured atom never fires', () => {
    expect(inList({ action: 'x', op: 'delete' }, {})).toBe(false);
    expect(inList({ action: 'x', op: 'delete' }, { field: '  ', values: ['delete'] })).toBe(false);
    expect(inList({ action: 'x', op: 'delete' }, { field: 'op', values: [] })).toBe(false);
  });
});

describe('context-value-not-in (allow-list)', () => {
  const READS = { field: 'op', values: ['read', 'list'] };
  it('fires on anything not allowed — including spellings and look-alikes a deny-list would miss', () => {
    expect(notInList({ action: 'x', op: 'read' }, READS)).toBe(false);
    expect(notInList({ action: 'x', op: ' READ ' }, READS)).toBe(false);
    for (const op of ['delete-all', 'drop_table', 'rеmove', 'wipe', 'x']) expect(notInList({ action: 'x', op }, READS), op).toBe(true);
    expect(notInList({ action: 'x', op: ['read', 'delete'] }, READS)).toBe(true);
  });
  it('an empty allow-list allows nothing that is sent', () => {
    expect(notInList({ action: 'x', op: 'read' }, { field: 'op', values: [] })).toBe(true);
  });
});

describe('the rule layer: escalate on what is done, with a derived signal', () => {
  it('self-declared low + op delete-all escalates, and says the risk was derived from op', () => {
    const ctx = buildRuleContext({ unsigned: { riskLevel: 'low', target: 'record-B', op: 'delete-all' }, signed: { action: 'records' } });
    const r = evaluateBoundStandards([{ standardKey: 'sop:1', document: { molecules: [riskReview, reviewDeletes] } }], ctx as never);
    expect(r).toMatchObject({ decision: 'escalate', reasonCode: 'OPERATION_NEEDS_APPROVAL', firedMoleculeId: 'deletes-need-review' });
    expect(contextRiskSignals(r)).toEqual([{ signal: 'context-value', level: 'high', detail: 'op=delete-all is owner-marked for review' }]);
  });

  it('the same agent reading is untouched (no signal, no review)', () => {
    const ctx = buildRuleContext({ unsigned: { riskLevel: 'low', op: 'read' }, signed: { action: 'records' } });
    const r = evaluateStandardRules([riskReview, reviewDeletes], ctx as never);
    expect(r.decision).toBe('allow');
    expect(contextRiskSignals(r)).toEqual([]);
  });

  it('a block names it as not allowed; a missing required field names the field', () => {
    const block: Molecule = { ...reviewDeletes, id: 'no-deletes', decision: 'block', reasonCode: 'OPERATION_NOT_ALLOWED', atoms: [{ id: 'a', predicate: 'context-value-in', config: { ...DELETE, missing: 'fire' } }] };
    expect(contextRiskSignals(evaluateStandardRules([block], { action: 'x', op: 'purge' }))[0].detail).toBe('op=purge is owner-marked as not allowed');
    expect(contextRiskSignals(evaluateStandardRules([block], { action: 'x' }))[0].detail).toBe('op was not sent, and the owner requires it');
  });

  it('signals are kept from every bound document, not only the one that names the reason', () => {
    const r = evaluateBoundStandards(
      [
        { standardKey: 'a', document: { molecules: [riskReview] } },
        { standardKey: 'b', document: { molecules: [reviewDeletes] } },
      ],
      buildRuleContext({ unsigned: { riskLevel: 'high', op: 'delete-all' }, signed: { action: 'x' } }) as never,
    );
    expect(r.reasonCode).toBe('RISK_REVIEW'); // first escalate wins the tie, as before
    expect(contextRiskSignals(r)).toHaveLength(1);
  });

  it('an observe molecule and a none molecule name no value', () => {
    const observe: Molecule = { ...reviewDeletes, decision: 'observe' };
    expect(evaluateStandardRules([observe], { action: 'x', op: 'delete' }).contextSignals).toBeUndefined();
    const none: Molecule = { ...reviewDeletes, combinator: 'none' };
    const r = evaluateStandardRules([none], { action: 'x', op: 'read' });
    expect(r.decision).toBe('escalate');
    expect(r.contextSignals).toBeUndefined();
  });

  it('the composed evaluate() a guard runs agrees with the gate', () => {
    const ctx = buildRuleContext({ unsigned: { riskLevel: 'low', op: 'DELETE_ALL' }, signed: { action: 'records' } });
    expect(evaluate({ sops: [{ standardKey: 'sop:1', document: { molecules: [reviewDeletes] } }], context: ctx as never })).toMatchObject({ decision: 'escalate', reasonCode: 'OPERATION_NEEDS_APPROVAL' });
  });
});

describe('authoring validation', () => {
  it('requires a non-blank field and a values list; rejects an unknown match/missing mode', () => {
    const mol = (config: Record<string, unknown>): Molecule[] => [{ ...reviewDeletes, atoms: [{ id: 'a', predicate: 'context-value-in', config }] }];
    expect(validateMolecules(mol(DELETE)).ok).toBe(true);
    expect(validateMolecules(mol({ ...DELETE, match: 'contains', missing: 'fire', actions: ['records'] })).ok).toBe(true);
    expect(validateMolecules(mol({ values: ['delete'] })).issues[0].message).toMatch(/missing required config 'field'/);
    expect(validateMolecules(mol({ field: ' ', values: ['delete'] })).issues[0].message).toMatch(/must not be blank/);
    expect(validateMolecules(mol({ field: 'op' })).issues[0].message).toMatch(/'values'/);
    expect(validateMolecules(mol({ ...DELETE, match: 'regex' })).ok).toBe(false);
    expect(validateMolecules(mol({ ...DELETE, missing: true })).ok).toBe(false);
  });
});

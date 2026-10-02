/**
 * Lookups keyed by document content must not reach Object.prototype (found by the mandate-eval fuzz test on
 * 2026-10-02: operator "valueOf" made evaluateMandate non-deterministic, and "constructor" / "toString" resolved to
 * built-ins returning something truthy — a constraint with such an operator was SATISFIED, failing open).
 */
import { describe, expect, it } from 'vitest';
import { evaluateMandate } from './mandate-eval.js';
import { evaluateBoundStandards, validateMolecules } from './standards-rules.js';
import { ownEntry } from './own-entry.js';
import type { Mandate } from './mandate.types.js';

const PROTO_KEYS = ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__', 'isPrototypeOf'];

describe('ownEntry', () => {
  it('returns own entries and nothing inherited', () => {
    const table = { eq: 1 } as Record<string, number>;
    expect(ownEntry(table, 'eq')).toBe(1);
    for (const k of PROTO_KEYS) expect(ownEntry(table, k)).toBeUndefined();
    expect(ownEntry(table, 42)).toBeUndefined();
    expect(ownEntry(table, undefined)).toBeUndefined();
  });
});

describe('a prototype-named operator never satisfies a mandate constraint', () => {
  for (const operator of PROTO_KEYS) {
    it(`operator "${operator}" fails closed`, () => {
      const mandate = {
        permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator, rightOperand: 500, unit: 'USD' }] }],
      } as unknown as Mandate;
      const request = { action: 'flight-purchase', values: { 'mm:payAmount': 100, currency: 'USD' } } as never;
      const first = evaluateMandate(mandate, request);
      expect(first.decision).not.toBe('allow');
      // and it is deterministic (the original fuzz counterexample)
      expect(evaluateMandate(mandate, request)).toEqual(first);
    });
  }
});

describe('a prototype-named atom predicate is never valid and never fires', () => {
  for (const predicate of PROTO_KEYS) {
    it(`predicate "${predicate}"`, () => {
      const molecule = { id: 'm', combinator: 'any', atoms: [{ id: 'a', predicate }], decision: 'block', reasonCode: 'X' };
      expect(validateMolecules([molecule] as never).ok).toBe(false);
      const r = evaluateBoundStandards([{ standardKey: 's', document: { molecules: [molecule] } }] as never, { amount: 1, currency: 'USD' } as never);
      expect(r.decision).toBe('allow');
    });
  }
});

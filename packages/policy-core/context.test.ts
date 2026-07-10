import { describe, it, expect } from 'vitest';
import { applySignedLast } from './context.js';
import { evaluateMandate } from './mandate-eval.js';
import type { Mandate } from './mandate.types.js';

/**
 * Regression tests for the signed-field-shadowing defence (spec §6.4.2, §11.5).
 * Before the fix, the mandate evaluator spread the unsigned `itinerary` LAST, so
 * an attacker could shadow the signed `amount`/`merchant` and slip a cheaper
 * amount or an allowed merchant past the mandate constraints.
 */

describe('applySignedLast — signed fields win on collision', () => {
  it('signed fields override colliding unsigned itinerary keys', () => {
    const merged = applySignedLast(
      { 'mm:payAmount': 1, 'mm:merchant': 'attacker', jurisdiction: 'SG' },
      { 'mm:payAmount': 600, 'mm:merchant': 'amadeus' },
    );
    expect(merged['mm:payAmount']).toBe(600); // signed wins
    expect(merged['mm:merchant']).toBe('amadeus'); // signed wins
    expect(merged.jurisdiction).toBe('SG'); // non-colliding unsigned context preserved
  });

  it('handles a missing / null unsigned context', () => {
    expect(applySignedLast(undefined, { a: 1 })).toEqual({ a: 1 });
    expect(applySignedLast(null, { a: 1 })).toEqual({ a: 1 });
  });

  it('does not mutate its inputs', () => {
    const unsigned = { x: 1 };
    const signed = { 'mm:payAmount': 5 };
    applySignedLast(unsigned, signed);
    expect(unsigned).toEqual({ x: 1 });
    expect(signed).toEqual({ 'mm:payAmount': 5 });
  });
});

describe('regression: an unsigned itinerary cannot shadow signed operands', () => {
  const capMandate: Mandate = {
    permission: [
      {
        target: 'flight-purchase',
        constraint: [
          { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 500 },
          { leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: ['amadeus'] },
        ],
      },
    ],
  };
  const now = '2026-07-10T00:00:00Z';

  it('blocks a $600 purchase even when the itinerary forges mm:payAmount = 1', () => {
    const values = applySignedLast(
      { 'mm:payAmount': 1 }, // forged unsigned — would allow under the old ordering
      { 'mm:payAmount': 600, 'mm:merchant': 'amadeus' }, // real signed
    );
    const r = evaluateMandate(capMandate, { target: 'flight-purchase', now, values });
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('SPEND_LIMIT_EXCEEDED');
  });

  it('blocks a disallowed merchant even when the itinerary forges an allowed one', () => {
    const values = applySignedLast(
      { 'mm:merchant': 'amadeus' }, // forged unsigned
      { 'mm:payAmount': 100, 'mm:merchant': 'sabre' }, // real signed
    );
    const r = evaluateMandate(capMandate, { target: 'flight-purchase', now, values });
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('MERCHANT_NOT_ALLOWED');
  });
});

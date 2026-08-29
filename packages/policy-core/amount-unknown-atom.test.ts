import { describe, it, expect } from 'vitest';
import { ATOM_REGISTRY } from './atom-registry.js';
import { ATOM_SPECS } from './atom-catalog.js';
import type { EvaluationContext } from './types.js';

const atom = ATOM_REGISTRY['amount-unknown'];
const over = ATOM_REGISTRY['amount-over'];
const ctx = (over_: Partial<EvaluationContext>): EvaluationContext => ({ action: 'send-transaction', ...over_ });

describe('amount-unknown', () => {
  it('does not fire when a real amount is present, including zero and negatives', () => {
    expect(atom(ctx({ amount: 1 }), {})).toBe(false);
    expect(atom(ctx({ amount: 0 }), {})).toBe(false);
    expect(atom(ctx({ amount: -5 }), {})).toBe(false);
  });

  it('fires when the amount is absent or not a usable number', () => {
    expect(atom(ctx({}), {})).toBe(true);
    expect(atom(ctx({ amount: undefined }), {})).toBe(true);
    expect(atom(ctx({ amount: NaN as number }), {})).toBe(true);
    expect(atom(ctx({ amount: Infinity as number }), {})).toBe(true);
    // A tinybar string off the wire is NOT an amount — it must be normalised first,
    // or a "100" would be compared against a 100 HBAR cap as if it were 100 HBAR.
    expect(atom(ctx({ amount: '5' as unknown as number }), {})).toBe(true);
  });

  it('covers exactly the gap amount-over leaves: a missing amount passes the cap untested', () => {
    const noAmount = ctx({});
    expect(over(noAmount, { limit: 100 })).toBe(false); // cap says "fine" about a number it never saw
    expect(atom(noAmount, {})).toBe(true); // which is why this must be authored ahead of it
  });

  it('is catalogued with the context field it reads', () => {
    const spec = ATOM_SPECS.find((s) => s.predicate === 'amount-unknown');
    expect(spec, 'missing spec for amount-unknown').toBeTruthy();
    expect(spec!.requiredContext).toContain('amount');
    expect(spec!.config).toEqual([]);
  });
});

import { describe, it, expect } from 'vitest';
import { ATOM_REGISTRY } from './atom-registry.js';
import type { EvaluationContext } from './types.js';

const atom = ATOM_REGISTRY['amount-over'];
const ctx = (over_: Partial<EvaluationContext>): EvaluationContext => ({ action: 'send-transaction', ...over_ });

describe('amount-over', () => {
  it('fires when the amount exceeds the limit', () => {
    expect(atom(ctx({ amount: 1200 }), { limit: 1000 })).toBe(true);
  });

  it('does not fire at or under the limit', () => {
    expect(atom(ctx({ amount: 1000 }), { limit: 1000 })).toBe(false);
    expect(atom(ctx({ amount: 10 }), { limit: 1000 })).toBe(false);
  });

  it('does not fire when the amount is not a real number (amount-unknown is the atom for that)', () => {
    expect(atom(ctx({ amount: '5000' as unknown as number }), { limit: 1000 })).toBe(false);
    expect(atom(ctx({}), { limit: 1000 })).toBe(false);
  });

  // A currency scope on `amount-over` is optional (atom-catalog.ts's `currency` config) and
  // mirrors mandate-eval.ts's constraintSatisfied() unit check on the PROHIBITION side: this
  // atom FIRES to trigger a BLOCK/ESCALATE, the same role a mandate prohibition plays, so a
  // currency that doesn't match — or can't be read at all — must resolve toward firing, not
  // toward silently letting the numeric comparison decide. This is what stops an SOP-authored
  // "block over 200" from being cleared by naming a cheaper-looking currency (e.g. 200 JPY vs
  // 200 USD) — the exact bypass class mandate-eval.ts's own currency check was built to close
  // on the ODRL mandate layer (see mandate-eval.test.ts's matching coverage there).
  describe('currency scope', () => {
    it('is currency-blind when no currency config is set — unchanged default behavior', () => {
      // Numerically over the limit, regardless of currency — the historical behavior every
      // SOP authored before this field existed still gets.
      expect(atom(ctx({ amount: 1200, currency: 'JPY' }), { limit: 1000 })).toBe(true);
      expect(atom(ctx({ amount: 800, currency: 'JPY' }), { limit: 1000 })).toBe(false);
    });

    it('does not fire an under-limit amount when the request currency matches the configured scope', () => {
      expect(atom(ctx({ amount: 800, currency: 'USD' }), { limit: 1000, currency: 'USD' })).toBe(false);
    });

    it('still fires an over-limit amount in the matching currency', () => {
      expect(atom(ctx({ amount: 1200, currency: 'USD' }), { limit: 1000, currency: 'USD' })).toBe(true);
    });

    it('is case-insensitive, like mandate-eval.ts', () => {
      expect(atom(ctx({ amount: 800, currency: 'usd' }), { limit: 1000, currency: 'USD' })).toBe(false);
    });

    it('accepts a currency ALLOW-LIST, membership not equality', () => {
      expect(atom(ctx({ amount: 800, currency: 'GBP' }), { limit: 1000, currency: ['USD', 'GBP'] })).toBe(false);
      expect(atom(ctx({ amount: 800, currency: 'JPY' }), { limit: 1000, currency: ['USD', 'GBP'] })).toBe(true);
    });

    it('fires a numerically-under-limit amount quoted in a DIFFERENT currency than configured — the reported bypass', () => {
      // The cap is scoped to 1000 units of USD. 800 in JPY is worth a tiny fraction of 800
      // USD — a bare numeric comparison would wrongly let this through, just as
      // mandate-eval.test.ts documents for the ODRL mandate layer.
      expect(atom(ctx({ amount: 800, currency: 'JPY' }), { limit: 1000, currency: 'USD' })).toBe(true);
    });

    it('fires even a tiny amount in a mismatched currency — unverifiable, so treated as unsafe', () => {
      expect(atom(ctx({ amount: 1, currency: 'JPY' }), { limit: 1000, currency: 'USD' })).toBe(true);
    });

    it('fires when the request supplies no currency at all but the cap is scoped', () => {
      expect(atom(ctx({ amount: 1 }), { limit: 1000, currency: 'USD' })).toBe(true);
    });

    it('does not fire when amount itself is not a real number, currency scope or not', () => {
      // amount-unknown is the atom responsible for an unreadable amount; amount-over must
      // never fire just because currency is out of scope on top of an unreadable amount.
      expect(atom(ctx({ amount: '5000' as unknown as number, currency: 'JPY' }), { limit: 1000, currency: 'USD' })).toBe(false);
    });
  });
});

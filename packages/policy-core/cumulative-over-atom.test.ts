import { describe, it, expect } from 'vitest';
import { ATOM_REGISTRY } from './atom-registry.js';
import { ATOM_SPECS, requiredContextFor } from './atom-catalog.js';
import type { EvaluationContext } from './types.js';

const atom = ATOM_REGISTRY['cumulative-over'];
const ctx = (over_: Partial<EvaluationContext>): EvaluationContext => ({ action: 'send-transaction', ...over_ });

describe('cumulative-over', () => {
  it('fires when already-spent + this amount exceeds the limit', () => {
    expect(atom(ctx({ cumulativeSpend: 9000, amount: 2000 }), { limit: 10000 })).toBe(true);
  });

  it('does not fire when the total stays at or under the limit', () => {
    expect(atom(ctx({ cumulativeSpend: 9000, amount: 1000 }), { limit: 10000 })).toBe(false);
    expect(atom(ctx({ cumulativeSpend: 0, amount: 200 }), { limit: 10000 })).toBe(false);
  });

  it('treats a missing cumulativeSpend as 0, not as "exempt"', () => {
    // The atom's own comment documents this as the intended default — but it also means a
    // caller that never supplies cumulativeSpend can never trip a total-budget cap no
    // matter how large a single amount is, unless amount alone already clears the limit.
    expect(atom(ctx({ amount: 5 }), { limit: 10000 })).toBe(false);
    expect(atom(ctx({ amount: 20000 }), { limit: 10000 })).toBe(true);
  });

  // Regression for a real incident: this atom's catalog spec declared `requiredContext:
  // ['amount']`, omitting `cumulativeSpend` even though the executable atom above reads
  // both. That single field is the union's ONLY source of truth for two independent,
  // real-world-facing consumers (see atom-catalog.ts's file header) — so the gap silently
  // broke both without ever throwing:
  //   1. The Scenario Bank's simulate form (scenario-context-fields.ts's
  //      contextFieldsForClauses) never rendered an "already spent" input for any set
  //      using this atom, so the control could never be exercised from the UI at all —
  //      confirmed live: selecting the seeded "Nearly at budget, one more top-up" preset
  //      (payment-exposure-baseline, `{ amount: 2000, cumulativeSpend: 9000 }`) populated
  //      only the transaction-amount field, fired the WRONG rule (the per-transaction
  //      ceiling, since $2000 alone happened to exceed it), and reported the actual
  //      cumulative-budget rule as "would allow".
  //   2. The generated integration docs' "context contract" (this catalog is what they're
  //      derived from) told real SDK integrators this atom only needs `amount` — so an
  //      agent built strictly to that contract never sends `cumulativeSpend`, which (per
  //      the test above) means its total-budget cap silently never fires in production.
  it('is catalogued with EVERY context field the executable atom reads, not just amount', () => {
    const spec = ATOM_SPECS.find((s) => s.predicate === 'cumulative-over');
    expect(spec, 'missing spec for cumulative-over').toBeTruthy();
    expect(spec!.requiredContext).toContain('amount');
    expect(spec!.requiredContext).toContain('cumulativeSpend');
  });

  it('requiredContextFor a clause using cumulative-over surfaces cumulativeSpend to callers', () => {
    expect(requiredContextFor(['cumulative-over'])).toEqual(['amount', 'cumulativeSpend']);
  });

  describe('currency scope (optional, mirrors mandate-eval.ts unit checks)', () => {
    it('is currency-blind when no currency config is set — unchanged default behavior', () => {
      expect(atom(ctx({ cumulativeSpend: 9000, amount: 2000, currency: 'JPY' }), { limit: 10000 })).toBe(true);
      expect(atom(ctx({ cumulativeSpend: 9000, amount: 1000, currency: 'JPY' }), { limit: 10000 })).toBe(false);
    });

    it('does not fire an in-budget total when the request currency matches the configured scope', () => {
      expect(atom(ctx({ cumulativeSpend: 9000, amount: 1000, currency: 'USD' }), { limit: 10000, currency: 'USD' })).toBe(false);
    });

    it('still fires an over-budget total in the matching currency', () => {
      expect(atom(ctx({ cumulativeSpend: 9000, amount: 2000, currency: 'USD' }), { limit: 10000, currency: 'USD' })).toBe(true);
    });

    it('is case-insensitive, like mandate-eval.ts', () => {
      expect(atom(ctx({ cumulativeSpend: 9000, amount: 1000, currency: 'usd' }), { limit: 10000, currency: 'USD' })).toBe(false);
    });

    it('accepts a currency ALLOW-LIST, membership not equality', () => {
      expect(atom(ctx({ cumulativeSpend: 9000, amount: 1000, currency: 'GBP' }), { limit: 10000, currency: ['USD', 'GBP'] })).toBe(false);
    });

    it('fires for a well-under-budget total in a DIFFERENT currency than configured — unverifiable, so treated as unsafe', () => {
      // The exact bypass this closes: an SOP author scopes the cap to USD, and a request
      // just relabels the currency to dodge the numeric comparison entirely.
      expect(atom(ctx({ cumulativeSpend: 0, amount: 1, currency: 'JPY' }), { limit: 10000, currency: 'USD' })).toBe(true);
    });

    it('fires when the request supplies no currency at all but the cap is scoped', () => {
      expect(atom(ctx({ cumulativeSpend: 0, amount: 1 }), { limit: 10000, currency: 'USD' })).toBe(true);
    });
  });
});

import { describe, expect, it } from 'vitest';
import { MAX_DELEGATION_DEPTH, constraintNarrows, delegationVerdict, narrows } from './delegation.js';
import type { Constraint, Mandate } from './mandate.types.js';

const cap = (v: number): Constraint => ({ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: v });
const merchants = (...v: string[]): Constraint => ({ leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: v });

const parent: Mandate = {
  target: 'flight-purchase',
  permission: [{ target: 'flight-purchase', constraint: [cap(500), merchants('skyward-air', 'globe-hotels')] }],
};

describe('constraintNarrows — the asymmetry per operator', () => {
  it('a lower ceiling narrows, a higher one widens', () => {
    expect(constraintNarrows(cap(500), cap(200))).toBe(true);
    expect(constraintNarrows(cap(500), cap(500))).toBe(true);
    expect(constraintNarrows(cap(500), cap(1000))).toBe(false);
  });

  it('a higher floor narrows', () => {
    const floor = (v: number): Constraint => ({ leftOperand: 'mm:score', operator: 'gteq', rightOperand: v });
    expect(constraintNarrows(floor(50), floor(80))).toBe(true);
    expect(constraintNarrows(floor(50), floor(20))).toBe(false);
  });

  it('a SMALLER allow-list narrows', () => {
    expect(constraintNarrows(merchants('a', 'b'), merchants('a'))).toBe(true);
    expect(constraintNarrows(merchants('a', 'b'), merchants('a', 'b', 'c'))).toBe(false);
    expect(constraintNarrows(merchants('a'), merchants('b'))).toBe(false);
  });

  it('a LARGER deny-list narrows — the inversion that is easy to get backwards', () => {
    const deny = (...v: string[]): Constraint => ({ leftOperand: 'mm:merchant', operator: 'isNoneOf', rightOperand: v });
    // Keeping the parent's exclusions and adding more is narrower…
    expect(constraintNarrows(deny('bad'), deny('bad', 'worse'))).toBe(true);
    // …and deleting one is a widening dressed as a shorter list.
    expect(constraintNarrows(deny('bad', 'worse'), deny('bad'))).toBe(false);
  });

  it('an earlier deadline and a later start both narrow', () => {
    const before = (t: string): Constraint => ({ leftOperand: 'mm:when', operator: 'before', rightOperand: t });
    const after = (t: string): Constraint => ({ leftOperand: 'mm:when', operator: 'after', rightOperand: t });
    expect(constraintNarrows(before('2026-12-31T00:00:00Z'), before('2026-06-30T00:00:00Z'))).toBe(true);
    expect(constraintNarrows(before('2026-06-30T00:00:00Z'), before('2026-12-31T00:00:00Z'))).toBe(false);
    expect(constraintNarrows(after('2026-01-01T00:00:00Z'), after('2026-06-01T00:00:00Z'))).toBe(true);
    expect(constraintNarrows(after('2026-06-01T00:00:00Z'), after('2026-01-01T00:00:00Z'))).toBe(false);
  });

  it('eq narrows only against itself', () => {
    const eq = (v: string): Constraint => ({ leftOperand: 'mm:currency', operator: 'eq', rightOperand: v });
    expect(constraintNarrows(eq('USD'), eq('USD'))).toBe(true);
    expect(constraintNarrows(eq('USD'), eq('EUR'))).toBe(false);
  });

  it('refuses to compare mismatched operators or unreadable operands', () => {
    // Swapping a cap it cannot meet for a list it can is not a narrowing question.
    expect(constraintNarrows(cap(500), merchants('a'))).toBeNull();
    expect(constraintNarrows(cap(500), { ...cap(0), rightOperand: 'not-a-number' })).toBeNull();
  });
});

describe('delegationVerdict', () => {
  it('permits a genuine narrowing', () => {
    const child: Mandate = {
      target: 'flight-purchase',
      permission: [{ target: 'flight-purchase', constraint: [cap(200), merchants('skyward-air')] }],
    };
    expect(delegationVerdict(parent, child, 1)).toEqual({ ok: true, refusal: null, detail: null });
  });

  it('refuses a raised cap', () => {
    const child: Mandate = {
      target: 'flight-purchase',
      permission: [{ target: 'flight-purchase', constraint: [cap(5000), merchants('skyward-air')] }],
    };
    expect(delegationVerdict(parent, child, 1)).toMatchObject({ ok: false, refusal: 'CONSTRAINT_WIDENED', detail: 'mm:payAmount' });
  });

  it('refuses a merchant the parent never had', () => {
    const child: Mandate = {
      target: 'flight-purchase',
      permission: [{ target: 'flight-purchase', constraint: [cap(100), merchants('rogue-air')] }],
    };
    expect(delegationVerdict(parent, child, 1)).toMatchObject({ refusal: 'CONSTRAINT_WIDENED', detail: 'mm:merchant' });
  });

  it('refuses a child that DROPS a parent constraint — the escalation this exists to stop', () => {
    // No cap at all is more authority than a $500 cap, however innocent the omission looks.
    const child: Mandate = {
      target: 'flight-purchase',
      permission: [{ target: 'flight-purchase', constraint: [merchants('skyward-air')] }],
    };
    expect(delegationVerdict(parent, child, 1)).toMatchObject({ refusal: 'CONSTRAINT_DROPPED', detail: 'mm:payAmount' });
  });

  it('refuses a child with no constraints at all', () => {
    const child: Mandate = { target: 'flight-purchase', permission: [{ target: 'flight-purchase' }] };
    expect(delegationVerdict(parent, child, 1).ok).toBe(false);
  });

  it('refuses an action the parent cannot do', () => {
    const child: Mandate = {
      target: 'wire-transfer',
      permission: [{ target: 'wire-transfer', constraint: [cap(10)] }],
    };
    expect(delegationVerdict(parent, child, 1)).toMatchObject({ refusal: 'ACTION_NOT_IN_PARENT', detail: 'wire-transfer' });
  });

  it('allows extra child constraints the parent never had', () => {
    const child: Mandate = {
      target: 'flight-purchase',
      permission: [{
        target: 'flight-purchase',
        constraint: [cap(200), merchants('skyward-air'), { leftOperand: 'mm:jurisdiction', operator: 'isAnyOf', rightOperand: ['SG'] }],
      }],
    };
    // They can only remove authority, so they are always safe.
    expect(narrows(parent, child)).toBe(true);
  });

  it('a mandate granting nothing cannot widen anything', () => {
    expect(narrows(parent, { target: 'flight-purchase', permission: [] })).toBe(true);
  });

  describe('validity window', () => {
    const p: Mandate = { ...parent, validFrom: '2026-01-01T00:00:00Z', validUntil: '2026-12-31T00:00:00Z' };
    const perm = [{ target: 'flight-purchase', constraint: [cap(100), merchants('skyward-air')] }];

    it('permits a window inside the parent', () => {
      expect(narrows(p, { ...p, permission: perm, validFrom: '2026-03-01T00:00:00Z', validUntil: '2026-06-01T00:00:00Z' })).toBe(true);
    });

    it('refuses a child that outlives its parent', () => {
      expect(delegationVerdict(p, { ...p, permission: perm, validUntil: '2027-01-01T00:00:00Z' }, 1)).toMatchObject({
        refusal: 'VALIDITY_WIDENED',
        detail: 'validUntil',
      });
    });

    it('refuses a child that starts before its parent', () => {
      expect(delegationVerdict(p, { ...p, permission: perm, validFrom: '2025-01-01T00:00:00Z' }, 1)).toMatchObject({
        detail: 'validFrom',
      });
    });

    it('refuses a child that simply omits a bounded window', () => {
      // An unbounded child of a bounded parent outlives it.
      expect(delegationVerdict(p, { target: 'flight-purchase', permission: perm }, 1)).toMatchObject({
        refusal: 'VALIDITY_WIDENED',
      });
    });
  });

  it('refuses a child that drops a parent prohibition', () => {
    const p: Mandate = { ...parent, prohibition: [{ target: 'crypto-purchase' }] };
    const child: Mandate = {
      target: 'flight-purchase',
      permission: [{ target: 'flight-purchase', constraint: [cap(100), merchants('skyward-air')] }],
    };
    expect(delegationVerdict(p, child, 1)).toMatchObject({ refusal: 'PROHIBITION_DROPPED', detail: 'crypto-purchase' });
    expect(narrows(p, { ...child, prohibition: [{ target: 'crypto-purchase' }] })).toBe(true);
  });

  describe('depth', () => {
    const child: Mandate = {
      target: 'flight-purchase',
      permission: [{ target: 'flight-purchase', constraint: [cap(100), merchants('skyward-air')] }],
    };

    it('permits a chain up to the bound', () => {
      for (let d = 1; d <= MAX_DELEGATION_DEPTH; d += 1) expect(delegationVerdict(parent, child, d).ok).toBe(true);
    });

    it('refuses beyond it, and refuses a nonsensical depth', () => {
      expect(delegationVerdict(parent, child, MAX_DELEGATION_DEPTH + 1)).toMatchObject({ refusal: 'DEPTH_EXCEEDED' });
      expect(delegationVerdict(parent, child, 0).ok).toBe(false);
      expect(delegationVerdict(parent, child, Number.NaN).ok).toBe(false);
    });
  });

  it('is satisfied when ANY parent permission for the action covers the child', () => {
    const p: Mandate = {
      target: 'flight-purchase',
      permission: [
        { target: 'flight-purchase', constraint: [cap(100), merchants('a')] },
        { target: 'flight-purchase', constraint: [cap(9000), merchants('skyward-air')] },
      ],
    };
    const child: Mandate = {
      target: 'flight-purchase',
      permission: [{ target: 'flight-purchase', constraint: [cap(500), merchants('skyward-air')] }],
    };
    expect(narrows(p, child)).toBe(true);
  });
});

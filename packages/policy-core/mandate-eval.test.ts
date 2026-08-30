import { describe, it, expect } from 'vitest';
import {
  evaluateMandate,
  remainingBudget,
  canAuthorize,
  applyHold,
  applyCapture,
  releaseHold,
  sumEventField,
} from './mandate-eval.js';
import type { Mandate, MandateRequest } from './mandate.types.js';

/** The worked "buy flights, ≤ USD 1000" mandate from design §3.2. */
const flightMandate: Mandate = {
  uid: 'urn:metamynd:mandate:test',
  validFrom: '2026-07-01T00:00:00Z',
  validUntil: '2026-08-31T23:59:59Z',
  permission: [
    {
      target: 'mm:flight-purchase',
      action: 'execute',
      constraint: [
        { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000, unit: 'USD' },
        { leftOperand: 'mm:cumulativeSpend', operator: 'lteq', rightOperand: 1000, unit: 'USD' },
        { leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: ['amadeus'] },
      ],
    },
  ],
};

function req(values: Record<string, unknown>, now = '2026-08-01T09:00:00Z'): MandateRequest {
  // Matches flightMandate's 'USD'-unit constraints by default; a test asserting the
  // currency check itself overrides 'mm:currency' explicitly.
  return { target: 'mm:flight-purchase', now, values: { 'mm:currency': 'USD', ...values } };
}

describe('evaluateMandate — happy path', () => {
  it('allows a purchase within cap, budget, and merchant scope', () => {
    const r = evaluateMandate(
      flightMandate,
      req({ 'mm:payAmount': 412.5, 'mm:cumulativeSpend': 0, 'mm:merchant': 'amadeus' }),
    );
    expect(r.decision).toBe('allow');
    expect(r.reasonCode).toBe('AUTHORIZED');
  });
});

describe('evaluateMandate — spend limits', () => {
  it('blocks when a single payment exceeds the per-transaction cap', () => {
    const r = evaluateMandate(
      flightMandate,
      req({ 'mm:payAmount': 1200, 'mm:cumulativeSpend': 0, 'mm:merchant': 'amadeus' }),
    );
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('SPEND_LIMIT_EXCEEDED');
    expect(r.matched?.constraint?.leftOperand).toBe('mm:payAmount');
  });

  it('blocks when cumulative spend would exceed the budget', () => {
    // payAmount ok (300) but 800 already spent -> cumulative 1100 pre-resolved by caller
    const r = evaluateMandate(
      flightMandate,
      req({ 'mm:payAmount': 300, 'mm:cumulativeSpend': 1100, 'mm:merchant': 'amadeus' }),
    );
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('SPEND_LIMIT_EXCEEDED');
  });

  it('allows exactly at the cap boundary', () => {
    const r = evaluateMandate(
      flightMandate,
      req({ 'mm:payAmount': 1000, 'mm:cumulativeSpend': 1000, 'mm:merchant': 'amadeus' }),
    );
    expect(r.decision).toBe('allow');
  });

  it('blocks a numerically-within-cap amount quoted in a DIFFERENT currency than the mandate was issued in', () => {
    // The cap is 1000 units of a 'USD'-denominated mandate. 800 JPY is worth a tiny
    // fraction of 800 USD — the numeric comparison alone would wrongly allow this.
    const r = evaluateMandate(
      flightMandate,
      req({ 'mm:payAmount': 800, 'mm:cumulativeSpend': 0, 'mm:merchant': 'amadeus', 'mm:currency': 'JPY' }),
    );
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('SPEND_LIMIT_EXCEEDED');
    expect(r.matched?.constraint?.leftOperand).toBe('mm:payAmount');
  });

  it('a constraint with no `unit` is unaffected by currency (e.g. merchant scope, routes)', () => {
    const r = evaluateMandate(
      flightMandate,
      req({ 'mm:payAmount': 100, 'mm:cumulativeSpend': 0, 'mm:merchant': 'amadeus', 'mm:currency': 'JPY' }),
    );
    // payAmount/cumulativeSpend still fail (wrong currency vs their 'USD' unit)...
    expect(r.decision).toBe('block');
    // ...but merchant scope itself never carries a unit, so it isn't what fails here —
    // confirmed by the reported constraint being the amount, not the merchant.
    expect(r.matched?.constraint?.leftOperand).not.toBe('mm:merchant');
  });
});

describe('evaluateMandate — scope', () => {
  it('blocks a merchant outside the allow-list', () => {
    const r = evaluateMandate(
      flightMandate,
      req({ 'mm:payAmount': 100, 'mm:cumulativeSpend': 0, 'mm:merchant': 'sabre' }),
    );
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('MERCHANT_NOT_ALLOWED');
  });

  it('blocks an action the mandate does not cover', () => {
    const r = evaluateMandate(flightMandate, {
      target: 'mm:hotel-purchase',
      now: '2026-08-01T09:00:00Z',
      values: { 'mm:payAmount': 100 },
    });
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('NO_PERMISSION_FOR_ACTION');
  });
});

describe('evaluateMandate — validity window', () => {
  it('blocks before validFrom', () => {
    const r = evaluateMandate(
      flightMandate,
      req({ 'mm:payAmount': 100, 'mm:cumulativeSpend': 0, 'mm:merchant': 'amadeus' }, '2026-06-01T00:00:00Z'),
    );
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('MANDATE_NOT_YET_VALID');
  });

  it('blocks after validUntil', () => {
    const r = evaluateMandate(
      flightMandate,
      req({ 'mm:payAmount': 100, 'mm:cumulativeSpend': 0, 'mm:merchant': 'amadeus' }, '2026-09-15T00:00:00Z'),
    );
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('MANDATE_EXPIRED');
  });
});

describe('evaluateMandate — fail-closed on unresolved operands', () => {
  it('blocks when a required operand is missing (never accidentally allows)', () => {
    const r = evaluateMandate(flightMandate, req({ 'mm:cumulativeSpend': 0, 'mm:merchant': 'amadeus' }));
    expect(r.decision).toBe('block'); // mm:payAmount absent -> lteq NaN is false
  });
});

describe('evaluateMandate — escalate via onFail', () => {
  const softLimit: Mandate = {
    permission: [
      {
        target: 'mm:flight-purchase',
        constraint: [
          { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 500, onFail: 'escalate' },
        ],
      },
    ],
  };
  it('escalates (not blocks) when the failing constraint says so', () => {
    const r = evaluateMandate(softLimit, req({ 'mm:payAmount': 750 }));
    expect(r.decision).toBe('escalate');
    expect(r.reasonCode).toBe('SPEND_LIMIT_EXCEEDED');
  });
});

describe('evaluateMandate — prohibitions win', () => {
  const withProhibition: Mandate = {
    permission: [{ target: 'mm:flight-purchase' }], // unconditional permission
    prohibition: [
      {
        target: 'mm:flight-purchase',
        constraint: [{ leftOperand: 'mm:route', operator: 'isAnyOf', rightOperand: ['KUL-DXB'] }],
        reasonCode: 'ROUTE_DENYLISTED',
      },
    ],
  };
  it('blocks via prohibition even when a permission would allow', () => {
    const r = evaluateMandate(withProhibition, req({ 'mm:route': 'KUL-DXB' }));
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('ROUTE_DENYLISTED');
  });
  it('allows when the prohibition does not fire', () => {
    const r = evaluateMandate(withProhibition, req({ 'mm:route': 'KUL-PEN' }));
    expect(r.decision).toBe('allow');
  });
});

describe('evaluateMandate — a unit-bearing PROHIBITION cannot be dodged by currency', () => {
  // A currency mismatch on a PERMISSION constraint must deny (proven above); reusing that
  // same "mismatch -> not satisfied" rule for a PROHIBITION fails OPEN instead, because a
  // prohibition only fires when every() constraint is satisfied — "not satisfied" on the
  // amount constraint would silently skip the prohibition, no matter how large the amount.
  const highValueProhibited: Mandate = {
    permission: [{ target: 'mm:flight-purchase' }], // unconditional permission (prohibition wins first)
    prohibition: [
      {
        target: 'mm:flight-purchase',
        constraint: [{ leftOperand: 'mm:payAmount', operator: 'gteq', rightOperand: 1000, unit: 'USD' }],
        reasonCode: 'HIGH_VALUE_BLOCKED',
      },
    ],
  };

  it('fires the prohibition for a large amount in the matching currency', () => {
    const r = evaluateMandate(highValueProhibited, req({ 'mm:payAmount': 1500, 'mm:currency': 'USD' }));
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('HIGH_VALUE_BLOCKED');
  });

  it('still fires when the matching currency is declared in a different case (usd)', () => {
    const r = evaluateMandate(highValueProhibited, req({ 'mm:payAmount': 1500, 'mm:currency': 'usd' }));
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('HIGH_VALUE_BLOCKED');
  });

  it('still fires when a DIFFERENT currency is declared for the same large amount — the reported bypass', () => {
    // 0.3.3's regression: declaring 'JPY' (or any other currency) made constraintSatisfied
    // return false for this constraint, so every() never fired the prohibition at all —
    // the exact same numeric amount that blocks in USD sailed through as an unconditional
    // permission grant just by relabeling the currency.
    const r = evaluateMandate(highValueProhibited, req({ 'mm:payAmount': 1500, 'mm:currency': 'JPY' }));
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('HIGH_VALUE_BLOCKED');
  });

  it('does not fire for a genuinely small amount in the matching currency', () => {
    const r = evaluateMandate(highValueProhibited, req({ 'mm:payAmount': 100, 'mm:currency': 'USD' }));
    expect(r.decision).toBe('allow');
  });

  it('a MISMATCHED currency fires the prohibition even for a small amount — unverifiable, so treated as unsafe', () => {
    // Deliberate: once the currency can't be confirmed, the amount comparison in that
    // currency is unverifiable, not "known small" — a prohibition resolves that ambiguity
    // toward blocking, the same direction amount-unknown resolves an unreadable amount.
    const r = evaluateMandate(highValueProhibited, req({ 'mm:payAmount': 1, 'mm:currency': 'JPY' }));
    expect(r.decision).toBe('block');
    expect(r.reasonCode).toBe('HIGH_VALUE_BLOCKED');
  });
});

describe('budget helpers — two-phase hold/capture', () => {
  it('computes remaining budget net of spent and holds', () => {
    expect(remainingBudget({ cap: 1000, spent: 200, held: 100 })).toBe(700);
    expect(remainingBudget({ cap: 1000, spent: 900, held: 200 })).toBe(0); // never negative
  });

  it('canAuthorize respects remaining and rejects negatives', () => {
    const b = { cap: 1000, spent: 0, held: 0 };
    expect(canAuthorize(b, 1000)).toBe(true);
    expect(canAuthorize(b, 1001)).toBe(false);
    expect(canAuthorize(b, -5)).toBe(false);
  });

  it('a hold reduces what a concurrent authorization can spend', () => {
    let b = { cap: 1000, spent: 0, held: 0 };
    b = applyHold(b, 600);
    expect(remainingBudget(b)).toBe(400);
    expect(canAuthorize(b, 500)).toBe(false); // second auth cannot overrun the cap
    expect(canAuthorize(b, 400)).toBe(true);
  });

  it('capture moves held -> spent', () => {
    let b = { cap: 1000, spent: 0, held: 600 };
    b = applyCapture(b, 600);
    expect(b).toEqual({ cap: 1000, spent: 600, held: 0 });
    expect(remainingBudget(b)).toBe(400);
  });

  it('capturing less than held (cheaper final charge) frees the difference', () => {
    let b = { cap: 1000, spent: 0, held: 600 };
    b = applyCapture(b, 550);
    expect(b).toEqual({ cap: 1000, spent: 550, held: 50 });
  });

  it('releaseHold returns budget when a booking fails', () => {
    let b = { cap: 1000, spent: 0, held: 600 };
    b = releaseHold(b, 600);
    expect(b).toEqual({ cap: 1000, spent: 0, held: 0 });
  });
});

describe('sumEventField — the cumulative-spend kernel', () => {
  const events = [
    { type: 'authorize', payload: { amount: 300 } },
    { type: 'capture', payload: { amount: 300 } },
    { type: 'capture', payload: { amount: 250 } },
    { type: 'capture', payload: { note: 'no amount' } },
  ];
  it('sums the field only over the requested event type', () => {
    expect(sumEventField(events, 'capture', 'amount')).toBe(550);
    expect(sumEventField(events, 'authorize', 'amount')).toBe(300);
    expect(sumEventField([], 'capture', 'amount')).toBe(0);
  });
});

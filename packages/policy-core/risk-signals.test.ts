import { describe, expect, it } from 'vitest';
import { buildRuleContext, effectiveRiskFloor, riskSignalsFor, riskSignalSettings, DEFAULT_AMOUNT_SHARE_HIGH } from './index.js';

/**
 * Risk the agent cannot lower (MAGP §6.4.3). The agent's own `riskLevel` was the only input to a high-risk review unless
 * the owner set a tier — so a compromised agent could say "low" and skip the human. These are the signals derived from
 * facts it cannot fake: the owner's tier, the signed amount against the cap, and (issuer only) an unvetted merchant.
 */
const mandate = (grant: Record<string, unknown> = {}, merchants?: string[]) => ({
  permission: [{
    target: 'flight-purchase',
    constraint: [
      { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 500 },
      ...(merchants ? [{ leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: merchants }] : []),
    ],
    ...grant,
  }],
});

describe('riskSignalsFor', () => {
  it('a payment at or above 70% of the per-transaction cap is HIGH by default, and says why', () => {
    expect(DEFAULT_AMOUNT_SHARE_HIGH).toBe(0.7);
    expect(riskSignalsFor(mandate(), 'flight-purchase', 349)).toEqual([]);
    const [s] = riskSignalsFor(mandate(), 'flight-purchase', 350);
    expect(s).toMatchObject({ signal: 'amount-share', level: 'high' });
    expect(s.detail).toBe('70% of the 500 per-transaction cap (review from 70%)');
  });

  it('the owner tunes the share, or turns the signal — or derived risk entirely — off', () => {
    expect(riskSignalsFor(mandate({ riskSignals: { amountShare: 0.9 } }), 'flight-purchase', 400)).toEqual([]);
    expect(riskSignalsFor(mandate({ riskSignals: { amountShare: 0.5 } }), 'flight-purchase', 260)[0]?.signal).toBe('amount-share');
    expect(riskSignalsFor(mandate({ riskSignals: { amountShare: false } }), 'flight-purchase', 499)).toEqual([]);
    expect(riskSignalsFor(mandate({ riskSignals: false }), 'flight-purchase', 499, { newMerchant: true })).toEqual([]);
  });

  it('an out-of-range share is ignored rather than trusted (no signal from 0, 2 or "lots")', () => {
    for (const amountShare of [0, 2, 'lots']) {
      expect(riskSignalSettings(mandate({ riskSignals: { amountShare } }), 'flight-purchase').amountShare).toBeNull();
    }
  });

  it('new-merchant is HIGH only when the issuer says the merchant is unvetted, and never where the mandate lists merchants', () => {
    expect(riskSignalsFor(mandate(), 'flight-purchase', 10, { newMerchant: true })).toEqual([
      { signal: 'new-merchant', level: 'high', detail: 'the first payment to this merchant' },
    ]);
    expect(riskSignalsFor(mandate({}, ['skyward-air']), 'flight-purchase', 10, { newMerchant: true })).toEqual([]);
    expect(riskSignalsFor(mandate({ riskSignals: { newMerchant: false } }), 'flight-purchase', 10, { newMerchant: true })).toEqual([]);
    expect(riskSignalsFor(mandate(), 'flight-purchase', 10)).toEqual([]); // a guard knows no history: never claims it
  });

  it('the owner tier is a signal too, and effectiveRiskFloor is the highest of them', () => {
    expect(effectiveRiskFloor(mandate({ riskTier: 'medium' }), 'flight-purchase', 10)).toBe('medium');
    expect(effectiveRiskFloor(mandate({ riskTier: 'medium' }), 'flight-purchase', 400)).toBe('high');
    expect(effectiveRiskFloor(mandate({ riskTier: 'critical' }), 'flight-purchase', 400)).toBe('critical');
    expect(effectiveRiskFloor(mandate(), 'flight-purchase', 10)).toBeNull();
    expect(effectiveRiskFloor(mandate(), 'another-action', 10_000)).toBeNull();
  });

  it('no cap, no amount, or a zero amount: no amount-share signal (nothing to compare)', () => {
    expect(riskSignalsFor({ permission: [{ target: 'x', constraint: [] }] }, 'x', 1e9)).toEqual([]);
    expect(riskSignalsFor(mandate(), 'flight-purchase', undefined)).toEqual([]);
    expect(riskSignalsFor(mandate(), 'flight-purchase', 0)).toEqual([]);
  });
});

describe('the agent cannot lower a derived floor', () => {
  it('"low" from the agent over a HIGH amount-share floor is judged high, labelled authoritative', () => {
    const floor = effectiveRiskFloor(mandate(), 'flight-purchase', 480);
    const ctx = buildRuleContext({ unsigned: { riskLevel: 'low' }, riskFloor: floor });
    expect(ctx.riskLevel).toBe('high');
  });
  it('the agent can still RAISE it', () => {
    const ctx = buildRuleContext({ unsigned: { riskLevel: 'critical' }, riskFloor: effectiveRiskFloor(mandate(), 'flight-purchase', 480) });
    expect(ctx.riskLevel).toBe('critical');
  });
});

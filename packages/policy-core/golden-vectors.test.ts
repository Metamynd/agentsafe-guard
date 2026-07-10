import { describe, it, expect } from 'vitest';
import { evaluate, type EvaluateInput } from './evaluate.js';
import type { Molecule } from './standards-rules.js';
import type { Mandate } from './mandate.types.js';
import type { Verdict } from './types.js';

/**
 * Golden vectors — frozen (input → verdict) pairs that pin the composed
 * deterministic evaluation (Standards → SOP → Mandate, most-restrictive wins).
 * A change to any evaluator that alters an established verdict must fail here, so
 * the gate and every guard stay bit-for-bit in agreement (spec §6.3). Each vector
 * is also asserted DETERMINISTIC — evaluate(input) === evaluate(input).
 */

const riskEscalate: Molecule = {
  id: 'risk',
  combinator: 'any',
  atoms: [{ id: 'r', predicate: 'risk-at-or-above', config: { level: 'high' } }],
  decision: 'escalate',
  reasonCode: 'RISK_REVIEW',
};

const capBlock: Molecule = {
  id: 'cap',
  combinator: 'any',
  atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 500 } }],
  decision: 'block',
  reasonCode: 'SOP_SPEND_CAP',
};

const flightMandate: Mandate = {
  permission: [
    {
      target: 'flight-purchase',
      constraint: [
        { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 },
        { leftOperand: 'mm:cumulativeSpend', operator: 'lteq', rightOperand: 1000 },
        { leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: ['amadeus'] },
      ],
    },
  ],
};

const NOW = '2026-07-10T05:12:00Z';

/** Build an EvaluateInput for a flight purchase with the standard rule packs bound. */
function input(amount: number, over: Record<string, unknown> = {}, merchant = 'amadeus'): EvaluateInput {
  return {
    standards: [{ standardKey: 'eu-ai-act', document: { molecules: [riskEscalate] } }],
    sops: [{ standardKey: 'sop:travel', document: { molecules: [capBlock] } }],
    mandate: flightMandate,
    context: { action: 'flight-purchase', amount, ...over },
    mandateRequest: {
      target: 'flight-purchase',
      now: NOW,
      values: { 'mm:payAmount': amount, 'mm:cumulativeSpend': amount, 'mm:merchant': merchant },
    },
  };
}

const allow: Verdict = { decision: 'allow', reasonCode: 'AUTHORIZED', authorizationId: null, remaining: null, proofRef: null };
const verdict = (decision: Verdict['decision'], reasonCode: string): Verdict => ({
  decision,
  reasonCode,
  authorizationId: null,
  remaining: null,
  proofRef: null,
});

const VECTORS: { name: string; input: EvaluateInput; expected: Verdict }[] = [
  {
    name: 'clean purchase within cap, allowed merchant, low risk → allow',
    input: input(100, { riskLevel: 'low' }),
    expected: allow,
  },
  {
    name: 'SOP per-transaction cap fires → block SOP_SPEND_CAP',
    input: input(600, { riskLevel: 'low' }),
    expected: verdict('block', 'SOP_SPEND_CAP'),
  },
  {
    name: 'Standard risk threshold fires → escalate RISK_REVIEW',
    input: input(100, { riskLevel: 'high' }),
    expected: verdict('escalate', 'RISK_REVIEW'),
  },
  {
    name: 'mandate merchant outside allow-list → block MERCHANT_NOT_ALLOWED',
    input: input(100, { riskLevel: 'low' }, 'sabre'),
    expected: verdict('block', 'MERCHANT_NOT_ALLOWED'),
  },
  {
    name: 'precedence: SOP block wins over Standard escalate',
    input: input(600, { riskLevel: 'high' }),
    expected: verdict('block', 'SOP_SPEND_CAP'),
  },
];

describe('golden vectors — composed evaluate()', () => {
  for (const v of VECTORS) {
    it(v.name, () => {
      expect(evaluate(v.input)).toEqual(v.expected);
    });
    it(`${v.name} — deterministic`, () => {
      expect(evaluate(v.input)).toEqual(evaluate(v.input));
    });
  }
});

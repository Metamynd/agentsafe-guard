/**
 * Authority outranks rules when the question is WHY.
 *
 * The round-four conversion test probed a sandbox agent with actions its mandate never
 * granted, including two flavours of self-escalation, and every one was refused. Nothing
 * was unsafe. But the refusal for `permissions.update` at $100,000 came back
 * `SOP_SPEND_CAP`, and the identical call at $1 came back `NO_PERMISSION_FOR_ACTION` —
 * because the rule layers ran first, a rule block and a mandate block tie on
 * restrictiveness, and a tie kept the incumbent.
 *
 * The consequence is not a security hole, it is a lie about the mechanism: as written, the
 * verdict says a bigger cap would let an agent rewrite its own authority. It would not. A
 * developer reading the reason code cannot know that, and a reviewer reading the evidence
 * trail would credit the wrong control with having held.
 *
 * These tests pin the corrected order and, just as importantly, pin what did NOT change:
 * an in-scope request that trips both an SOP cap and the mandate cap must still report the
 * SOP, which is the more specific and more editable of the two.
 */

import { describe, it, expect } from 'vitest';

import { evaluate } from './evaluate.js';
import { authorityFailure } from './mandate-eval.js';
import type { Mandate } from './mandate.types.js';
import type { RulePack } from './evaluate.js';

const NOW = '2026-08-23T00:00:00Z';

/** The sandbox agent's shape: one granted action, a per-transaction cap, a merchant list. */
const mandate: Mandate = {
  uid: 'urn:metamynd:mandate:authority-precedence',
  validFrom: '2026-08-01T00:00:00Z',
  validUntil: '2026-12-31T23:59:59Z',
  permission: [
    {
      target: 'flight-purchase',
      action: 'execute',
      constraint: [
        { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 500, unit: 'USD' },
        { leftOperand: 'mm:cumulativeSpend', operator: 'lteq', rightOperand: 5000, unit: 'USD' },
      ],
    },
  ],
};

/** The sandbox's starter SOP: block over the per-transaction cap. */
const sops: RulePack[] = [
  {
    standardKey: 'sandbox-controls',
    document: {
      molecules: [
        {
          id: 'cap',
          name: 'Per-transaction cap',
          combinator: 'any',
          atoms: [{ id: 'a1', predicate: 'amount-over', config: { limit: 500 } }],
          decision: 'block',
          reasonCode: 'SOP_SPEND_CAP',
        },
      ],
    },
  },
];

const verdictFor = (action: string, amount: number) =>
  evaluate({
    sops,
    mandate,
    context: { action, amount },
    mandateRequest: {
      target: action,
      now: NOW,
      values: { 'mm:payAmount': amount, 'mm:cumulativeSpend': amount, 'mm:currency': 'USD' },
    },
  });

describe('authority precedence', () => {
  it('names the cap when an in-scope request is simply too large', () => {
    // Unchanged behaviour, and the reason this fix had to be surgical: the action IS
    // granted, so the SOP is genuinely why it was refused.
    expect(verdictFor('flight-purchase', 5_000)).toMatchObject({
      decision: 'block',
      reasonCode: 'SOP_SPEND_CAP',
    });
  });

  it('names the missing permission for an ungranted action, whatever the amount', () => {
    // The bug: at $1 the SOP did not fire and the truth surfaced; at $100,000 it did fire
    // and buried it. Both must now answer the same way.
    for (const amount of [1, 100_000]) {
      expect(verdictFor('permissions.update', amount)).toMatchObject({
        decision: 'block',
        reasonCode: 'NO_PERMISSION_FOR_ACTION',
      });
    }
  });

  it('answers identically for an action nobody has ever heard of', () => {
    expect(verdictFor('wibble.wobble', 100_000).reasonCode).toBe('NO_PERMISSION_FOR_ACTION');
  });

  it('reports the expiry, not a rule, when the mandate has run out', () => {
    // Expiry is the same defect in a second costume, and it was there too: an expired
    // mandate grants nothing, so "your spend cap" is exactly as misleading a reason as it
    // was for the ungranted action, and for the same tie.
    const expired: Mandate = { ...mandate, validUntil: '2026-08-02T00:00:00Z' };
    expect(
      evaluate({
        sops,
        mandate: expired,
        context: { action: 'flight-purchase', amount: 100_000 },
        mandateRequest: { target: 'flight-purchase', now: NOW, values: {} },
      }),
    ).toMatchObject({ decision: 'block', reasonCode: 'MANDATE_EXPIRED' });
  });

  it('leaves a prohibition ranked alongside the rules, not above them', () => {
    // Deliberately NOT changed. A prohibition says how a target may be treated, which is
    // the same kind of statement an SOP makes about it — so which one names the refusal is
    // a genuine judgement call about specificity, not the lie the authority tie was. It is
    // pinned here so a later change to it is a decision somebody made on purpose.
    const prohibited: Mandate = {
      ...mandate,
      prohibition: [{ target: 'flight-purchase', action: 'execute', reasonCode: 'PROHIBITED_ACTION' }],
    };
    expect(
      evaluate({
        sops,
        mandate: prohibited,
        context: { action: 'flight-purchase', amount: 100_000 },
        mandateRequest: { target: 'flight-purchase', now: NOW, values: {} },
      }),
    ).toMatchObject({ decision: 'block', reasonCode: 'SOP_SPEND_CAP' });
  });

  it('lets a containment molecule outrank the authority answer', () => {
    // The regression this fix nearly introduced. On the gate a `suspend`/`quarantine`
    // verdict does more than refuse this call — it persists containment on the agent and
    // denies everything after it. Short-circuiting on authority would have downgraded that
    // to a one-call block and lost the containment, trading a cosmetic reason-code fix for
    // a real safety hole. So authority seeds the accumulator; it does not return.
    const containing: RulePack[] = [
      {
        standardKey: 'containment',
        document: {
          molecules: [
            {
              id: 'runaway',
              name: 'Contain a runaway agent',
              combinator: 'any',
              atoms: [{ id: 'a1', predicate: 'amount-over', config: { limit: 500 } }],
              decision: 'quarantine',
              reasonCode: 'RUNAWAY_AGENT',
            },
          ],
        },
      },
    ];
    expect(
      evaluate({
        standards: containing,
        sops,
        mandate,
        context: { action: 'permissions.update', amount: 100_000 },
        mandateRequest: { target: 'permissions.update', now: NOW, values: {} },
      }),
    ).toMatchObject({ decision: 'quarantine', reasonCode: 'RUNAWAY_AGENT' });
  });

  it('outranks an escalate, because there is nothing to approve', () => {
    // A human cannot grant authority the mandate does not carry, so routing an ungranted
    // action to a review queue would put an unanswerable question in front of somebody.
    const reviewing: RulePack[] = [
      {
        standardKey: 'review',
        document: {
          molecules: [
            {
              id: 'big',
              name: 'Large amounts go to a human',
              combinator: 'any',
              atoms: [{ id: 'a1', predicate: 'amount-over', config: { limit: 500 } }],
              decision: 'escalate',
              reasonCode: 'RISK_REVIEW',
            },
          ],
        },
      },
    ];
    expect(
      evaluate({
        sops: reviewing,
        mandate,
        context: { action: 'permissions.update', amount: 100_000 },
        mandateRequest: { target: 'permissions.update', now: NOW, values: {} },
      }),
    ).toMatchObject({ decision: 'block', reasonCode: 'NO_PERMISSION_FOR_ACTION' });
  });

  it('permits a granted, in-budget request exactly as before', () => {
    expect(verdictFor('flight-purchase', 150)).toMatchObject({ decision: 'allow' });
  });

  it('authorityFailure answers for standing alone, and needs no operands to do it', () => {
    expect(authorityFailure(mandate, 'permissions.update', NOW)).toMatchObject({
      reasonCode: 'NO_PERMISSION_FOR_ACTION',
    });
    // In scope: standing exists, whatever the constraints later decide about the amount.
    expect(authorityFailure(mandate, 'flight-purchase', NOW)).toBeNull();
    // Expired: no standing for anything, including actions it once granted.
    const expired: Mandate = { ...mandate, validUntil: '2026-08-02T00:00:00Z' };
    expect(authorityFailure(expired, 'flight-purchase', NOW)).toMatchObject({
      reasonCode: 'MANDATE_EXPIRED',
    });
  });
});

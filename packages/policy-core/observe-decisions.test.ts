import { describe, it, expect } from 'vitest';
import { evaluateStandardRules, evaluateBoundStandards, validateMolecules, type Molecule } from './standards-rules.js';
import { evaluate } from './evaluate.js';
import { evaluateMandate } from './mandate-eval.js';
import type { Mandate } from './mandate.types.js';
import type { EvaluationContext } from './types.js';

/**
 * OBSERVE decisions (SAFR §11): 'observe' extends the fire-decision vocabulary as a
 * PERMIT-BUT-FLAG outcome. It outranks 'allow' (a flag survives an otherwise-allow
 * verdict) but is outranked by every deny/escalate (a human-review or block always
 * wins over a mere flag). These pin the precedence, validation, and permit behaviour;
 * the gate/guard treat allow AND observe as the two execution-permitting verdicts.
 */
const fires = (decision: Molecule['decision'], reason: string): Molecule => ({
    id: `m-${decision}`,
    combinator: 'any',
    atoms: [{ id: 'a1', predicate: 'amount-over', config: { limit: 100 } }],
    decision,
    reasonCode: reason,
});
const ctx = (amount: number): EvaluationContext => ({ action: 'x', amount });

describe('observe decisions', () => {
    it('validateMolecules accepts observe', () => {
        expect(validateMolecules([fires('observe', 'WATCH')]).ok).toBe(true);
    });

    it('precedence: block > escalate > observe > allow (most-restrictive wins)', () => {
        // observe outranks allow (a non-firing molecule = allow), so a firing observe surfaces.
        expect(evaluateStandardRules([fires('observe', 'W')], ctx(1000)).decision).toBe('observe');
        // but any escalate/block outranks observe.
        expect(evaluateStandardRules([fires('observe', 'W'), fires('escalate', 'E')], ctx(1000)).decision).toBe('escalate');
        expect(evaluateStandardRules([fires('observe', 'W'), fires('block', 'B')], ctx(1000)).decision).toBe('block');
    });

    it('a non-firing observe molecule leaves the action allowed', () => {
        expect(evaluateStandardRules([fires('observe', 'W')], ctx(50)).decision).toBe('allow');
    });

    it('across bound standards, observe wins over allow but loses to a deny', () => {
        const observeThenAllow = evaluateBoundStandards(
            [
                { standardKey: 's1', document: { molecules: [fires('observe', 'W')] } },
                { standardKey: 's2', document: { molecules: [] } },
            ],
            ctx(999),
        );
        expect(observeThenAllow.decision).toBe('observe');
        expect(observeThenAllow.reasonCode).toBe('W');
        expect(observeThenAllow.standardKey).toBe('s1');

        const observeThenBlock = evaluateBoundStandards(
            [
                { standardKey: 's1', document: { molecules: [fires('observe', 'W')] } },
                { standardKey: 's2', document: { molecules: [fires('block', 'B')] } },
            ],
            ctx(999),
        );
        expect(observeThenBlock.decision).toBe('block');
    });

    it('the composed evaluate() surfaces observe through the full Standards→SOP→Mandate compose', () => {
        const v = evaluate({
            standards: [{ standardKey: 's1', document: { molecules: [fires('observe', 'WATCH_LARGE')] } }],
            context: ctx(1000),
        });
        expect(v.decision).toBe('observe');
        expect(v.reasonCode).toBe('WATCH_LARGE');
        // A permit carries no authorizationId at the pure layer — the gate mints it.
        expect(v.authorizationId).toBeNull();
    });

    it('a mandate permission constraint can be authored to observe (permit-but-flag) via onFail', () => {
        const mandate: Mandate = {
            target: 'mm:pay',
            permission: [
                {
                    target: 'mm:pay',
                    constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 100, onFail: 'observe' }],
                },
            ],
        };
        const res = evaluateMandate(mandate, { target: 'mm:pay', now: '2026-08-10T00:00:00Z', values: { 'mm:payAmount': 500 } });
        expect(res.decision).toBe('observe');
    });
});

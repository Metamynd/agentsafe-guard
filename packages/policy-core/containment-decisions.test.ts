import { describe, it, expect } from 'vitest';
import { evaluateStandardRules, evaluateBoundStandards, validateMolecules, type Molecule } from './standards-rules.js';
import { evaluateMandate } from './mandate-eval.js';
import type { Mandate } from './mandate.types.js';
import type { EvaluationContext } from './types.js';

/**
 * Containment decisions (1C): suspend/quarantine extend the fire-decision
 * vocabulary as terminal denies that outrank a plain block. These pin the
 * precedence, validation, and mandate-authoring behaviour. Fail-safety itself is
 * covered by the gate/guard, which permit ONLY `allow`.
 */
const fires = (decision: Molecule['decision'], reason: string): Molecule => ({
    id: `m-${decision}`,
    combinator: 'any',
    atoms: [{ id: 'a1', predicate: 'amount-over', config: { limit: 100 } }],
    decision,
    reasonCode: reason,
});
const ctx = (amount: number): EvaluationContext => ({ action: 'x', amount });

describe('containment decisions', () => {
    it('validateMolecules accepts suspend/quarantine and rejects an unknown decision', () => {
        expect(validateMolecules([fires('suspend', 'S')]).ok).toBe(true);
        expect(validateMolecules([fires('quarantine', 'Q')]).ok).toBe(true);
        const bad = validateMolecules([{ ...fires('block', 'B'), decision: 'nuke' as never }]);
        expect(bad.ok).toBe(false);
        expect(bad.issues[0].message).toMatch(/invalid decision/);
    });

    it('precedence: quarantine > suspend > block > escalate (most-restrictive wins)', () => {
        expect(evaluateStandardRules([fires('escalate', 'E'), fires('quarantine', 'Q')], ctx(1000)).decision).toBe('quarantine');
        expect(evaluateStandardRules([fires('block', 'B'), fires('suspend', 'S')], ctx(1000)).decision).toBe('suspend');
        expect(evaluateStandardRules([fires('block', 'B'), fires('escalate', 'E')], ctx(1000)).decision).toBe('block');
    });

    it('a non-firing containment molecule leaves the action allowed', () => {
        expect(evaluateStandardRules([fires('quarantine', 'Q')], ctx(50)).decision).toBe('allow');
    });

    it('across bound standards, the single most-restrictive decision wins', () => {
        const r = evaluateBoundStandards(
            [
                { standardKey: 's1', document: { molecules: [fires('block', 'B')] } },
                { standardKey: 's2', document: { molecules: [fires('quarantine', 'Q')] } },
            ],
            ctx(999),
        );
        expect(r.decision).toBe('quarantine');
        expect(r.reasonCode).toBe('Q');
        expect(r.standardKey).toBe('s2');
    });

    it('a mandate prohibition can be authored to quarantine (contain, not just block)', () => {
        const mandate: Mandate = {
            target: 'mm:pay',
            prohibition: [{ target: 'mm:pay', enforcement: 'quarantine', reasonCode: 'ROGUE_ACTION' }],
        };
        const res = evaluateMandate(mandate, { target: 'mm:pay', now: '2026-07-27T00:00:00Z', values: {} });
        expect(res.decision).toBe('quarantine');
        expect(res.reasonCode).toBe('ROGUE_ACTION');
    });
});

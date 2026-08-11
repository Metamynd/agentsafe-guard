import { describe, it, expect } from 'vitest';
import { ATOM_REGISTRY } from './atom-registry.js';
import { ATOM_SPECS } from './atom-catalog.js';
import type { EvaluationContext } from './types.js';

/**
 * Evidence-quality atoms (SAFR §24, Phase-4 PR-3). Unlike the allow-list atoms, these are REQUIRE
 * controls: they fire on ABSENCE (missing / low-confidence evidence) so an author can escalate or
 * block an under-evidenced action. Opt-in — they only run when a molecule keys them.
 */
const requirement = ATOM_REGISTRY['evidence-requirement'];
const confidenceBelow = ATOM_REGISTRY['evidence-confidence-below'];
const ctx = (over: Partial<EvaluationContext> = {}): EvaluationContext => ({ action: 'purchase', ...over });

describe('evidence-requirement', () => {
  it('fires when a required evidence type is missing (including none attested)', () => {
    expect(requirement(ctx({ evidenceTypes: ['kyc'] }), { required: ['kyc', 'source-doc'] })).toBe(true);
    expect(requirement(ctx({}), { required: ['kyc'] })).toBe(true); // nothing attested → missing
  });
  it('does not fire when every required type is attested (case/space-insensitive)', () => {
    expect(requirement(ctx({ evidenceTypes: ['KYC', ' source-doc '] }), { required: ['kyc', 'source-doc'] })).toBe(false);
  });
  it('never fires with no requirement configured', () => {
    expect(requirement(ctx({}), { required: [] })).toBe(false);
    expect(requirement(ctx({ evidenceTypes: ['x'] }), {})).toBe(false);
  });
});

describe('evidence-confidence-below', () => {
  it('fires when attested confidence is below the minimum', () => {
    expect(confidenceBelow(ctx({ evidenceConfidence: 0.6 }), { min: 0.8 })).toBe(true);
    expect(confidenceBelow(ctx({ evidenceConfidence: 0.8 }), { min: 0.8 })).toBe(false); // at the bar passes
    expect(confidenceBelow(ctx({ evidenceConfidence: 0.95 }), { min: 0.8 })).toBe(false);
  });
  it('fires when confidence is absent but a minimum is required', () => {
    expect(confidenceBelow(ctx({}), { min: 0.8 })).toBe(true);
  });
  it('never fires when no minimum is set (min 0 / unset = no requirement)', () => {
    expect(confidenceBelow(ctx({}), { min: 0 })).toBe(false);
    expect(confidenceBelow(ctx({}), {})).toBe(false);
    expect(confidenceBelow(ctx({ evidenceConfidence: 0 }), {})).toBe(false);
  });
});

describe('catalog parity', () => {
  it('both evidence atoms have a spec whose requiredContext names the context they read', () => {
    for (const pred of ['evidence-requirement', 'evidence-confidence-below']) {
      const spec = ATOM_SPECS.find((s) => s.predicate === pred);
      expect(spec, `missing spec for ${pred}`).toBeTruthy();
      expect(ATOM_REGISTRY[pred], `missing impl for ${pred}`).toBeTypeOf('function');
      expect(spec!.requiredContext.length).toBeGreaterThan(0);
    }
  });
});

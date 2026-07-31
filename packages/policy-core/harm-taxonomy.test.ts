import { describe, it, expect } from 'vitest';
import {
  validateHarms,
  harmsFromDocument,
  summarizeHarmCoverage,
  isHarmCategory,
  type HarmAnnotation,
} from './harm-taxonomy.js';

const good: HarmAnnotation = {
  category: 'financial',
  subtype: 'unauthorized financial loss',
  foreseeability: { level: 'known', basis: ['known-incident', 'architecture'] },
};

describe('validateHarms', () => {
  it('accepts absent harms (optional / backward-compatible)', () => {
    expect(validateHarms(undefined)).toEqual({ ok: true, issues: [] });
    expect(validateHarms(null)).toEqual({ ok: true, issues: [] });
    expect(validateHarms([])).toEqual({ ok: true, issues: [] });
  });

  it('accepts a well-formed annotation', () => {
    expect(validateHarms([good])).toMatchObject({ ok: true });
  });

  it('rejects an invalid category', () => {
    const r = validateHarms([{ ...good, category: 'made-up' as never }]);
    expect(r.ok).toBe(false);
    expect(r.issues[0].message).toMatch(/invalid harm category/);
  });

  it('rejects an invalid foreseeability level', () => {
    const r = validateHarms([{ ...good, foreseeability: { level: 'certain' as never, basis: ['x'] } }]);
    expect(r.ok).toBe(false);
    expect(r.issues[0].message).toMatch(/invalid foreseeability level/);
  });

  it('requires a non-empty foreseeability basis (WHY it is foreseeable)', () => {
    expect(validateHarms([{ ...good, foreseeability: { level: 'known', basis: [] } }]).ok).toBe(false);
    expect(validateHarms([{ ...good, foreseeability: { level: 'known', basis: ['  '] } }]).ok).toBe(false);
  });

  it('rejects a non-array', () => {
    expect(validateHarms({ category: 'financial' }).ok).toBe(false);
  });

  it('isHarmCategory guards the vocabulary', () => {
    expect(isHarmCategory('privacy')).toBe(true);
    expect(isHarmCategory('vibes')).toBe(false);
  });
});

describe('harmsFromDocument — defensive read', () => {
  it('returns only the valid annotations', () => {
    const doc = { molecules: [], harms: [good, { category: 'nonsense' }, { category: 'privacy' /* no foreseeability */ }] };
    const out = harmsFromDocument(doc);
    expect(out).toHaveLength(1);
    expect(out[0].category).toBe('financial');
  });
  it('handles a document with no harms', () => {
    expect(harmsFromDocument({ molecules: [] })).toEqual([]);
    expect(harmsFromDocument(null)).toEqual([]);
  });
});

describe('summarizeHarmCoverage', () => {
  it('aggregates per category and keeps the STRONGEST foreseeability', () => {
    const harms: HarmAnnotation[] = [
      { category: 'financial', subtype: 'loss', foreseeability: { level: 'emerging', basis: ['a'] } },
      { category: 'financial', subtype: 'fraud', foreseeability: { level: 'known', basis: ['b'] } },
      { category: 'privacy', foreseeability: { level: 'reasonably-foreseeable', basis: ['c'] } },
    ];
    const cov = summarizeHarmCoverage(harms);
    // Declared-taxonomy order: financial before privacy.
    expect(cov.map((c) => c.category)).toEqual(['financial', 'privacy']);
    const fin = cov.find((c) => c.category === 'financial')!;
    expect(fin.count).toBe(2);
    expect(fin.worstForeseeability).toBe('known'); // strongest of emerging/known
    expect(fin.subtypes.sort()).toEqual(['fraud', 'loss']);
  });
  it('is empty for no harms', () => {
    expect(summarizeHarmCoverage([])).toEqual([]);
  });
});

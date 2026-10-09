import { describe, expect, it } from 'vitest';
import { ATOM_REGISTRY } from './atom-registry.js';
import { EU_MEMBER_STATES, expandJurisdictionGroups } from './jurisdiction-groups.js';
import type { EvaluationContext } from './types.js';

// Self-contained on purpose: policy-core is mirrored to the public Metamynd/agentsafe-guard repo, where `@/features/...`
// does not exist. That the mandate expands EU to this same list is pinned in features/policy/mandate/jurisdiction.test.ts.

/**
 * Before 2026-10-09 the `jurisdiction-not-allowed` atom compared "EU" literally, so a rule allowing ['GB', 'EU'] (the
 * onboarding rule pack and the sandbox baseline both list EU) refused a request signed FR — while the mandate's own term,
 * given the same list, allowed it. One list now serves both.
 */
const fires = (jurisdiction: string | undefined, allowed: unknown) =>
  ATOM_REGISTRY['jurisdiction-not-allowed']({ action: 'x', ...(jurisdiction ? { jurisdiction } : {}) } as EvaluationContext, { allowed });

describe('jurisdiction-not-allowed reads "EU" as its member states', () => {
  it('allows every member state, in any case', () => {
    for (const c of EU_MEMBER_STATES) expect(fires(c, ['GB', 'EU']), c).toBe(false);
    expect(fires('fr', ['eu'])).toBe(false);
  });

  it('still refuses a country outside the list, and EU-adjacent non-members', () => {
    for (const c of ['US', 'CH', 'NO', 'IS']) expect(fires(c, ['GB', 'EU']), c).toBe(true);
    expect(fires('FR', ['GB'])).toBe(true);
  });

  it('keeps matching a request that literally signs EU, as before (it only ever widens)', () => {
    expect(fires('EU', ['EU'])).toBe(false);
  });

  it('is otherwise unchanged: a missing jurisdiction does not fire, an empty list fires on any value', () => {
    expect(fires(undefined, ['EU'])).toBe(false);
    expect(fires('FR', [])).toBe(true);
  });
});

describe('expandJurisdictionGroups', () => {
  it('expandJurisdictionGroups keeps the group code and adds its members once', () => {
    const out = expandJurisdictionGroups(['gb', 'EU', 'FR']);
    expect(out).toContain('GB');
    expect(out).toContain('EU');
    expect(out.filter((c) => c === 'FR')).toHaveLength(1);
    expect(out).toHaveLength(2 + EU_MEMBER_STATES.length);
  });

  it('an inherited property name is not a group', () => {
    expect(expandJurisdictionGroups(['constructor', '__proto__'])).toEqual(['CONSTRUCTOR', '__PROTO__']);
  });
});

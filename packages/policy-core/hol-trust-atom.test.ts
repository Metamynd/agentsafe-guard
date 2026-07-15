import { describe, it, expect } from 'vitest';
import { ATOM_REGISTRY } from './atom-registry.js';

const atom = ATOM_REGISTRY['hol-trust-below-review'];

describe('hol-trust-below-review atom (Trust Index guidance)', () => {
  it('fires when the counterparty trust score is below the review line', () => {
    expect(atom({ holTrustScore: 55 }, { reviewBelow: 60 })).toBe(true);
    expect(atom({ holTrustScore: 0 }, { reviewBelow: 60 })).toBe(true);
  });

  it('does not fire at or above the review line', () => {
    expect(atom({ holTrustScore: 60 }, { reviewBelow: 60 })).toBe(false);
    expect(atom({ holTrustScore: 90 }, { reviewBelow: 60 })).toBe(false);
  });

  it('does not fire when no trust score is present — no counterparty, no guidance', () => {
    expect(atom({}, { reviewBelow: 60 })).toBe(false);
    expect(atom({ holTrustScore: 'high' as unknown as number }, { reviewBelow: 60 })).toBe(false);
    expect(atom({ holTrustScore: null as unknown as number }, { reviewBelow: 60 })).toBe(false);
  });

  it('defaults the review line to 60 when unconfigured', () => {
    expect(atom({ holTrustScore: 59 })).toBe(true);
    expect(atom({ holTrustScore: 61 })).toBe(false);
  });
});

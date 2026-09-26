import { describe, it, expect } from 'vitest';
import { AUTH_MESSAGE_V2_TAG, buildAuthMessage } from './canonical.js';

const base = {
  agentDid: 'did:key:zAgent',
  action: 'flight-purchase',
  amount: 100,
  currency: 'USD',
  merchant: 'skyward-air',
  nonce: 'n-1',
  issuedAt: '2026-01-01T00:00:00.000Z',
};

describe('buildAuthMessage', () => {
  it('joins the eight fields with | in the documented order', () => {
    expect(buildAuthMessage(base)).toBe('did:key:zAgent|flight-purchase|100|USD|skyward-air||n-1|2026-01-01T00:00:00.000Z');
  });

  it('substitutes an empty string for an absent merchant', () => {
    expect(buildAuthMessage({ ...base, merchant: undefined })).toBe(
      'did:key:zAgent|flight-purchase|100|USD|||n-1|2026-01-01T00:00:00.000Z',
    );
  });

  it('substitutes an empty string for an absent resource', () => {
    // resource omitted entirely — the overwhelmingly common (non-resource-scoped) case.
    // Confirms this produces the SAME bytes as an explicit resource: undefined, so an old
    // caller that never even knows about `resource` signs identically to one that does but
    // has nothing to declare.
    expect(buildAuthMessage(base)).toBe(buildAuthMessage({ ...base, resource: undefined }));
  });

  it('a genuine resource is a signed field — a different resource produces a different signed message', () => {
    // The whole point of moving `resource` into buildAuthMessage rather than leaving it
    // signed-last-ordered: two requests differing ONLY in resource must sign differently,
    // or a compromised counterparty relaying a buildSignedRequest()-built request could
    // swap which resource is declared without invalidating the signature.
    const a = buildAuthMessage({ ...base, resource: 'inspection-db' });
    const b = buildAuthMessage({ ...base, resource: 'billing-db' });
    const none = buildAuthMessage({ ...base, resource: undefined });
    expect(a).not.toBe(b);
    expect(a).not.toBe(none);
    expect(a).toBe('did:key:zAgent|flight-purchase|100|USD|skyward-air|inspection-db|n-1|2026-01-01T00:00:00.000Z');
  });

  it('is unaffected by escaping for every value used in this codebase today (no | or \\\\)', () => {
    // Locks in that the escaping hardening below is a no-op for real traffic — any
    // agentDid/action/currency/merchant/resource/nonce/timestamp actually produced by this system.
    const withResource = { ...base, resource: 'inspection-db' };
    expect(buildAuthMessage(withResource)).toBe(
      `${withResource.agentDid}|${withResource.action}|${withResource.amount}|${withResource.currency}|${withResource.merchant}|${withResource.resource}|${withResource.nonce}|${withResource.issuedAt}`,
    );
  });

  it('escapes a literal | inside a field so it cannot be mistaken for the delimiter', () => {
    // Without escaping, a merchant of "A|1000|USD|EVIL" (say, extracted by an LLM agent
    // from an untrusted content) would occupy the same bytes a genuinely-different,
    // shorter field-tuple could also produce (see the collision test below). Escaped,
    // the merchant's own pipes are visibly distinct (\|) from real field-boundary pipes.
    const withPipe = buildAuthMessage({ ...base, merchant: 'A|1000|USD|EVIL' });
    expect(withPipe).toBe('did:key:zAgent|flight-purchase|100|USD|A\\|1000\\|USD\\|EVIL||n-1|2026-01-01T00:00:00.000Z');
  });

  it('escapes a literal backslash so it cannot be used to smuggle a fake escape sequence', () => {
    const withBackslash = buildAuthMessage({ ...base, merchant: 'A\\|B' });
    // "A\|B" must decode as literal backslash + literal pipe, not as an escaped pipe —
    // achieved by escaping the backslash FIRST, then the pipe.
    expect(withBackslash).toBe('did:key:zAgent|flight-purchase|100|USD|A\\\\\\|B||n-1|2026-01-01T00:00:00.000Z');
  });

  it('two different field-tuples that would collide unescaped now produce different bytes', () => {
    // Unescaped, currency:"USD", merchant:"A|1000|USD|EVIL" and some other split of the
    // same characters across adjacent fields could join to identical bytes. Escaped, the
    // field boundary is unambiguous, so no two distinct tuples used in this suite collide.
    const a = buildAuthMessage({ ...base, currency: 'USD', merchant: 'A|1000|USD|EVIL' });
    const b = buildAuthMessage({ ...base, currency: 'USD|A', merchant: '1000|USD|EVIL' });
    expect(a).not.toBe(b);
  });
});

describe('buildAuthMessage v2 — the signed jurisdiction (§8.3.12)', () => {
  it('absent (undefined or null) is the v1 eight-field message, byte for byte', () => {
    const v1 = 'did:key:zAgent|flight-purchase|100|USD|skyward-air||n-1|2026-01-01T00:00:00.000Z';
    expect(buildAuthMessage(base)).toBe(v1);
    expect(buildAuthMessage({ ...base, jurisdiction: undefined })).toBe(v1);
    expect(buildAuthMessage({ ...base, jurisdiction: null })).toBe(v1);
  });

  it('present appends the version tag and the literal value: ten fields', () => {
    expect(AUTH_MESSAGE_V2_TAG).toBe('MAGP-AUTH-v2');
    expect(buildAuthMessage({ ...base, jurisdiction: 'SG' })).toBe('did:key:zAgent|flight-purchase|100|USD|skyward-air||n-1|2026-01-01T00:00:00.000Z|MAGP-AUTH-v2|SG');
    expect(buildAuthMessage({ ...base, resource: 'db', jurisdiction: 'DE' })).toBe('did:key:zAgent|flight-purchase|100|USD|skyward-air|db|n-1|2026-01-01T00:00:00.000Z|MAGP-AUTH-v2|DE');
  });

  it('is signed as transmitted (no case folding in the message) and differs per value', () => {
    expect(buildAuthMessage({ ...base, jurisdiction: 'sg' })).not.toBe(buildAuthMessage({ ...base, jurisdiction: 'SG' }));
    expect(buildAuthMessage({ ...base, jurisdiction: 'SG' })).not.toBe(buildAuthMessage({ ...base, jurisdiction: 'DE' }));
  });

  it('a v2 message can never equal a v1 one: a delimiter smuggled into issuedAt is escaped, not a field boundary', () => {
    const smuggled = buildAuthMessage({ ...base, issuedAt: '2026-01-01T00:00:00.000Z|MAGP-AUTH-v2|SG' });
    expect(smuggled).not.toBe(buildAuthMessage({ ...base, jurisdiction: 'SG' }));
    expect(smuggled).toContain('\\|MAGP-AUTH-v2\\|SG');
  });
});

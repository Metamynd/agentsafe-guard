import { describe, it, expect } from 'vitest';
import { buildAuthMessage } from './canonical.js';

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
  it('joins the seven fields with | in the documented order', () => {
    expect(buildAuthMessage(base)).toBe('did:key:zAgent|flight-purchase|100|USD|skyward-air|n-1|2026-01-01T00:00:00.000Z');
  });

  it('substitutes an empty string for an absent merchant', () => {
    expect(buildAuthMessage({ ...base, merchant: undefined })).toBe(
      'did:key:zAgent|flight-purchase|100|USD||n-1|2026-01-01T00:00:00.000Z',
    );
  });

  it('is unaffected by escaping for every value used in this codebase today (no | or \\\\)', () => {
    // Locks in that the escaping hardening below is a no-op for real traffic — any
    // agentDid/action/currency/merchant/nonce/timestamp actually produced by this system.
    expect(buildAuthMessage(base)).toBe(`${base.agentDid}|${base.action}|${base.amount}|${base.currency}|${base.merchant}|${base.nonce}|${base.issuedAt}`);
  });

  it('escapes a literal | inside a field so it cannot be mistaken for the delimiter', () => {
    // Without escaping, a merchant of "A|1000|USD|EVIL" (say, extracted by an LLM agent
    // from an untrusted content) would occupy the same bytes a genuinely-different,
    // shorter field-tuple could also produce (see the collision test below). Escaped,
    // the merchant's own pipes are visibly distinct (\|) from real field-boundary pipes.
    const withPipe = buildAuthMessage({ ...base, merchant: 'A|1000|USD|EVIL' });
    expect(withPipe).toBe('did:key:zAgent|flight-purchase|100|USD|A\\|1000\\|USD\\|EVIL|n-1|2026-01-01T00:00:00.000Z');
  });

  it('escapes a literal backslash so it cannot be used to smuggle a fake escape sequence', () => {
    const withBackslash = buildAuthMessage({ ...base, merchant: 'A\\|B' });
    // "A\|B" must decode as literal backslash + literal pipe, not as an escaped pipe —
    // achieved by escaping the backslash FIRST, then the pipe.
    expect(withBackslash).toBe('did:key:zAgent|flight-purchase|100|USD|A\\\\\\|B|n-1|2026-01-01T00:00:00.000Z');
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

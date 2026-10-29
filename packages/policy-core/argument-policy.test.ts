import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  argumentPoliciesFor,
  argumentPolicyNarrowing,
  argumentPolicyProblem,
  checkArguments,
  parseArgumentPointer,
  sanitizeArguments,
  HMAC_ARGUMENT_PREFIX,
  REDACTED_ARGUMENT,
} from './argument-policy.js';
import { delegationVerdict } from './delegation.js';
import type { Mandate } from './mandate.types.js';

const hmac = (s: string) => createHmac('sha256', 'guard-key').update(s).digest('hex');

describe('parseArgumentPointer', () => {
  it('reads RFC 6901 pointers, unescaping ~1 and ~0', () => {
    expect(parseArgumentPointer('/a/b')).toEqual(['a', 'b']);
    expect(parseArgumentPointer('/a~1b/c~0d')).toEqual(['a/b', 'c~d']);
    expect(parseArgumentPointer('/items/*/sku')).toEqual(['items', '*', 'sku']);
  });
  it('refuses the root, a relative path and a malformed escape', () => {
    for (const bad of ['', 'a/b', '/a~2', '/a~', 7, null]) expect(parseArgumentPointer(bad)).toBeNull();
  });
});

describe('argumentPolicyProblem', () => {
  it('accepts a well-formed policy', () => {
    expect(argumentPolicyProblem({ allow: ['/to', '/amount'], sensitive: [{ path: '/to', mode: 'hmac' }] })).toBeNull();
  });
  it('refuses an empty allow list, a root path and an unknown mode', () => {
    expect(argumentPolicyProblem({ allow: [] })).toMatch(/at least one/);
    expect(argumentPolicyProblem({ allow: [''] })).toMatch(/JSON Pointer/);
    expect(argumentPolicyProblem({ allow: ['/a'], sensitive: [{ path: '/a', mode: 'mask' }] })).toMatch(/mode/);
    expect(argumentPolicyProblem(['/a'])).toMatch(/object/);
  });
});

describe('checkArguments', () => {
  const policy = { allow: ['/to', '/subject', '/items/*/sku', '/meta'] };

  it('passes when there is no policy, whatever the arguments', () => {
    expect(checkArguments([], { anything: 1 })).toEqual({ ok: true });
  });

  it('passes arguments that stay inside the allowed paths', () => {
    expect(checkArguments([policy], { to: 'a@b.c', subject: 'hi', items: [{ sku: 'x' }, { sku: 'y' }], meta: { deep: { ok: true } } })).toEqual({ ok: true });
    expect(checkArguments([policy], {})).toEqual({ ok: true });
  });

  it('refuses a stray field, naming its path (fails closed)', () => {
    expect(checkArguments([policy], { to: 'a@b.c', bcc: 'x@evil' })).toEqual({ ok: false, reasonCode: 'ARGUMENT_NOT_ALLOWED', path: '/bcc' });
    expect(checkArguments([policy], { items: [{ sku: 'x', price: 0 }] })).toEqual({ ok: false, reasonCode: 'ARGUMENT_NOT_ALLOWED', path: '/items/0/price' });
  });

  it('refuses a renamed or re-cased key', () => {
    expect(checkArguments([policy], { To: 'a@b.c' })).toMatchObject({ ok: false, path: '/To' });
    expect(checkArguments([policy], { 'to ': 'a@b.c' })).toMatchObject({ ok: false, reasonCode: 'ARGUMENT_NOT_ALLOWED' });
  });

  it('escapes the refused path as a JSON Pointer', () => {
    expect(checkArguments([policy], { 'a/b': 1 })).toMatchObject({ path: '/a~1b' });
  });

  it('must satisfy every policy covering the action', () => {
    const narrower = { allow: ['/to'] };
    expect(checkArguments([policy, narrower], { subject: 'hi' })).toMatchObject({ ok: false, path: '/subject' });
  });

  it('refuses arguments it cannot see into', () => {
    expect(checkArguments([policy], [1])).toMatchObject({ ok: false, reasonCode: 'ARGUMENTS_UNCHECKABLE' });
    expect(checkArguments([policy], 'to')).toMatchObject({ ok: false, reasonCode: 'ARGUMENTS_UNCHECKABLE' });
    expect(checkArguments([policy], { to: new Date() })).toMatchObject({ ok: false, reasonCode: 'ARGUMENTS_UNCHECKABLE' });
    expect(checkArguments([policy], { to: Number.NaN })).toMatchObject({ ok: false, reasonCode: 'ARGUMENTS_UNCHECKABLE' });
    let deep: Record<string, unknown> = { v: 1 };
    for (let i = 0; i < 40; i++) deep = { meta: deep };
    expect(checkArguments([policy], deep)).toMatchObject({ ok: false, reasonCode: 'ARGUMENTS_UNCHECKABLE' });
  });

  it('refuses the call when the policy itself is malformed, rather than skipping it', () => {
    expect(checkArguments([{ allow: [] }], { to: 'x' })).toMatchObject({ ok: false, reasonCode: 'ARGUMENTS_UNCHECKABLE' });
  });

  it('treats an own __proto__ key as an ordinary key', () => {
    expect(checkArguments([policy], JSON.parse('{"__proto__":{"to":1}}'))).toMatchObject({ ok: false, path: '/__proto__/to' });
  });
});

describe('sanitizeArguments', () => {
  const args = { to: 'alice@example.com', card: { number: '4242', exp: '12/30' }, items: [{ sku: 'x', note: 'n1' }, { sku: 'y', note: 'n2' }] };

  it('returns the arguments unchanged when nothing is sensitive', () => {
    const r = sanitizeArguments([{ allow: ['/to'] }], args);
    expect(r).toEqual({ ok: true, value: args });
  });

  it('redacts and keyed-hashes without touching the input', () => {
    const r = sanitizeArguments([{ allow: ['/to', '/card', '/items'], sensitive: [{ path: '/card/number', mode: 'redact' }, { path: '/to', mode: 'hmac' }, { path: '/items/*/note', mode: 'redact' }] }], args, { hmac });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value).toEqual({
      to: HMAC_ARGUMENT_PREFIX + hmac('"alice@example.com"'),
      card: { number: REDACTED_ARGUMENT, exp: '12/30' },
      items: [{ sku: 'x', note: REDACTED_ARGUMENT }, { sku: 'y', note: REDACTED_ARGUMENT }],
    });
    expect(args.card.number).toBe('4242');
  });

  it('hashes an object over its canonical JSON, so key order does not change the hash', () => {
    const p = [{ allow: ['/o'], sensitive: [{ path: '/o', mode: 'hmac' as const }] }];
    const a = sanitizeArguments(p, { o: { b: 1, a: 2 } }, { hmac });
    const b = sanitizeArguments(p, { o: { a: 2, b: 1 } }, { hmac });
    expect(a).toEqual(b);
    expect(a).toEqual({ ok: true, value: { o: HMAC_ARGUMENT_PREFIX + hmac('{"a":2,"b":1}') } });
  });

  it('lets redact win over hmac on the same value, whichever policy lists it', () => {
    const r = sanitizeArguments([{ allow: ['/to'], sensitive: [{ path: '/to', mode: 'hmac' }] }, { allow: ['/to'], sensitive: [{ path: '/to', mode: 'redact' }] }], { to: 'x' }, { hmac });
    expect(r).toEqual({ ok: true, value: { to: REDACTED_ARGUMENT } });
  });

  it('refuses rather than send a value in the clear when no key is configured', () => {
    expect(sanitizeArguments([{ allow: ['/to'], sensitive: [{ path: '/to', mode: 'hmac' }] }], { to: 'x' })).toEqual({
      ok: false, reasonCode: 'SENSITIVE_ARGUMENT_UNPROTECTED', path: '/to', detail: expect.any(String),
    });
    expect(sanitizeArguments([{ allow: ['/to'], sensitive: [{ path: '/to', mode: 'hmac' }] }], { to: 'x' }, { hmac: () => 'NOT-HEX' })).toMatchObject({ ok: false, reasonCode: 'SENSITIVE_ARGUMENT_UNPROTECTED' });
  });

  it('skips a sensitive path the call does not carry', () => {
    expect(sanitizeArguments([{ allow: ['/to', '/cc'], sensitive: [{ path: '/cc', mode: 'hmac' }] }], { to: 'x' })).toEqual({ ok: true, value: { to: 'x' } });
    // An array's `length` (or a non-index like `01`) is not a member: it matches nothing and never throws.
    const items = { items: ['a', 'b'] };
    expect(sanitizeArguments([{ allow: ['/items'], sensitive: [{ path: '/items/length', mode: 'redact' }, { path: '/items/01', mode: 'redact' }] }], items)).toEqual({ ok: true, value: items });
    expect(sanitizeArguments([{ allow: ['/items'], sensitive: [{ path: '/items/1', mode: 'redact' }] }], items)).toEqual({ ok: true, value: { items: ['a', '[REDACTED]'] } });
  });
});

describe('argumentPoliciesFor', () => {
  it('collects every policy for the action, using the mandate target as the default', () => {
    const m: Mandate = {
      target: 'send-email',
      permission: [
        { target: 'send-email', arguments: { allow: ['/to'] } },
        { arguments: { allow: ['/to', '/subject'] } } as never,
        { target: 'send-email' },
        { target: 'other', arguments: { allow: ['/x'] } },
      ],
    };
    expect(argumentPoliciesFor(m, 'send-email')).toEqual([{ allow: ['/to'] }, { allow: ['/to', '/subject'] }]);
    expect(argumentPoliciesFor(m, 'nothing')).toEqual([]);
    expect(argumentPoliciesFor(null, 'send-email')).toEqual([]);
  });
});

describe('delegation narrowing of an argument policy', () => {
  const parent = { allow: ['/to', '/items/*'], sensitive: [{ path: '/to', mode: 'hmac' as const }] };

  it('accepts the same policy, a narrower allow list and a stronger mode', () => {
    expect(argumentPolicyNarrowing(parent, parent)).toBeNull();
    expect(argumentPolicyNarrowing(parent, { allow: ['/to', '/items/0/sku'], sensitive: [{ path: '/to', mode: 'redact' }] })).toBeNull();
    expect(argumentPolicyNarrowing(undefined, { allow: ['/to'] })).toBeNull();
    expect(argumentPolicyNarrowing(undefined, undefined)).toBeNull();
  });

  it('refuses dropping, widening or weakening it', () => {
    expect(argumentPolicyNarrowing(parent, undefined)).toEqual({ refusal: 'CONSTRAINT_DROPPED', detail: 'arguments' });
    expect(argumentPolicyNarrowing(parent, { allow: ['/to', '/bcc'], sensitive: parent.sensitive })).toMatchObject({ refusal: 'CONSTRAINT_WIDENED' });
    expect(argumentPolicyNarrowing({ allow: ['/items/0'] }, { allow: ['/items/*'] })).toMatchObject({ refusal: 'CONSTRAINT_WIDENED' });
    expect(argumentPolicyNarrowing(parent, { allow: ['/to'] })).toMatchObject({ refusal: 'CONSTRAINT_DROPPED', detail: 'arguments.sensitive /to' });
    expect(argumentPolicyNarrowing({ allow: ['/to'], sensitive: [{ path: '/to', mode: 'redact' }] }, { allow: ['/to'], sensitive: [{ path: '/to', mode: 'hmac' }] })).toMatchObject({ refusal: 'CONSTRAINT_DROPPED' });
    expect(argumentPolicyNarrowing(parent, { allow: [] })).toMatchObject({ refusal: 'UNCOMPARABLE' });
  });

  it('is applied by delegationVerdict', () => {
    const p: Mandate = { permission: [{ target: 'send-email', arguments: parent }] };
    expect(delegationVerdict(p, { permission: [{ target: 'send-email' }] }, 1)).toMatchObject({ ok: false, refusal: 'CONSTRAINT_DROPPED', detail: 'arguments' });
    expect(delegationVerdict(p, { permission: [{ target: 'send-email', arguments: parent }] }, 1)).toMatchObject({ ok: true });
  });

  it('binds the child to a policy on ANY of the parent permissions for the action, not just the one that covers it', () => {
    const p: Mandate = { permission: [{ target: 'send-email', arguments: parent }, { target: 'send-email' }] };
    expect(delegationVerdict(p, { permission: [{ target: 'send-email' }] }, 1)).toMatchObject({ ok: false, refusal: 'CONSTRAINT_DROPPED', detail: 'arguments' });
    expect(delegationVerdict(p, { permission: [{ target: 'send-email', arguments: parent }] }, 1)).toMatchObject({ ok: true });
  });
});

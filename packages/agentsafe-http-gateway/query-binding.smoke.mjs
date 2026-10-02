// query-binding.smoke.mjs — a governed route refuses a URL query the agent's signature does not cover (M-7, 0.17.1).
//
// The payload binding covers the BODY. Before 0.17.1 the query string rode through to the upstream verbatim: a body bound
// to a $250 skyward-air booking plus `?amount=4000&merchant=attacker-llc` was authorized, the hold claimed, and the query
// handed to an upstream that might read it. Now any query (or one smuggled into the path) is refused with
// 403 QUERY_NOT_BOUND before the guard is asked anything — so nothing is claimed — unless the route lists the exact keys
// it may forward (`allowedQuery`).
//
//   node query-binding.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import { createHttpGateway, queryRefusal } from './gateway.mjs';
import { matchRoute } from './route-match.mjs';

let guardCalls = 0, forwarded = null;
const guard = { verifyRequest: async () => { guardCalls++; return { decision: 'allow', reasonCode: 'AUTHORIZED' }; } };
const forward = async (req) => { forwarded = req; return { status: 200, body: { ran: true } }; };

const SIGNED = { agentDid: 'did:x', amount: 250, currency: 'USD', merchant: 'skyward-air', nonce: 'n', issuedAt: 'now', signature: 's' };
const BODY = { amount: 250, merchant: 'skyward-air' };
const ROUTE = { method: 'POST', path: '/book-flight', action: 'flight-purchase', valueFields: ['amount', 'merchant'], allowedFields: ['amount', 'currency', 'merchant'] };

const quiet = (fn) => { const w = console.warn; console.warn = () => {}; try { return fn(); } finally { console.warn = w; } };
const mk = (routeExtra = {}, opts = {}) => quiet(() => createHttpGateway({ guard, forward, routes: [{ ...ROUTE, ...routeExtra }], ...opts }));
const call = (gw, path, body = BODY) => {
  guardCalls = 0; forwarded = null;
  return gw({ method: 'POST', path, headers: { 'x-magp-request': JSON.stringify(SIGNED) }, rawBody: Buffer.from(JSON.stringify(body)) });
};
const refused = (r) => {
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.reasonCode, 'QUERY_NOT_BOUND');
  assert.equal(forwarded, null, 'the upstream must not be reached');
  assert.equal(guardCalls, 0, 'nothing may be claimed for a refused request');
};

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('the reproduced attack: bound $250 body + ?amount=4000&merchant=attacker-llc → refused before forwarding', async () => {
  refused(await call(mk(), '/book-flight?amount=4000&merchant=attacker-llc'));
});

test('no query → forwarded unchanged (path, body, one guard call)', async () => {
  const r = await call(mk(), '/book-flight');
  assert.equal(r.status, 200); assert.equal(forwarded.path, '/book-flight'); assert.equal(guardCalls, 1);
});

test('any query on a route without allowedQuery is refused — even an innocuous key, even an empty "?"', async () => {
  for (const p of ['/book-flight?page=2', '/book-flight?', '/book-flight/?x', '/book-flight?amount=250']) refused(await call(mk(), p));
});

test('an opted-in key is forwarded verbatim', async () => {
  const gw = mk({ allowedQuery: ['page', 'sort'] });
  for (const p of ['/book-flight?page=2', '/book-flight?page=2&sort=price', '/book-flight?', '/book-flight?page=a%20b']) {
    const r = await call(gw, p);
    assert.equal(r.status, 200, `${p} → ${JSON.stringify(r.body)}`); assert.equal(forwarded.path, p);
  }
});

test('with allowedQuery: an unlisted, renamed, encoded or differently-cased key is refused', async () => {
  const gw = mk({ allowedQuery: ['page'] });
  for (const p of ['/book-flight?page=2&amount=4000', '/book-flight?merchant=x', '/book-flight?Page=2', '/book-flight?p%61ge=2', '/book-flight?amount']) refused(await call(gw, p));
});

test('with allowedQuery: a repeated key, an empty segment, a ";" separator or an encoded separator in a value is refused', async () => {
  const gw = mk({ allowedQuery: ['page'] });
  for (const p of [
    '/book-flight?page=1&page=2',
    '/book-flight?page=1&&',
    '/book-flight?page=1;amount=4000',
    '/book-flight?page=1%26amount%3D4000',
    '/book-flight?page=1%2526amount%253D4000',
    '/book-flight?page=1%23x',
  ]) refused(await call(gw, p));
});

test('a query, path parameter or fragment smuggled into the path is refused (raw, encoded, double-encoded)', async () => {
  for (const gw of [mk(), mk({ allowedQuery: ['page'] })]) {
    for (const p of [
      '/book-flight%3Famount=4000',
      '/book-flight%3famount=4000',
      '/book-flight;amount=4000',
      '/book-flight%3Bamount=4000',
      '/book-flight#frag',
      '/book-flight%23frag',
      '/book-flight?page=1#frag',
    ]) refused(await call(gw, p));
  }
  // A wildcard route matches a double-encoded variant as a segment; it is still refused.
  const wild = mk({ path: '/book/*' });
  for (const p of ['/book/x%253Famount=4000', '/book/x%3Famount=4000', '/book/x;amount=4000', '/book/x%253Bamount=4000']) refused(await call(wild, p));
});

test('route matching: a ";"/encoded-"?"/"#" variant of a governed path MATCHES it (so it is governed, then refused)', () => {
  const routes = [ROUTE];
  for (const p of ['/book-flight;amount=4000', '/book-flight%3Famount=4000', '/book-flight%23x', '/book-flight?amount=1']) {
    assert.equal(matchRoute(routes, 'POST', p), ROUTE, p);
  }
  assert.equal(matchRoute(routes, 'POST', '/other;x'), null);
});

test('route matching: double/triple-encoded, dot-segment and backslash variants of an EXACT route match it too', async () => {
  const routes = [ROUTE];
  // Carrying a smuggled query / parameter / fragment: matched, then refused before the guard.
  for (const p of [
    '/book-flight%253Famount=4000', // decodes twice to /book-flight?amount=4000
    '/book-flight%25253Famount=4000', // three times
    '/book-flight%253Bx=1',
    '/book-flight%2523x',
  ]) {
    assert.equal(matchRoute(routes, 'POST', p), ROUTE, p);
    refused(await call(mk(), p));
  }
  // A traversal or backslash spelling of the governed path: matched, so it is GOVERNED (guard re-verifies it)
  // instead of falling through as unmatched and being forwarded ungoverned.
  for (const p of ['/x/../book-flight', '/x/%2e%2e/book-flight', '/./book-flight', '/../book-flight', '\\book-flight', '/x\\..\\book-flight']) {
    assert.equal(matchRoute(routes, 'POST', p), ROUTE, p);
    guardCalls = 0;
    await call(mk(), p);
    assert.equal(guardCalls, 1, `${p} was governed`);
  }
  // Legitimate paths are unaffected: a different path stays unmatched, a wildcard id is still one segment.
  assert.equal(matchRoute(routes, 'POST', '/book-flights'), null);
  assert.ok(matchRoute([{ ...ROUTE, path: '/orders/*' }], 'POST', '/orders/ord-123'));
  assert.equal(matchRoute([{ ...ROUTE, path: '/orders/*' }], 'POST', '/orders/a/b'), null);
});

test('unmatched routes behave as before: forwarded with their query (or ROUTE_NOT_ALLOWED under denyByDefault)', async () => {
  let r = await call(mk(), '/search?q=x&amount=4000');
  assert.equal(r.status, 200); assert.equal(forwarded.path, '/search?q=x&amount=4000'); assert.equal(guardCalls, 0);
  r = await call(mk({}, { denyByDefault: true }), '/search?q=x');
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'ROUTE_NOT_ALLOWED'); assert.equal(forwarded, null);
});

test('allowedQuery may not list a signed value field, an invalid key, or be a non-array — refused at construction', () => {
  for (const bad of [['amount'], ['merchant'], ['currency'], ['page', 'total'], ['a=b'], ['p%61ge'], [''], 'page', [1]]) {
    const extra = { allowedQuery: bad, ...(bad?.[1] === 'total' ? { valueFields: ['amount', 'merchant', 'total'] } : {}) };
    assert.throws(() => mk(extra), /allowedQuery/, JSON.stringify(bad));
  }
});

// Item 15 (2026-10-02 open items): two allowedQuery edge cases.
test('0.17.3: any casing of a signed value field is refused at construction (a case-insensitive upstream reads it)', () => {
  for (const bad of [['Amount'], ['MERCHANT'], ['Currency'], ['page', 'Total']]) {
    const extra = { allowedQuery: bad, ...(bad?.[1] === 'Total' ? { valueFields: ['amount', 'merchant', 'total'] } : {}) };
    assert.throws(() => mk(extra), /signed value field/, JSON.stringify(bad));
  }
});

test('0.17.3: an "=" in a value (a base64 cursor, a padded token) is forwarded; real separators are still refused', async () => {
  const gw = mk({ allowedQuery: ['cursor'] });
  for (const p of ['/book-flight?cursor=abc==', '/book-flight?cursor=abc%3D%3D', '/book-flight?cursor=a=b']) {
    const r = await call(gw, p);
    assert.equal(r.status, 200, p);
    assert.equal(forwarded.path, p);
  }
  for (const p of ['/book-flight?cursor=abc%26amount=4000', '/book-flight?cursor=abc%253Bx', '/book-flight?cursor=a%3Fb']) refused(await call(gw, p));
});

test('allowedQuery logs, at startup, that its keys are forwarded UNBOUND', () => {
  const lines = [];
  const w = console.warn; console.warn = (m) => lines.push(String(m));
  try { createHttpGateway({ guard, forward, routes: [{ ...ROUTE, allowedQuery: ['page'] }] }); } finally { console.warn = w; }
  assert.ok(lines.some((l) => l.includes('UNBOUND') && l.includes('page')), lines.join('\n'));
});

test('queryRefusal: null for a clean target, a reason otherwise', () => {
  assert.equal(queryRefusal('/book-flight', ROUTE), null);
  assert.equal(queryRefusal('/book-flight?page=1', { allowedQuery: ['page'] }), null);
  assert.match(queryRefusal('/book-flight?page=1', ROUTE), /allowedQuery/);
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`  ok   ${name}`); } catch (e) { failed++; console.log(`  FAIL ${name}\n       ${e.message}`); }
}
if (failed) { console.log(`\nFAIL — ${failed} of ${t.length} query-binding cases`); process.exit(1); }
console.log(`\nPASS — a governed route refuses a query its signature does not cover (${t.length} cases)`);

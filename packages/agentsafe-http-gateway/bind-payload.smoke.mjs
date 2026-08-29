// Unit tests for payload binding. Fake guard => no network, deterministic.
import assert from 'node:assert/strict';
import { createHttpGateway } from './gateway.mjs';

let guardCalls = 0, forwarded = null;
const guard = { verifyRequest: async () => { guardCalls++; return { decision: 'allow', reasonCode: 'AUTHORIZED' }; } };
const forward = async (req) => { forwarded = req; return { status: 200, body: { ran: true } }; };

const SIGNED = { agentDid: 'did:x', amount: 250, currency: 'USD', merchant: 'skyward-air', nonce: 'n', issuedAt: 'now', signature: 's' };
const mk = (opts = {}, routeExtra = {}) => createHttpGateway({
  guard, forward, denyByDefault: true,
  routes: [{ method: 'POST', path: '/book-flight', action: 'flight-purchase', ...routeExtra }],
  ...opts,
});
const call = (gw, body, signed = SIGNED, path = '/book-flight') => {
  guardCalls = 0; forwarded = null;
  return gw({ method: 'POST', path, headers: { 'x-magp-request': JSON.stringify(signed) },
              rawBody: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)) });
};

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('honest payload matching the signature is forwarded', async () => {
  const r = await call(mk(), { amount: 250, merchant: 'skyward-air', riskLevel: 'low' });
  assert.equal(r.status, 200); assert.ok(forwarded);
});
test('tampered amount is blocked, naming the field', async () => {
  const r = await call(mk(), { amount: 5000, merchant: 'skyward-air' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
  assert.equal(r.body.field, 'amount'); assert.equal(forwarded, null);
});
test('tampered merchant is blocked', async () => {
  const r = await call(mk(), { amount: 250, merchant: 'evil-corp' });
  assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(r.body.field, 'merchant');
});
test('tampered currency is blocked', async () => {
  const r = await call(mk(), { amount: 250, currency: 'BTC', merchant: 'skyward-air' });
  assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(r.body.field, 'currency');
});
test('payload introducing a value the signature never mentioned is blocked', async () => {
  const bare = { agentDid: 'did:x', nonce: 'n', issuedAt: 'now', signature: 's' }; // no amount/merchant
  const r = await call(mk(), { amount: 9999 }, bare);
  assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(r.body.field, 'amount');
});
test('binding runs BEFORE the guard - a tampered request burns no nonce', async () => {
  await call(mk(), { amount: 5000, merchant: 'skyward-air' });
  assert.equal(guardCalls, 0, 'guard.verifyRequest must not be reached');
});
test('numeric string in the body matches a numeric signed amount', async () => {
  const r = await call(mk(), { amount: '250', merchant: 'skyward-air' });
  assert.equal(r.status, 200);
});
test('empty body binds nothing and still governs', async () => {
  const r = await call(mk(), '');
  assert.equal(r.status, 200); assert.equal(guardCalls, 1);
});
test('non-JSON body binds nothing (documented limitation)', async () => {
  const r = await call(mk(), 'amount=5000&merchant=evil');
  assert.equal(r.status, 200);
});
test('an empty JSON object {} binds nothing - it carries no fields, hides none either', async () => {
  const r = await call(mk(), {});
  assert.equal(r.status, 200);
});
test('an empty JSON array [] binds nothing', async () => {
  const r = await call(mk(), []);
  assert.equal(r.status, 200);
});
test('nested value needs a route binder - and then it blocks', async () => {
  const gw = mk({}, { bind: (req) => { const b = JSON.parse(req.rawBody.toString('utf8')); return { amount: b.booking?.amount }; } });
  const r = await call(gw, { booking: { amount: 5000 } });
  assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
});
// The exploit as reported: sign $250/skyward-air, ship the REAL values one level deeper than
// the DEFAULT binder looks. Before the UNBINDABLE fix these all forwarded with status 200 —
// the flat top-level matcher found none of amount/currency/merchant, returned null, and the
// gateway treated "found nothing" as "nothing to check" instead of "cannot confirm the match".
test('DEFAULT binder: a nested payload is blocked, not silently forwarded', async () => {
  const r = await call(mk(), { booking: { amount: 5000, merchant: 'evil-corp' } });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE'); assert.equal(forwarded, null);
});
test('DEFAULT binder: a JSON array payload is blocked', async () => {
  const r = await call(mk(), [{ amount: 5000, merchant: 'evil-corp' }]);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('DEFAULT binder: capitalized field names are blocked (exact key match only)', async () => {
  const r = await call(mk(), { Amount: 5000, Merchant: 'evil-corp' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('DEFAULT binder: a differently-named field is blocked', async () => {
  const r = await call(mk(), { total: 5000, vendor: 'evil-corp' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('DEFAULT binder: UNBINDABLE is reached BEFORE the guard - burns no nonce either', async () => {
  await call(mk(), { booking: { amount: 5000 } });
  assert.equal(guardCalls, 0, 'guard.verifyRequest must not be reached');
});
test('bind:false restores legacy behaviour (opt-out works)', async () => {
  const r = await call(mk({ bind: false }), { amount: 5000, merchant: 'evil-corp' });
  assert.equal(r.status, 200, 'opt-out must forward the tampered body');
});
test('a throwing binder fails CLOSED', async () => {
  const gw = mk({}, { bind: () => { throw new Error('boom'); } });
  const r = await call(gw, { amount: 250 });
  assert.equal(r.status, 502); assert.equal(r.body.reasonCode, 'BIND_ERROR'); assert.equal(forwarded, null);
});
test('unmatched route under denyByDefault is unchanged', async () => {
  const r = await call(mk(), { amount: 250 }, SIGNED, '/other');
  assert.equal(r.body.reasonCode, 'ROUTE_NOT_ALLOWED');
});
test('missing governance header is unchanged', async () => {
  const r = await mk()({ method: 'POST', path: '/book-flight', headers: {}, rawBody: Buffer.from('{}') });
  assert.equal(r.status, 401); assert.equal(r.body.reasonCode, 'MISSING_GOVERNANCE');
});

let pass = 0, fail = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m ' + name); pass++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m ' + name + '\n       ' + e.message); fail++; }
}
console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

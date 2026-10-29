// access-context.smoke.mjs — route.access: an upstream answer reaches the agent only when every tenant and user field in
// it names the principal the request is served for. Fails closed on anything it cannot check; never echoes a value.
//
//   node access-context.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import { createHttpGateway } from './gateway.mjs';
import { assertAccessPolicy, checkAccessContext, parseAccessPointer, valuesAt } from './access-context.mjs';

const quiet = console.warn; console.warn = () => {};
let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`PASS  ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}

const ACCESS = { tenant: ['/items/*/tenantId'], user: ['/items/*/owner/email'], principal: { tenantId: 'acme', userId: 'alice@acme.example' } };
const row = (tenantId, email) => ({ id: 'r', tenantId, owner: { email } });
let upstreamBody;
let forwarded = 0;
let released = [];
const forward = async () => { forwarded++; return { status: 200, headers: { 'content-type': 'application/json' }, rawBody: new TextEncoder().encode(JSON.stringify(upstreamBody)) }; };
const guard = {
  verifyRequest: async () => ({ decision: 'allow', authorizationId: 'auth-1', claimToken: 't' }),
  releaseAuthorization: async (a) => { released.push(a.reason); return { ok: true }; },
  captureAuthorization: async () => ({ ok: true }),
};
const gatewayWith = (access, extra = {}) => createHttpGateway({
  guard, forward, settle: true, settleInBackground: false, reportOutcomes: false, denyByDefault: true,
  routes: [{ method: 'POST', path: '/records', action: 'read-records', bind: false, extract: () => ({ agentDid: 'did:x', action: 'read-records' }), access, ...extra }],
});
const call = (gw) => gw({ method: 'POST', path: '/records', headers: {}, rawBody: new TextEncoder().encode('{}') });

await check('records that all belong to the principal are released untouched', async () => {
  upstreamBody = { items: [row('acme', 'alice@acme.example'), row('acme', 'alice@acme.example')] };
  const res = await call(gatewayWith(ACCESS));
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(res.rawBody)), upstreamBody);
});

await check('one row from another tenant withholds the whole answer, naming the path and never the value', async () => {
  upstreamBody = { items: [row('acme', 'alice@acme.example'), row('globex', 'alice@acme.example')] };
  const res = await call(gatewayWith(ACCESS));
  assert.equal(res.status, 502);
  assert.deepEqual(res.body, { decision: 'block', reasonCode: 'ACCESS_CONTEXT_MISMATCH', path: '/items/1/tenantId', action: 'read-records', executed: true });
  assert.ok(!JSON.stringify(res.body).includes('globex'));
  assert.equal(res.rawBody, undefined);
});

await check('the right tenant but another user is withheld', async () => {
  upstreamBody = { items: [row('acme', 'bob@acme.example')] };
  assert.equal((await call(gatewayWith(ACCESS))).body.reasonCode, 'ACCESS_CONTEXT_MISMATCH');
});

await check('a row missing a named field, a non-scalar value, or a body that is not JSON is uncheckable', async () => {
  upstreamBody = { items: [{ id: 'r', owner: { email: 'alice@acme.example' } }] };
  assert.deepEqual([(await call(gatewayWith(ACCESS))).body.reasonCode, (await call(gatewayWith(ACCESS))).body.path], ['ACCESS_CONTEXT_UNCHECKABLE', '/items/0/tenantId']);
  upstreamBody = { items: [row({ id: 'acme' }, 'alice@acme.example')] };
  assert.equal((await call(gatewayWith(ACCESS))).body.reasonCode, 'ACCESS_CONTEXT_UNCHECKABLE');
  const notJson = createHttpGateway({ guard, settle: false, reportOutcomes: false, forward: async () => ({ status: 200, rawBody: new TextEncoder().encode('<html>') }),
    routes: [{ method: 'POST', path: '/records', action: 'read-records', bind: false, extract: () => ({ agentDid: 'did:x' }), access: ACCESS }] });
  assert.equal((await call(notJson)).body.reasonCode, 'ACCESS_CONTEXT_UNCHECKABLE');
  upstreamBody = { items: [] }; // no records: nothing to withhold
  assert.equal((await call(gatewayWith(ACCESS))).status, 200);
});

await check('the principal comes from the operator\'s resolver; a failing one forwards nothing and releases the hold', async () => {
  upstreamBody = { items: [row('t-7', 'u-9')] };
  const resolved = await call(gatewayWith({ ...ACCESS, principal: async (request) => (request.agentDid === 'did:x' ? { tenantId: 't-7', userId: 'u-9' } : null) }));
  assert.equal(resolved.status, 200);
  forwarded = 0; released = [];
  const res = await call(gatewayWith({ ...ACCESS, principal: async () => { throw new Error('directory down'); } }));
  assert.deepEqual(res.body, { decision: 'block', reasonCode: 'ACCESS_PRINCIPAL_UNAVAILABLE', action: 'read-records', executed: false });
  assert.equal(forwarded, 0);
  assert.deepEqual(released, ['ACCESS_PRINCIPAL_UNAVAILABLE']);
  assert.equal((await call(gatewayWith({ ...ACCESS, principal: async () => ({ tenantId: 'acme' }) }))).body.reasonCode, 'ACCESS_PRINCIPAL_UNAVAILABLE');
});

await check('a map keyed by tenant name: the refusal path keeps `*`, never the other tenant\'s name', async () => {
  upstreamBody = { byTenant: { acme: { id: 'acme' }, 'globex-corp': { id: 'globex-corp' } } };
  const res = await call(gatewayWith({ tenant: ['/byTenant/*/id'], principal: { tenantId: 'acme' } }));
  assert.equal(res.body.reasonCode, 'ACCESS_CONTEXT_MISMATCH');
  assert.equal(res.body.path, '/byTenant/*/id');
  assert.ok(!JSON.stringify(res.body).includes('globex'));
  upstreamBody = { byTenant: { 'globex-corp': {} } };
  const missing = await call(gatewayWith({ tenant: ['/byTenant/*/id'], principal: { tenantId: 'acme' } }));
  assert.deepEqual([missing.body.reasonCode, missing.body.path], ['ACCESS_CONTEXT_UNCHECKABLE', '/byTenant/*/id']);
});

await check('an answer with no status, or a status that is not a number, is still checked', async () => {
  for (const status of [undefined, '200 OK']) {
    const gw = createHttpGateway({ guard, settle: false, reportOutcomes: false, forward: async () => ({ status, body: { items: [row('globex', 'x')] } }),
      routes: [{ method: 'POST', path: '/records', action: 'read-records', bind: false, extract: () => ({ agentDid: 'did:x' }), access: ACCESS }] });
    assert.equal((await call(gw)).body.reasonCode, 'ACCESS_CONTEXT_MISMATCH', String(status));
  }
});

await check('an empty answer (a 204 from a write that already ran) is released, not refused', async () => {
  for (const answer of [{ status: 204 }, { status: 200, rawBody: new Uint8Array(0) }, { status: 200, body: '' }]) {
    const gw = createHttpGateway({ guard, settle: false, reportOutcomes: false, forward: async () => answer,
      routes: [{ method: 'POST', path: '/records', action: 'read-records', bind: false, extract: () => ({ agentDid: 'did:x' }), access: ACCESS }] });
    assert.equal((await call(gw)).status, answer.status);
  }
});

await check('duplicate keys, an own __proto__ key and a big-integer id are refused as uncheckable, with a detail', async () => {
  for (const text of ['{"items":[{"tenantId":"globex","tenantId":"acme","owner":{"email":"alice@acme.example"}}]}', '{"items":[{"tenantId":"acme","owner":{"email":"alice@acme.example"}}],"n":9007199254740993}']) {
    const gw = createHttpGateway({ guard, settle: false, reportOutcomes: false, forward: async () => ({ status: 200, rawBody: new TextEncoder().encode(text) }),
      routes: [{ method: 'POST', path: '/records', action: 'read-records', bind: false, extract: () => ({ agentDid: 'did:x' }), access: ACCESS }] });
    const res = await call(gw);
    assert.equal(res.body.reasonCode, 'ACCESS_CONTEXT_UNCHECKABLE', text);
    assert.equal(res.body.detail, 'the answer is not strict JSON');
  }
  // An own __proto__ key is a field like any other: the wildcard sees it, and its record is checked.
  const proto = JSON.parse('{"items":{"__proto__":{"tenantId":"globex","owner":{"email":"alice@acme.example"}}}}');
  assert.equal(checkAccessContext(proto, { tenant: ['/items/*/tenantId'] }, { tenantId: 'acme' }).reasonCode, 'ACCESS_CONTEXT_MISMATCH');
});

await check('the withheld answer still settles as executed, and the decision header says block', async () => {
  const captured = [];
  released = [];
  const gw = createHttpGateway({ guard: { ...guard, captureAuthorization: async (a) => { captured.push(a.authorizationId); return { ok: true }; } }, forward, settle: true, settleInBackground: false, reportOutcomes: false,
    routes: [{ method: 'POST', path: '/records', action: 'read-records', bind: false, extract: () => ({ agentDid: 'did:x' }), access: ACCESS }] });
  upstreamBody = { items: [row('globex', 'alice@acme.example')] };
  const res = await call(gw);
  assert.deepEqual(captured, ['auth-1']);
  assert.deepEqual(released, []);
  assert.equal(res.governance.decision, 'block');
  assert.equal(res.governance.reasonCode, 'ACCESS_CONTEXT_MISMATCH');
});

await check('more fields than the cap is uncheckable, said so, with the configured pointer as the path', () => {
  const many = { items: Array.from({ length: 100_001 }, () => ({ tenantId: 'acme' })) };
  assert.deepEqual(checkAccessContext(many, { tenant: ['/items/*/tenantId'] }, { tenantId: 'acme' }), { reasonCode: 'ACCESS_CONTEXT_UNCHECKABLE', path: '/items/*/tenantId', kind: 'tenant', detail: 'more than 100000 fields to check' });
});

await check('a non-2xx answer is an error, not records, and passes', async () => {
  const gw = createHttpGateway({ guard, settle: false, reportOutcomes: false, forward: async () => ({ status: 404, body: { error: 'not found' } }),
    routes: [{ method: 'POST', path: '/records', action: 'read-records', bind: false, extract: () => ({ agentDid: 'did:x' }), access: ACCESS }] });
  assert.equal((await call(gw)).status, 404);
});

await check('ids compare as NFC text: 42 matches "42", a decomposed é matches a composed one', async () => {
  assert.equal(checkAccessContext({ t: 42, u: 'café' }, { tenant: ['/t'], user: ['/u'] }, { tenantId: '42', userId: 'café' }), null);
  assert.equal(checkAccessContext({ t: 'ACME' }, { tenant: ['/t'] }, { tenantId: 'acme' }).reasonCode, 'ACCESS_CONTEXT_MISMATCH');
});

await check('pointers: escapes, wildcards over objects, array indices, the root refused', () => {
  assert.deepEqual(parseAccessPointer('/a~1b/~0c/*'), ['a/b', '~c', '*']);
  assert.equal(parseAccessPointer(''), null);
  assert.equal(parseAccessPointer('/bad~2'), null);
  // Object keys matched by `*` are never put in a path (they may be another tenant's name); the values are all visited.
  assert.deepEqual(valuesAt({ byId: { x: { t: 'a' }, y: { t: 'b' } } }, ['byId', '*', 't']).values.map((v) => [v.path, v.value]), [['/byId/*/t', 'a'], ['/byId/*/t', 'b']]);
  assert.deepEqual(valuesAt({ rows: [{ t: 1 }] }, ['rows', '0', 't']).values[0].value, 1);
  assert.equal(valuesAt({ rows: [] }, ['rows', '0', 't']).missing, '/rows/0');
  assert.equal(valuesAt({ a: 'x' }, ['a', 'b']).missing, '/a');
});

await check('a misconfigured route fails startup', () => {
  const r = (access) => ({ method: 'POST', path: '/x', access });
  for (const bad of [null, [], { tenant: ['/t'] }, { tenant: [], principal: {} }, { tenant: ['t'], principal: {} }, { principal: {} }, { tenant: ['/t'], principal: 'acme' }, { tenant: ['/t'], principal: { tenantId: 'a' }, tenantField: 'x' }, { tenant: ['/t'], principal: {} }, { user: ['/u'], principal: { tenantId: 'a' } }]) {
    assert.throws(() => assertAccessPolicy(r(bad)), undefined, JSON.stringify(bad));
  }
  assert.doesNotThrow(() => assertAccessPolicy(r({ user: ['/u'], principal: () => ({ userId: 'u' }) })));
  assert.throws(() => gatewayWith({ tenant: ['/t'] }));
});

console.warn = quiet;
console.log(failed === 0 ? '\nPASS' : `\nFAIL (${failed})`);
process.exit(failed === 0 ? 0 : 1);

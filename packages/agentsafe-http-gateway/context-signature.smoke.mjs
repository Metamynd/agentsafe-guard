// context-signature.smoke.mjs — the HTTP gateway refuses a governed request whose itinerary was altered after the agent
// signed it (context-claim binding), through the REAL agentsafe-mcp-guard, with a request built by the REAL agentsafe-guard
// (`signContext: true`) and carried in the `x-magp-request` header. Before mcp-guard 0.17.0 the altered request was
// judged on the rewritten context and FORWARDED upstream.
//
//   node context-signature.smoke.mjs
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createHttpGateway } from './gateway.mjs';
import { createMcpGuard } from '../agentsafe-mcp-guard/agentsafe-mcp-guard.mjs';
import { buildHederaDid } from '../agentsafe-mcp-guard/magp-did.mjs';
import { createGuard } from '../agentsafe-guard/agentsafe-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { did: buildHederaDid('testnet', spki.subarray(spki.length - 32), topic), keyHex: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex') };
}
const agent = mint('0.0.100');
const service = mint('0.0.200');
// agentsafe-guard >= 0.17.0 signs the context by default (signing); plain opts out.
const plain = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: agent.did, agentKey: agent.keyHex, signContext: false });
const signing = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: agent.did, agentKey: agent.keyHex });

const mol = (id, predicate, config, decision, reasonCode) => ({ id, combinator: 'any', atoms: [{ id: 'a', predicate, config }], decision, reasonCode });
const bundle = {
  subject: agent.did,
  standards: [],
  sops: [{ id: 't', document: { molecules: [mol('t', 'tool-not-allowed', { allowed: ['lookup'] }, 'block', 'TOOL_BLOCKED')] } }],
  mandates: [{ action: 'report', document: { permission: [{ target: 'report', constraint: [] }] } }],
};
const guard = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => bundle });
let forwarded = 0;
const forward = async () => { forwarded++; return { status: 200, body: { ok: true } }; };
const route = { method: 'POST', path: '/report', action: 'report', valueFields: [], allowedFields: [] };
const strictRoute = { ...route, path: '/strict-report', requireContextSignature: true };
const gw = createHttpGateway({ guard, forward, settle: false, routes: [route, strictRoute] });
const gwStrict = createHttpGateway({ guard, forward, settle: false, routes: [route, { ...strictRoute, requireContextSignature: false }], requireContextSignature: true });

const call = (g, path, signed) => g({ method: 'POST', path, headers: { 'x-magp-request': JSON.stringify(signed) }, body: {} });
const sign = (g, itinerary) => g.buildSignedRequest({ action: 'report', amount: 0, context: itinerary });

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`PASS  ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}

await check('a valid context signature → forwarded', async () => {
  forwarded = 0;
  const res = await call(gw, '/report', await sign(signing, { tool: 'lookup' }));
  assert.equal(res.status, 200);
  assert.equal(forwarded, 1);
});
await check('a valid context signature over a blocked tool → the rule still judges it (403 TOOL_BLOCKED)', async () => {
  forwarded = 0;
  const res = await call(gw, '/report', await sign(signing, { tool: 'wire-funds' }));
  assert.equal(res.body.reasonCode, 'TOOL_BLOCKED');
  assert.equal(forwarded, 0);
});
await check('the itinerary altered between agent and gateway → 403 CONTEXT_SIGNATURE_INVALID, never forwarded (was 200)', async () => {
  forwarded = 0;
  const signed = await sign(signing, { tool: 'wire-funds' });
  const res = await call(gw, '/report', { ...signed, itinerary: { tool: 'lookup' } });
  assert.equal(res.status, 403);
  assert.equal(res.body.reasonCode, 'CONTEXT_SIGNATURE_INVALID');
  assert.equal(forwarded, 0);
});
await check('no context signature → judged as before (optional)', async () => {
  forwarded = 0;
  const res = await call(gw, '/report', await sign(plain, { tool: 'lookup' }));
  assert.equal(res.status, 200);
  assert.equal(forwarded, 1);
});
await check('route.requireContextSignature: no context signature → 403 CONTEXT_SIGNATURE_REQUIRED', async () => {
  forwarded = 0;
  const res = await call(gw, '/strict-report', await sign(plain, { tool: 'lookup' }));
  assert.equal(res.status, 403);
  assert.equal(res.body.reasonCode, 'CONTEXT_SIGNATURE_REQUIRED');
  assert.equal(forwarded, 0);
});
await check('route.requireContextSignature: a signed context → forwarded', async () => {
  forwarded = 0;
  const res = await call(gw, '/strict-report', await sign(signing, { tool: 'lookup' }));
  assert.equal(res.status, 200);
  assert.equal(forwarded, 1);
});
await check('gateway-wide requireContextSignature: no context signature → 403 CONTEXT_SIGNATURE_REQUIRED', async () => {
  const res = await call(gwStrict, '/report', await sign(plain, { tool: 'lookup' }));
  assert.equal(res.body.reasonCode, 'CONTEXT_SIGNATURE_REQUIRED');
});
await check('a route that sets requireContextSignature: false overrides the gateway-wide setting', async () => {
  const res = await call(gwStrict, '/strict-report', await sign(plain, { tool: 'lookup' }));
  assert.equal(res.status, 200);
});

if (failed) {
  console.error(`\n${failed} check(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — the gateway refuses a context altered after the agent signed it.');

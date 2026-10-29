// argument-policy.smoke.mjs — the owner's per-tool argument policy (a mandate's `arguments`), enforced on the JSON body this
// gateway forwards. The route's own `allowedFields` is the operator's; the policy is the owner's and travels in the signed
// bundle, so a route that admits a field the owner did not is still refused. A sensitive value reaches the upstream
// rewritten, in the form the body arrived in.
//
//   node argument-policy.smoke.mjs   → PASS when every case matches.
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
const agent = mint('0.0.120');
const service = mint('0.0.220');
const KEY = 'g'.repeat(32);

const bundle = {
  subject: agent.did, standards: [], sops: [],
  mandates: [
    { action: 'send-email', document: { permission: [{ target: 'send-email', constraint: [], arguments: { allow: ['/to', '/subject', '/body'], sensitive: [{ path: '/body', mode: 'redact' }, { path: '/to', mode: 'hmac' }] } }] } },
    { action: 'read-report', document: { permission: [{ target: 'read-report', constraint: [], arguments: { allow: ['/id'] } }] } },
  ],
};
// The operator's route admits `bcc`; the owner's policy does not.
const routes = [
  { method: 'POST', path: '/send', action: 'send-email', valueFields: [], allowedFields: ['to', 'subject', 'body', 'bcc'] },
  { method: 'POST', path: '/report', action: 'read-report', valueFields: [], allowedFields: ['id'] },
];
let upstream = [];
const forward = async (req) => { upstream.push(req); return { status: 200, body: { done: true } }; };
const quiet = console.warn; console.warn = () => {};
const gatewayWith = (guardOpts = {}) => createHttpGateway({ guard: createMcpGuard({ serviceDid: service.did, fetchBundle: async () => bundle, allowedAgents: 'any', ...guardOpts }), forward, settle: false, routes, denyByDefault: true });
const signed = async (action) => JSON.stringify(await createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: agent.did, agentKey: agent.keyHex }).buildSignedRequest({ action, amount: 0, context: { riskLevel: 'low' } }));
const call = async (gw, path, action, body, headers = {}) => gw({ method: 'POST', path, headers: { 'x-magp-request': await signed(action), 'content-length': String(Buffer.byteLength(body)), ...headers }, rawBody: Buffer.from(body) });

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`PASS  ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}

await check('a body inside the policy is forwarded with its sensitive values rewritten', async () => {
  upstream = [];
  const res = await call(gatewayWith({ argumentKey: KEY }), '/send', 'send-email', JSON.stringify({ to: 'alice@example.com', subject: 'hi', body: 'secret' }));
  assert.equal(res.status, 200);
  assert.equal(upstream.length, 1);
  const sent = JSON.parse(Buffer.from(upstream[0].rawBody).toString('utf8'));
  assert.equal(sent.body, '[REDACTED]');
  assert.equal(sent.to, 'hmac-sha256:' + crypto.createHmac('sha256', KEY).update('"alice@example.com"').digest('hex'));
  assert.equal(sent.subject, 'hi');
  assert.ok(upstream[0].rawBody instanceof Uint8Array, 'the body is forwarded as bytes, as it arrived');
  assert.equal(Object.keys(upstream[0].headers).some((h) => h.toLowerCase() === 'content-length'), false, 'the stale Content-Length is dropped');
});

await check('a field the route admits but the owner does not → 403 ARGUMENT_NOT_ALLOWED, never forwarded', async () => {
  upstream = [];
  const res = await call(gatewayWith({ argumentKey: KEY }), '/send', 'send-email', JSON.stringify({ to: 'a@b.c', bcc: 'x@evil.example' }));
  assert.equal(res.status, 403);
  assert.equal(res.body.reasonCode, 'ARGUMENT_NOT_ALLOWED');
  assert.equal(res.body.path, '/bcc');
  assert.equal(upstream.length, 0);
});

await check('no argumentKey for a value the owner wants hashed → 403 SENSITIVE_ARGUMENT_UNPROTECTED, never forwarded', async () => {
  upstream = [];
  const res = await call(gatewayWith(), '/send', 'send-email', JSON.stringify({ to: 'a@b.c' }));
  assert.equal(res.body.reasonCode, 'SENSITIVE_ARGUMENT_UNPROTECTED');
  assert.equal(upstream.length, 0);
});

await check('a policy with nothing to rewrite forwards the original bytes untouched', async () => {
  upstream = [];
  const raw = '{ "id" : "r-1" }';
  const res = await call(gatewayWith(), '/report', 'read-report', raw);
  assert.equal(res.status, 200);
  assert.equal(Buffer.from(upstream[0].rawBody).toString('utf8'), raw);
  assert.ok(Object.keys(upstream[0].headers).some((h) => h.toLowerCase() === 'content-length'));
});

await check('a body that does not parse, under a policy → 403 ARGUMENTS_UNCHECKABLE', async () => {
  upstream = [];
  const res = await call(gatewayWith(), '/report', 'read-report', '{"id": 1, "id": 2}');
  assert.equal(res.body.reasonCode, 'ARGUMENTS_UNCHECKABLE');
  assert.equal(upstream.length, 0);
});

await check('a query string under a policy → 403 ARGUMENTS_UNCHECKABLE, even on a route that admits it', async () => {
  upstream = [];
  const gw = createHttpGateway({ guard: createMcpGuard({ serviceDid: service.did, fetchBundle: async () => bundle, allowedAgents: 'any' }), forward, settle: false, denyByDefault: true,
    routes: [{ ...routes[1], allowedQuery: ['bcc'] }] });
  const res = await gw({ method: 'POST', path: '/report?bcc=x', headers: { 'x-magp-request': await signed('read-report') }, rawBody: Buffer.from('{"id":"r-1"}') });
  assert.equal(res.body.reasonCode, 'ARGUMENTS_UNCHECKABLE');
  assert.equal(upstream.length, 0);
});

await check('a request carrying both body fields has both rewritten', async () => {
  upstream = [];
  const body = { to: 'a@b.c', body: 'secret' };
  const res = await gatewayWith({ argumentKey: KEY })({ method: 'POST', path: '/send', headers: { 'x-magp-request': await signed('send-email') }, rawBody: Buffer.from(JSON.stringify(body)), body });
  assert.equal(res.status, 200);
  assert.equal(upstream[0].body.body, '[REDACTED]');
  assert.equal(JSON.parse(Buffer.from(upstream[0].rawBody).toString('utf8')).body, '[REDACTED]');
});

await check('a guard that predates argument policies is named at startup', async () => {
  const warnings = [];
  console.warn = (m) => warnings.push(String(m));
  // An agentsafe-mcp-guard before 0.32.0: it has guardIncomingTool, but not checksArguments.
  createHttpGateway({ guard: { verifyRequest: async () => ({ decision: 'allow' }), guardIncomingTool: () => {} }, forward, settle: false, routes });
  assert.ok(warnings.some((w) => /does not check arguments/.test(w)));
  // A custom guard is the integrator's own: not named.
  warnings.length = 0;
  createHttpGateway({ guard: { verifyRequest: async () => ({ decision: 'allow' }) }, forward, settle: false, routes });
  console.warn = () => {};
  assert.ok(!warnings.some((w) => /does not check arguments/.test(w)));
});

console.warn = quiet;
console.log(failed === 0 ? '\nPASS' : `\nFAIL (${failed})`);
process.exit(failed === 0 ? 0 : 1);

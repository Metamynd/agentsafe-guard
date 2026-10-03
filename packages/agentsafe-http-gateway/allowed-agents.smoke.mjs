// allowed-agents.smoke.mjs — defect XT-1 of the 2026-10-03 pre-beta evaluation, end to end through the gateway shape every
// scaffolded agent ships: another tenant's agent, whose OWN owner granted it the same action, sent a validly signed request
// to an agent's own gateway and the tool ran (HTTP 200). With the REAL agentsafe-mcp-guard pinned to the agent it serves
// (`allowedAgents`, MAGP §16.3), the gateway answers 403 AGENT_NOT_SERVED and never forwards — requests built by the REAL
// agentsafe-guard and carried in the `x-magp-request` header, as the scaffold's agent sends them.
//
//   node allowed-agents.smoke.mjs
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
const mine = mint('0.0.100');
const theirs = mint('0.0.101'); // another tenant's agent
const service = mint('0.0.200');
const agentGuard = (a) => createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: a.did, agentKey: a.keyHex });

// Each agent's bundle grants it the same action — the attacker's owner wrote the attacker's.
const bundleFor = async (did) => ({ subject: did, standards: [], sops: [], mandates: [{ action: 'records-update', document: { permission: [{ target: 'records-update', constraint: [] }] } }] });
const route = { method: 'POST', path: '/perform', action: 'records-update', valueFields: [], allowedFields: [] };
let forwarded = 0;
const forward = async () => { forwarded++; return { status: 200, body: { done: true } }; };
const gatewayFor = (allowedAgents) => createHttpGateway({ guard: createMcpGuard({ serviceDid: service.did, fetchBundle: bundleFor, allowedAgents }), forward, settle: false, routes: [route], denyByDefault: true });
const call = async (gw, a) => gw({ method: 'POST', path: '/perform', headers: { 'x-magp-request': JSON.stringify(await agentGuard(a).buildSignedRequest({ action: 'records-update', amount: 0, context: { riskLevel: 'low' } })) }, rawBody: Buffer.from('{}') });

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`PASS  ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}
const quiet = console.warn; console.warn = () => {};

await check('pinned gateway: its own agent → forwarded', async () => {
  forwarded = 0;
  const res = await call(gatewayFor([mine.did]), mine);
  assert.equal(res.status, 200);
  assert.equal(forwarded, 1);
});
await check('pinned gateway: another tenant\'s agent granted the same action → 403 AGENT_NOT_SERVED, never forwarded (was 200)', async () => {
  forwarded = 0;
  const res = await call(gatewayFor([mine.did]), theirs);
  assert.equal(res.status, 403);
  assert.equal(res.body.reasonCode, 'AGENT_NOT_SERVED');
  assert.equal(forwarded, 0);
});
await check('unpinned gateway (as before): the other agent is still forwarded — the gap the pin closes', async () => {
  forwarded = 0;
  const res = await call(gatewayFor(undefined), theirs);
  assert.equal(res.status, 200);
  assert.equal(forwarded, 1);
});

console.warn = quiet;
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log('\nPASS — allowedAgents through the gateway.');

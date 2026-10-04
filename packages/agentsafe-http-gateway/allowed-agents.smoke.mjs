// allowed-agents.smoke.mjs — gateway authority end to end through the gateway shape every scaffolded agent ships (XT-1 of the
// 2026-10-03 pre-beta rerun, refined by the 2026-10-04 Gateway Authority Refinement Plan; MAGP §16.3): another tenant's
// agent, whose OWN owner granted it the same action, sent a validly signed request to an agent's own gateway and the tool
// ran (HTTP 200). With the REAL agentsafe-mcp-guard admitting only its own agents and bound to their owner, the gateway
// answers 403 AGENT_NOT_ADMITTED and never forwards; a route can admit fewer agents than the gateway (a credential
// profile). Requests are built by the REAL agentsafe-guard and carried in `x-magp-request`, as the scaffold's agent sends them.
//
//   node allowed-agents.smoke.mjs
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createHttpGateway } from './gateway.mjs';
import { createMcpGuard } from '../agentsafe-mcp-guard/agentsafe-mcp-guard.mjs';
import { buildHederaDid } from '../agentsafe-mcp-guard/magp-did.mjs';
import { createGuard } from '../agentsafe-guard/agentsafe-guard.mjs';

const OWNER_A = 'did:hedera:testnet:zOwnerA_0.0.900';
const OWNER_B = 'did:hedera:testnet:zOwnerB_0.0.901';
function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { did: buildHederaDid('testnet', spki.subarray(spki.length - 32), topic), keyHex: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex') };
}
const mine = mint('0.0.100');
const mine2 = mint('0.0.102');
const theirs = mint('0.0.101'); // another tenant's agent
const service = mint('0.0.200');
const ownerOf = new Map([[mine.did, OWNER_A], [mine2.did, OWNER_A], [theirs.did, OWNER_B]]);
const agentGuard = (a) => createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: a.did, agentKey: a.keyHex });

// Each agent's bundle grants it the same action — the attacker's owner wrote the attacker's.
const bundleFor = async (did) => ({ subject: did, ownerPrincipal: ownerOf.get(did), standards: [], sops: [], mandates: [{ action: 'records-update', document: { permission: [{ target: 'records-update', constraint: [] }] } }] });
const route = { method: 'POST', path: '/perform', action: 'records-update', valueFields: [], allowedFields: [] };
let forwarded = 0;
const forward = async () => { forwarded++; return { status: 200, body: { done: true } }; };
const guardFor = (allowedAgents) => createMcpGuard({ serviceDid: service.did, fetchBundle: bundleFor, allowedAgents, ...(allowedAgents === 'any' ? {} : { gatewayOwnerPrincipal: OWNER_A }) });
const gatewayFor = (allowedAgents, routes = [route]) => createHttpGateway({ guard: guardFor(allowedAgents), forward, settle: false, routes, denyByDefault: true });
const call = async (gw, a, path = '/perform') => gw({ method: 'POST', path, headers: { 'x-magp-request': JSON.stringify(await agentGuard(a).buildSignedRequest({ action: 'records-update', amount: 0, context: { riskLevel: 'low' } })) }, rawBody: Buffer.from('{}') });

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`PASS  ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}
const quiet = console.warn; console.warn = () => {};

await check('its own agent → forwarded', async () => {
  forwarded = 0;
  const res = await call(gatewayFor([mine.did]), mine);
  assert.equal(res.status, 200);
  assert.equal(forwarded, 1);
});
await check('another tenant\'s agent granted the same action → 403 AGENT_NOT_ADMITTED, never forwarded (was 200)', async () => {
  forwarded = 0;
  const res = await call(gatewayFor([mine.did]), theirs);
  assert.equal(res.status, 403);
  assert.equal(res.body.reasonCode, 'AGENT_NOT_ADMITTED');
  assert.equal(forwarded, 0);
});
await check('even when listed, an agent another principal owns → 403 GATEWAY_OWNER_MISMATCH', async () => {
  forwarded = 0;
  const res = await call(gatewayFor([mine.did, theirs.did]), theirs);
  assert.equal(res.body.reasonCode, 'GATEWAY_OWNER_MISMATCH');
  assert.equal(forwarded, 0);
});
await check('a route admitting fewer agents (credential profile) → 403 CREDENTIAL_PROFILE_NOT_PERMITTED for the others', async () => {
  forwarded = 0;
  const narrow = { ...route, path: '/payroll', allowedAgents: [mine2.did] };
  const gw = gatewayFor([mine.did, mine2.did], [route, narrow]);
  assert.equal((await call(gw, mine, '/payroll')).body.reasonCode, 'CREDENTIAL_PROFILE_NOT_PERMITTED');
  assert.equal((await call(gw, mine2, '/payroll')).status, 200);
  assert.equal((await call(gw, mine, '/perform')).status, 200);
  assert.equal(forwarded, 2);
});
await check("'any' (explicit) forwards every governed agent — the posture the default used to be", async () => {
  forwarded = 0;
  assert.equal((await call(gatewayFor('any'), theirs)).status, 200);
  assert.equal(forwarded, 1);
});
await check('a malformed route list, or one the guard cannot enforce, fails startup', async () => {
  assert.throws(() => gatewayFor([mine.did], [{ ...route, allowedAgents: [] }]), /non-empty/);
  const oldGuard = { verifyRequest: async () => ({ decision: 'allow' }) }; // predates gatewayOwnerPrincipal
  assert.throws(() => createHttpGateway({ guard: oldGuard, forward, routes: [{ ...route, allowedAgents: [mine.did] }] }), /cannot enforce/);
});

console.warn = quiet;
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log('\nPASS — gateway authority through the gateway.');

// lifecycle-freshness.smoke.mjs — a suspension or a reinstatement reaches a running agent within seconds (0.30.0; pre-beta
// rerun 5, N-1).
//
// Before: the local-first guard decided against a bundle cached for its maxStaleness (10 minutes). A process that loaded
// it while the agent was ACTIVE kept permitting value-less calls after the owner suspended the agent (only a gateway
// stopped them), and one that loaded it while SUSPENDED kept refusing for minutes after the owner reinstated it. Now a
// local permit or containment refusal is only given on a bundle younger than lifecycleMaxAgeMs; an older one is fetched
// again first, and a failed fetch hands the decision to the gate.
//
//   node lifecycle-freshness.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';

const { privateKey } = crypto.generateKeyPairSync('ed25519');
const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const agentDid = 'did:hedera:testnet:z6MkFresh_0.0.1';

// The issuer, faked: a bundle granting `perform-action` (value-less), with the agent's live containment as a sibling.
const state = { contained: null, bundleFetches: 0, authorizes: 0, bundleDown: false };
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  const reply = (data, code = 200) => ({ ok: code < 400, status: code, json: async () => data });
  if (u.includes('/policy/bundle/')) {
    state.bundleFetches++;
    if (state.bundleDown) throw new TypeError('fetch failed');
    return reply({
      success: true,
      data: { maxStaleness: 'PT10M', standards: [], sops: [], mandates: [{ action: 'perform-action', document: { uid: 'm', permission: [{ target: 'perform-action', constraint: [] }] } }] },
      contained: state.contained,
    });
  }
  if (u.endsWith('/policy/mandate/authorize')) {
    state.authorizes++;
    return reply({ success: true, data: { decision: state.contained ? 'suspend' : 'allow', reasonCode: state.contained ? 'AGENT_SUSPENDED' : 'AUTHORIZED', authorizationId: null } });
  }
  if (u.endsWith('/policy/decisions/local')) return reply({ success: true, data: {} });
  return reply({}, 404);
};

const mk = (opts = {}) => createGuard({ api: 'http://issuer.test/api/v1', agentDid, agentKey, ...opts });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`ok    ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.stack ?? e.message}`); }
}
const reset = (contained = null) => Object.assign(state, { contained, bundleFetches: 0, authorizes: 0, bundleDown: false });
// guardTool runs the same local-first decision every tool call makes.
async function decide(g) {
  let decision;
  const tool = g.guardTool('perform-action', async (_a, d) => { decision = d; return 'ran'; }, () => ({ context: { riskLevel: 'low' } }));
  try { await tool({}); return decision; } catch (e) { return e.governance; }
}

await check('the reproduced defect: an agent suspended after its process loaded the rules is refused within the freshness window', async () => {
  reset(null);
  const g = mk({ lifecycleMaxAgeMs: 50 });
  assert.equal((await decide(g)).decision, 'allow');
  state.contained = { status: 'suspended' }; // the owner suspends the agent
  await sleep(80);
  const d = await decide(g);
  assert.equal(d.decision, 'suspend');
  assert.equal(d.reasonCode, 'AGENT_SUSPENDED');
});

await check('...and a reinstatement reaches a process that loaded the rules while suspended', async () => {
  reset({ status: 'suspended' });
  const g = mk({ lifecycleMaxAgeMs: 50 });
  assert.equal((await decide(g)).reasonCode, 'AGENT_SUSPENDED');
  state.contained = null; // the owner reinstates it
  await sleep(80);
  assert.equal((await decide(g)).decision, 'allow');
});

await check('within the window a permit is decided on the cached bundle, with no extra fetch', async () => {
  reset(null);
  const g = mk({ lifecycleMaxAgeMs: 60_000 });
  await decide(g);
  await decide(g);
  await decide(g);
  assert.equal(state.bundleFetches, 1);
});

await check('a rule BLOCK on an old bundle is still decided locally, with no network (it can only refuse more)', async () => {
  reset(null);
  const g = mk({ lifecycleMaxAgeMs: 10 });
  await decide(g);
  await sleep(30);
  const before = state.bundleFetches;
  let d;
  const tool = g.guardTool('not-granted', async () => 'ran', () => ({ context: { riskLevel: 'low' } }));
  try { await tool({}); } catch (e) { d = e.governance; }
  assert.equal(d.reasonCode, 'NO_PERMISSION_FOR_ACTION');
  assert.equal(state.bundleFetches, before);
});

await check('when the bundle cannot be fetched again, the gate decides — never the stale permit', async () => {
  reset(null);
  const g = mk({ lifecycleMaxAgeMs: 10 });
  await decide(g);
  state.contained = { status: 'suspended' };
  state.bundleDown = true;
  await sleep(30);
  const d = await decide(g);
  assert.equal(state.authorizes, 1, 'asked the gate');
  assert.equal(d.decision, 'suspend');
});

await check('a reinstatement also reaches a call for an action the agent was never granted (refused for that, not "suspended")', async () => {
  reset({ status: 'suspended' });
  const g = mk({ lifecycleMaxAgeMs: 50 });
  const refusalOf = async () => { try { await g.guardTool('not-granted', async () => 'ran', () => ({})) ({}); return null; } catch (e) { return e.governance.reasonCode; } };
  assert.equal(await refusalOf(), 'AGENT_SUSPENDED');
  state.contained = null;
  await sleep(80);
  assert.equal(await refusalOf(), 'NO_PERMISSION_FOR_ACTION');
});

await check('calls that find the bundle too old at once share one re-fetch', async () => {
  reset(null);
  const g = mk({ lifecycleMaxAgeMs: 20 });
  await decide(g);
  await sleep(40);
  const before = state.bundleFetches;
  await Promise.all(Array.from({ length: 10 }, () => decide(g)));
  assert.equal(state.bundleFetches - before, 1);
});

await check('a configured null is not 0: the default window applies', async () => {
  reset(null);
  const g = mk({ lifecycleMaxAgeMs: null });
  await decide(g);
  await decide(g);
  assert.equal(state.bundleFetches, 1);
});

globalThis.fetch = realFetch;
if (failed) { console.log(`\n${failed} FAILED`); process.exit(1); }
console.log('\nPASS lifecycle-freshness');

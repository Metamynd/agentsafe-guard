// allowed-agents.smoke.mjs — defect XT-1 of the 2026-10-03 pre-beta evaluation (rerun on v1.78.0): a cross-tenant
// confused deputy. Every check this guard makes judges the CALLER by the CALLER's own policy, which the caller's owner
// writes. So a gateway that held one owner's credentials ran them for another tenant's agent whose owner had granted it
// an action of the same name — and, with requireAuthorization, once that owner registered the gateway's DID as its own
// counterparty. `allowedAgents` (MAGP §16.3) pins a Service to the agents it acts for: any other agent is refused
// AGENT_NOT_SERVED, after its signature is verified and before its policy is fetched or anything is claimed.
//
//   node allowed-agents.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function agent(account) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), account);
  const sign = (action, extra = {}) => {
    const base = { agentDid: did, action, amount: 0, currency: 'USD', merchant: '', nonce: crypto.randomUUID(), issuedAt: new Date().toISOString(), ...extra };
    return { ...base, signature: crypto.sign(null, Buffer.from(buildAuthMessage(base), 'utf8'), privateKey).toString('hex') };
  };
  return { did, sign };
}
const mine = agent('0.0.131');
const theirs = agent('0.0.132'); // another tenant's agent, whose OWN owner granted it the same action
const ISSUER = 'https://issuer.example/api/v1';
const serviceDid = buildHederaDid('testnet', crypto.randomBytes(32), '0.0.231');
const granted = { action: 'records-update', document: { permission: [{ target: 'records-update' }] } };

/** A guard whose bundle source and network are both recorded, so a test can prove nothing was fetched or claimed. */
function guardWith(opts) {
  const fetched = [];
  const guard = createMcpGuard({
    serviceDid,
    issuerApi: ISSUER,
    fetchBundle: async (did) => { fetched.push(did); return { subject: did, mandates: [granted], standards: [], sops: [] }; },
    ...opts,
  });
  return { guard, fetched };
}
async function quietly(fn) {
  const warn = console.warn; const warnings = [];
  console.warn = (...a) => warnings.push(a.join(' '));
  try { return { value: await fn(), warnings }; } finally { console.warn = warn; }
}

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('pinned: the agent it serves is evaluated as before', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did] });
  const v = await guard.verifyRequest(mine.sign('records-update'));
  assert.equal(v.decision, 'allow');
});

test('pinned: another tenant\'s agent, validly signed and granted the same action, is refused AGENT_NOT_SERVED', async () => {
  const { guard, fetched } = guardWith({ allowedAgents: [mine.did] });
  const v = await guard.verifyRequest(theirs.sign('records-update'));
  assert.deepEqual([v.decision, v.reasonCode], ['block', 'AGENT_NOT_SERVED']);
  assert.deepEqual(fetched, [], 'its policy is never fetched');
});

test('pinned + requireAuthorization: nothing is claimed for an agent it does not serve (the financial variant)', async () => {
  const real = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url) => { calls.push(String(url)); return { ok: true, status: 200, json: async () => ({ success: true, data: { claimed: true } }) }; };
  try {
    const { guard } = guardWith({ allowedAgents: [mine.did], requireAuthorization: true });
    const v = await guard.verifyRequest({ ...theirs.sign('records-update', { amount: 250, merchant: 'skyward-air' }), authorizationId: crypto.randomUUID() });
    assert.deepEqual([v.decision, v.reasonCode], ['block', 'AGENT_NOT_SERVED']);
    assert.deepEqual(calls, [], 'no claim or any other issuer call');
  } finally { globalThis.fetch = real; }
});

test('the signature is checked first: a forged request naming another agent is still SIGNATURE_INVALID', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did] });
  const forged = { ...theirs.sign('records-update'), signature: '00'.repeat(64) };
  assert.equal((await guard.verifyRequest(forged)).reasonCode, 'SIGNATURE_INVALID');
});

test('guardIncomingTool refuses an agent it does not serve before the handler runs', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did] });
  let ran = false;
  const tool = guard.guardIncomingTool('records-update', async () => { ran = true; return 'done'; });
  await assert.rejects(() => tool(theirs.sign('records-update')), (err) => err.governance?.reasonCode === 'AGENT_NOT_SERVED');
  assert.equal(ran, false);
  assert.equal(await tool(mine.sign('records-update')), 'done');
});

test("'any' serves every governed agent on purpose, without a warning", async () => {
  const { value, warnings } = await quietly(async () => guardWith({ allowedAgents: 'any' }).guard.verifyRequest(theirs.sign('records-update')));
  assert.equal(value.decision, 'allow');
  assert.equal(warnings.filter((w) => w.includes('allowedAgents')).length, 0);
});

test('unset keeps serving every agent (as before 0.20.0) and warns once at startup', async () => {
  const { value, warnings } = await quietly(async () => guardWith({}).guard.verifyRequest(theirs.sign('records-update')));
  assert.equal(value.decision, 'allow');
  assert.equal(warnings.filter((w) => w.includes('no allowedAgents')).length, 1);
});

test('a malformed allowedAgents fails at startup, never at the first request', () => {
  for (const bad of [[], [''], ['  '], [42], 'all', 42, {}]) {
    assert.throws(() => createMcpGuard({ serviceDid, issuerApi: ISSUER, allowedAgents: bad }), /allowedAgents/, `rejects ${JSON.stringify(bad)}`);
  }
});

test('the guard reports the pin it enforces (a gateway asserts it at startup)', async () => {
  assert.deepEqual([...guardWith({ allowedAgents: [` ${mine.did} `] }).guard.allowedAgents], [mine.did]);
  assert.equal(guardWith({ allowedAgents: 'any' }).guard.allowedAgents, 'any');
  const { value } = await quietly(async () => guardWith({}).guard.allowedAgents);
  assert.equal(value, null);
});

test('the mutual handshake opens no channel to an agent it does not serve', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const serviceKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
  // The other agent proves control of its DID, so only the pin can refuse it.
  const keys = crypto.generateKeyPairSync('ed25519');
  const spki = keys.publicKey.export({ type: 'spki', format: 'der' });
  const other = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.133');
  const guard = createMcpGuard({ serviceDid, serviceKey, fetchBundle: async () => ({}), allowedAgents: [mine.did] });
  const challenge = await guard.handshakeChallenge({ fromDid: other, nonceA: crypto.randomUUID() });
  const sigA = crypto.sign(null, Buffer.from(challenge.nonceB, 'utf8'), keys.privateKey).toString('hex');
  assert.throws(() => guard.handshakeVerify({ handshakeId: challenge.handshakeId, sigA }), (err) => err.code === 'AGENT_NOT_SERVED');
});

test('several agents may be listed', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did, ` ${theirs.did} `] });
  assert.equal((await guard.verifyRequest(theirs.sign('records-update'))).decision, 'allow');
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} allowedAgents cases.`);

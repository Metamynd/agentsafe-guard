// allowed-agents.smoke.mjs (A2A receiver; same contract as agentsafe-mcp-guard's) — gateway authority (XT-1, refined by the
// 2026-10-04 Gateway Authority Refinement Plan; MAGP §16.3): an agent that acts with its owner's credentials names the agents
// it accepts tasks from (unset is a startup error), is bound to the principal that owns those credentials, and may narrow
// admission per skill.
//
//   node allowed-agents.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createA2aGuard } from './agentsafe-a2a-guard.mjs';

const OWNER_A = 'did:hedera:testnet:zOwnerA_0.0.900';
const OWNER_B = 'did:hedera:testnet:zOwnerB_0.0.901';
function agent(account, owner) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), account);
  const sign = (action) => {
    const base = { agentDid: did, action, amount: 0, currency: 'USD', merchant: '', nonce: crypto.randomUUID(), issuedAt: new Date().toISOString() };
    return { ...base, signature: crypto.sign(null, Buffer.from(buildAuthMessage(base), 'utf8'), privateKey).toString('hex') };
  };
  return { did, owner, sign };
}
const mine = agent('0.0.131', OWNER_A);
const mine2 = agent('0.0.133', OWNER_A);
const theirs = agent('0.0.132', OWNER_B);
const ownerOf = new Map([mine, mine2, theirs].map((a) => [a.did, a.owner]));
const ISSUER = 'https://issuer.example/api/v1';
const serviceDid = buildHederaDid('testnet', crypto.randomBytes(32), '0.0.231');
const granted = { action: 'records-update', document: { permission: [{ target: 'records-update' }] } };

function guardWith(opts) {
  const fetched = [];
  const guard = createA2aGuard({
    serviceDid,
    issuerApi: ISSUER,
    fetchBundle: async (did) => { fetched.push(did); return { subject: did, ownerPrincipal: ownerOf.get(did), mandates: [granted], standards: [], sops: [] }; },
    ...(Array.isArray(opts.allowedAgents) && !('gatewayOwnerPrincipal' in opts) ? { gatewayOwnerPrincipal: OWNER_A } : {}),
    ...opts,
  });
  return { guard, fetched };
}

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('admitted agent evaluated; another tenant\'s agent refused AGENT_NOT_ADMITTED before its policy is fetched', async () => {
  const { guard, fetched } = guardWith({ allowedAgents: [mine.did] });
  assert.equal((await guard.verifyRequest(mine.sign('records-update'))).decision, 'allow');
  fetched.length = 0;
  assert.equal((await guard.verifyRequest(theirs.sign('records-update'))).reasonCode, 'AGENT_NOT_ADMITTED');
  assert.deepEqual(fetched, []);
});

test('owner binding: a listed agent of another owner is refused GATEWAY_OWNER_MISMATCH; owner fleet works', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did, mine2.did, theirs.did] });
  assert.equal((await guard.verifyRequest(theirs.sign('records-update'))).reasonCode, 'GATEWAY_OWNER_MISMATCH');
  assert.equal((await guard.verifyRequest(mine2.sign('records-update'))).decision, 'allow');
});

test('a skill (credential profile) may admit fewer agents: CREDENTIAL_PROFILE_NOT_PERMITTED', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did, mine2.did] });
  assert.equal((await guard.verifyRequest(mine.sign('records-update'), { allowedAgents: [mine2.did] })).reasonCode, 'CREDENTIAL_PROFILE_NOT_PERMITTED');
  assert.throws(() => guard.guardA2ATask('records-update', async () => 1, { allowedAgents: [] }), /non-empty/);
});

test('unset is a startup error; a list needs gatewayOwnerPrincipal; \'any\' needs none', () => {
  assert.throws(() => createA2aGuard({ serviceDid, issuerApi: ISSUER }), /allowedAgents is required/);
  assert.throws(() => createA2aGuard({ serviceDid, issuerApi: ISSUER, allowedAgents: [mine.did] }), (e) => e.code === 'GATEWAY_OWNER_UNBOUND');
  const g = createA2aGuard({ serviceDid, issuerApi: ISSUER, allowedAgents: 'any' });
  assert.deepEqual([g.allowedAgents, g.gatewayOwnerPrincipal], ['any', null]);
});

test('a malformed allowedAgents fails at startup', () => {
  for (const bad of [[], [''], ['  '], [42], 'all', 42, {}]) {
    assert.throws(() => createA2aGuard({ serviceDid, issuerApi: ISSUER, allowedAgents: bad, gatewayOwnerPrincipal: OWNER_A }), /allowedAgents/, `rejects ${JSON.stringify(bad)}`);
  }
});

const quiet = console.warn; console.warn = () => {};
let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
console.warn = quiet;
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} gateway-authority cases.`);

// allowed-agents.smoke.mjs — gateway authority (XT-1 of the 2026-10-03 pre-beta rerun, refined by the 2026-10-04 Gateway
// Authority Refinement Plan; MAGP §16.3). Every check a Service makes judges the CALLER by the CALLER's own policy, which
// the caller's owner writes, so a gateway holding one owner's credentials ran them for another tenant's agent. A Service now:
//   - must name the agents it acts for (`allowedAgents`; unset is a startup error, serving everyone is an explicit 'any');
//   - is bound to the principal that owns its credentials (`gatewayOwnerPrincipal`): an admitted agent whose SIGNED bundle
//     names another owner is refused GATEWAY_OWNER_MISMATCH;
//   - may narrow admission per credential profile (a route, a tool): CREDENTIAL_PROFILE_NOT_PERMITTED;
//   - refuses any other agent AGENT_NOT_ADMITTED, after its signature and before its policy is fetched or anything claimed;
//   - signs only a plain-token handshake nonce, so it is no signing oracle for its own claims (§8.2).
//
//   node allowed-agents.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createHandshakeInitiator, createMcpGuard } from './agentsafe-mcp-guard.mjs';

const OWNER_A = 'did:hedera:testnet:zOwnerA_0.0.900';
const OWNER_B = 'did:hedera:testnet:zOwnerB_0.0.901';
function agent(account, owner) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), account);
  const sign = (action, extra = {}) => {
    const base = { agentDid: did, action, amount: 0, currency: 'USD', merchant: '', nonce: crypto.randomUUID(), issuedAt: new Date().toISOString(), ...extra };
    return { ...base, signature: crypto.sign(null, Buffer.from(buildAuthMessage(base), 'utf8'), privateKey).toString('hex') };
  };
  return { did, owner, sign, privateKey };
}
const mine = agent('0.0.131', OWNER_A);
const mine2 = agent('0.0.133', OWNER_A); // a second agent of the same owner (an owner fleet)
const theirs = agent('0.0.132', OWNER_B); // another tenant's agent, whose OWN owner granted it the same action
const ownerOf = new Map([mine, mine2, theirs].map((a) => [a.did, a.owner]));
const ISSUER = 'https://issuer.example/api/v1';
const serviceDid = buildHederaDid('testnet', crypto.randomBytes(32), '0.0.231');
const granted = { action: 'records-update', document: { permission: [{ target: 'records-update' }] } };

/** A guard whose bundle source and network are both recorded, so a test can prove nothing was fetched or claimed. */
function guardWith(opts) {
  const fetched = [];
  const guard = createMcpGuard({
    serviceDid,
    issuerApi: ISSUER,
    fetchBundle: async (did) => { fetched.push(did); return { subject: did, ownerPrincipal: ownerOf.get(did), mandates: [granted], standards: [], sops: [] }; },
    ...(Array.isArray(opts.allowedAgents) && !('gatewayOwnerPrincipal' in opts) ? { gatewayOwnerPrincipal: OWNER_A } : {}),
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

test('admitted: the agent it serves is evaluated as before', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did] });
  assert.equal((await guard.verifyRequest(mine.sign('records-update'))).decision, 'allow');
});

test("not admitted: another tenant's agent, validly signed and granted the same action, is refused AGENT_NOT_ADMITTED", async () => {
  const { guard, fetched } = guardWith({ allowedAgents: [mine.did] });
  const v = await guard.verifyRequest(theirs.sign('records-update'));
  assert.deepEqual([v.decision, v.reasonCode], ['block', 'AGENT_NOT_ADMITTED']);
  assert.deepEqual(fetched, [], 'its policy is never fetched');
});

test('not admitted + requireAuthorization: nothing is claimed (the financial variant)', async () => {
  const real = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url) => { calls.push(String(url)); return { ok: true, status: 200, json: async () => ({ success: true, data: { claimed: true } }) }; };
  try {
    const { guard } = guardWith({ allowedAgents: [mine.did], requireAuthorization: true });
    const v = await guard.verifyRequest({ ...theirs.sign('records-update', { amount: 250, merchant: 'skyward-air' }), authorizationId: crypto.randomUUID() });
    assert.deepEqual([v.decision, v.reasonCode], ['block', 'AGENT_NOT_ADMITTED']);
    assert.deepEqual(calls, [], 'no claim or any other issuer call');
  } finally { globalThis.fetch = real; }
});

test('the signature is checked first: a forged request naming another agent is still SIGNATURE_INVALID', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did] });
  assert.equal((await guard.verifyRequest({ ...theirs.sign('records-update'), signature: '00'.repeat(64) })).reasonCode, 'SIGNATURE_INVALID');
});

test('owner binding: an admitted agent that another principal owns is refused GATEWAY_OWNER_MISMATCH', async () => {
  // The owner listed a foreign agent by mistake (or was tricked into it): its signed bundle names OWNER_B.
  const { guard } = guardWith({ allowedAgents: [mine.did, theirs.did] });
  assert.equal((await guard.verifyRequest(theirs.sign('records-update'))).reasonCode, 'GATEWAY_OWNER_MISMATCH');
  assert.equal((await guard.verifyRequest(mine.sign('records-update'))).decision, 'allow');
});

test('owner binding: a bundle that names no owner is refused, never assumed to be the gateway owner', async () => {
  const guard = createMcpGuard({ serviceDid, issuerApi: ISSUER, allowedAgents: [mine.did], gatewayOwnerPrincipal: OWNER_A, fetchBundle: async (did) => ({ subject: did, mandates: [granted], standards: [], sops: [] }) });
  assert.equal((await guard.verifyRequest(mine.sign('records-update'))).reasonCode, 'GATEWAY_OWNER_MISMATCH');
});

test('owner fleet: two admitted agents of the same owner both work', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did, ` ${mine2.did} `] });
  assert.equal((await guard.verifyRequest(mine.sign('records-update'))).decision, 'allow');
  assert.equal((await guard.verifyRequest(mine2.sign('records-update'))).decision, 'allow');
});

test('credential profile: a route admits fewer agents than the gateway — CREDENTIAL_PROFILE_NOT_PERMITTED', async () => {
  const { guard, fetched } = guardWith({ allowedAgents: [mine.did, mine2.did] });
  const v = await guard.verifyRequest(mine.sign('records-update'), { allowedAgents: [mine2.did] });
  assert.deepEqual([v.decision, v.reasonCode], ['block', 'CREDENTIAL_PROFILE_NOT_PERMITTED']);
  assert.deepEqual(fetched, [], 'refused before the policy is fetched');
  assert.equal((await guard.verifyRequest(mine2.sign('records-update'), { allowedAgents: [mine2.did] })).decision, 'allow');
});

test('credential profile on a tool: guardIncomingTool refuses an agent outside it before the handler runs', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did, mine2.did] });
  let ran = 0;
  const tool = guard.guardIncomingTool('records-update', async () => { ran++; return 'done'; }, { allowedAgents: [mine2.did] });
  await assert.rejects(() => tool(mine.sign('records-update')), (err) => err.governance?.reasonCode === 'CREDENTIAL_PROFILE_NOT_PERMITTED');
  assert.equal(await tool(mine2.sign('records-update')), 'done');
  assert.equal(ran, 1);
  assert.throws(() => guard.guardIncomingTool('records-update', async () => 1, { allowedAgents: [] }), /non-empty/);
});

test('guardIncomingTool refuses an agent it does not admit before the handler runs', async () => {
  const { guard } = guardWith({ allowedAgents: [mine.did] });
  let ran = false;
  const tool = guard.guardIncomingTool('records-update', async () => { ran = true; return 'done'; });
  await assert.rejects(() => tool(theirs.sign('records-update')), (err) => err.governance?.reasonCode === 'AGENT_NOT_ADMITTED');
  assert.equal(ran, false);
});

test("'any' serves every governed agent on purpose, says so at startup, and needs no owner", async () => {
  const { value, warnings } = await quietly(async () => guardWith({ allowedAgents: 'any' }).guard.verifyRequest(theirs.sign('records-update')));
  assert.equal(value.decision, 'allow');
  assert.equal(warnings.filter((w) => w.includes("allowedAgents: 'any'")).length, 1);
});

test('unset is a startup error (it used to serve everyone): a Service must name whom it acts for', () => {
  assert.throws(() => createMcpGuard({ serviceDid, issuerApi: ISSUER }), /allowedAgents is required/);
});

test('a list without gatewayOwnerPrincipal is a startup error (GATEWAY_OWNER_UNBOUND)', () => {
  assert.throws(() => createMcpGuard({ serviceDid, issuerApi: ISSUER, allowedAgents: [mine.did] }), (e) => e.code === 'GATEWAY_OWNER_UNBOUND');
  assert.throws(() => createMcpGuard({ serviceDid, issuerApi: ISSUER, allowedAgents: [mine.did], gatewayOwnerPrincipal: 'owner-a' }), (e) => e.code === 'GATEWAY_OWNER_UNBOUND');
});

test('a malformed allowedAgents fails at startup, never at the first request', () => {
  for (const bad of [[], [''], ['  '], [42], 'all', 42, {}]) {
    assert.throws(() => createMcpGuard({ serviceDid, issuerApi: ISSUER, allowedAgents: bad, gatewayOwnerPrincipal: OWNER_A }), /allowedAgents/, `rejects ${JSON.stringify(bad)}`);
  }
});

test('the guard reports the admission and owner it enforces (a gateway asserts both at startup)', async () => {
  const { guard } = guardWith({ allowedAgents: [` ${mine.did} `] });
  assert.deepEqual([...guard.allowedAgents], [mine.did]);
  assert.equal(guard.gatewayOwnerPrincipal, OWNER_A);
  const { value } = await quietly(async () => guardWith({ allowedAgents: 'any' }).guard);
  assert.deepEqual([value.allowedAgents, value.gatewayOwnerPrincipal], ['any', null]);
});

test('the mutual handshake opens no channel to an agent it does not admit', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const serviceKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
  const guard = createMcpGuard({ serviceDid, serviceKey, fetchBundle: async () => ({}), allowedAgents: [mine.did], gatewayOwnerPrincipal: OWNER_A });
  const challenge = await guard.handshakeChallenge({ fromDid: theirs.did, nonceA: crypto.randomUUID() });
  const sigA = crypto.sign(null, Buffer.from(challenge.nonceB, 'utf8'), theirs.privateKey).toString('hex');
  assert.throws(() => guard.handshakeVerify({ handshakeId: challenge.handshakeId, sigA }), (err) => err.code === 'AGENT_NOT_ADMITTED');
});

test('the handshake is no signing oracle: a nonce that is not a plain token is never signed (§8.2)', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const serviceKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
  const guard = createMcpGuard({ serviceDid, serviceKey, fetchBundle: async () => ({}), allowedAgents: 'any' });
  // A HELLO whose "nonce" is a forged MAGP-SERVICE-v1 claim: signing it would hand the caller this Service's claim signature.
  const forged = `MAGP-SERVICE-v1|claim|${crypto.randomUUID()}|key|nonce|${new Date().toISOString()}`;
  await assert.rejects(() => guard.handshakeChallenge({ fromDid: mine.did, nonceA: forged }), /plain token/);
  await assert.rejects(() => guard.handshakeChallenge({ fromDid: mine.did, nonceA: 'short' }), /plain token/);
  // The initiator side refuses to sign a CHALLENGE nonce that is an authorize message.
  const init = createHandshakeInitiator({ fromDid: mine.did, sign: () => { throw new Error('must not sign'); } });
  const { nonceA } = init.hello();
  const sigB = crypto.sign(null, Buffer.from(nonceA, 'utf8'), privateKey).toString('hex');
  await assert.rejects(() => init.prove({ nonceA, challenge: { toDid: serviceDid, nonceB: buildAuthMessage({ agentDid: mine.did, action: 'flight-purchase', amount: 500, currency: 'USD', merchant: 'x', resource: null, nonce: 'n', issuedAt: 't' }), sigB } }), /plain token/);
});

const quiet = console.warn; console.warn = () => {};
let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
console.warn = quiet;
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} gateway-authority cases.`);

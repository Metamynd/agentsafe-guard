// claim-authorization.smoke.mjs — proves the requireAuthorization opt-in actually closes
// replay and cumulative spend: a PERMIT verdict is only granted if the agent's
// authorizationId atomically claims single-use execution against the (mocked) stateful
// issuer gate, AND the claimed hold's own bound values match what's being executed.
//
//   node claim-authorization.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const raw = spki.subarray(spki.length - 32);
  const did = buildHederaDid('testnet', raw, topic);
  const sign = (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex');
  return { did, sign };
}

const agent = mint('0.0.101');
const service = mint('0.0.201');

const bundle = {
  subject: agent.did,
  standards: [],
  sops: [],
  mandates: [{
    action: 'flight-purchase',
    document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] },
  }],
};

function signedRequest({ amount, currency = 'USD', merchant = 'skyward-air', authorizationId }) {
  const action = 'flight-purchase';
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const message = buildAuthMessage({ agentDid: agent.did, action, amount, currency, merchant, nonce, issuedAt });
  const signature = agent.sign(message);
  return { agentDid: agent.did, action, amount, currency, merchant, nonce, issuedAt, signature, authorizationId };
}

/** Mock the ONE network call claimAuthorization makes: POST .../effect/dispatching. */
function withMockClaim(responder) {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    assert.match(String(url), /\/effect\/dispatching$/, 'claimAuthorization must hit the dispatching transition');
    assert.equal(opts?.method, 'POST');
    const { status, body } = responder(url);
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  return () => { globalThis.fetch = realFetch; };
}

const mk = (opts = {}) => createMcpGuard({ serviceDid: service.did, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true, ...opts });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('a genuine, matching claim permits the request', async () => {
  const restore = withMockClaim(() => ({ status: 200, body: { success: true, data: { ok: true, effectState: 'dispatching', agentDid: agent.did, amount: 250, currency: 'USD' } } }));
  try {
    const r = await mk().verifyRequest(signedRequest({ amount: 250, authorizationId: 'auth-1' }));
    assert.equal(r.decision, 'allow');
  } finally { restore(); }
});

test('requireAuthorization is OFF by default — no authorizationId needed, no network call', async () => {
  const restore = withMockClaim(() => { throw new Error('must not be called'); });
  try {
    const guard = createMcpGuard({ serviceDid: service.did, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1' });
    const r = await guard.verifyRequest(signedRequest({ amount: 250 }));
    assert.equal(r.decision, 'allow');
  } finally { restore(); }
});

test('missing authorizationId is refused when required', async () => {
  const restore = withMockClaim(() => { throw new Error('must not be called — no id to claim'); });
  try {
    const r = await mk().verifyRequest(signedRequest({ amount: 250 }));
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'AUTHORIZATION_REQUIRED');
  } finally { restore(); }
});

test('a replay — claiming the same authorizationId twice — is refused the second time', async () => {
  const claimed = new Set();
  const restore = withMockClaim((url) => {
    const id = decodeURIComponent(String(url).split('/authorize/')[1].split('/effect')[0]);
    if (claimed.has(id)) return { status: 409, body: { success: false, message: 'INVALID_EFFECT_TRANSITION' } };
    claimed.add(id);
    return { status: 200, body: { success: true, data: { ok: true, agentDid: agent.did, amount: 250, currency: 'USD' } } };
  });
  try {
    const g = mk();
    const first = await g.verifyRequest(signedRequest({ amount: 250, authorizationId: 'auth-replay' }));
    assert.equal(first.decision, 'allow');
    const second = await g.verifyRequest(signedRequest({ amount: 250, authorizationId: 'auth-replay' }));
    assert.equal(second.decision, 'block'); assert.equal(second.reasonCode, 'INVALID_EFFECT_TRANSITION');
  } finally { restore(); }
});

test('an unknown authorizationId is refused', async () => {
  const restore = withMockClaim(() => ({ status: 404, body: { success: false, message: 'AUTHORIZATION_NOT_FOUND' } }));
  try {
    const r = await mk().verifyRequest(signedRequest({ amount: 250, authorizationId: 'nope' }));
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'AUTHORIZATION_NOT_FOUND');
  } finally { restore(); }
});

test('a claimed hold for a DIFFERENT amount is refused, not silently trusted', async () => {
  // 500 is well within the bundle's own $1000 mandate cap — this must reach the claim step
  // (an amount over the mandate cap would be blocked by policy alone, proving nothing about
  // the claim-binding check this test targets).
  const restore = withMockClaim(() => ({ status: 200, body: { success: true, data: { ok: true, agentDid: agent.did, amount: 10, currency: 'USD' } } }));
  try {
    const r = await mk().verifyRequest(signedRequest({ amount: 500, authorizationId: 'auth-cheap' }));
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'AUTHORIZATION_AMOUNT_MISMATCH');
  } finally { restore(); }
});

test('a claimed hold for a DIFFERENT currency is refused', async () => {
  const restore = withMockClaim(() => ({ status: 200, body: { success: true, data: { ok: true, agentDid: agent.did, amount: 250, currency: 'EUR' } } }));
  try {
    const r = await mk().verifyRequest(signedRequest({ amount: 250, currency: 'USD', authorizationId: 'auth-x' }));
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'AUTHORIZATION_CURRENCY_MISMATCH');
  } finally { restore(); }
});

test('a claimed hold for a DIFFERENT agent is refused', async () => {
  const restore = withMockClaim(() => ({ status: 200, body: { success: true, data: { ok: true, agentDid: 'did:hedera:testnet:someone-else_0.0.999', amount: 250, currency: 'USD' } } }));
  try {
    const r = await mk().verifyRequest(signedRequest({ amount: 250, authorizationId: 'auth-y' }));
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'AUTHORIZATION_AGENT_MISMATCH');
  } finally { restore(); }
});

test('a block/escalate verdict never attempts a claim — nothing to protect, no hold spent', async () => {
  const restore = withMockClaim(() => { throw new Error('must not be called for a non-permit verdict'); });
  try {
    const r = await mk().verifyRequest(signedRequest({ amount: 9999, authorizationId: 'auth-z' })); // over the $1000 mandate cap
    assert.equal(r.decision, 'block');
  } finally { restore(); }
});

test('the issuer being unreachable fails CLOSED', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('ECONNREFUSED'); };
  try {
    const r = await mk().verifyRequest(signedRequest({ amount: 250, authorizationId: 'auth-w' }));
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'AUTHORIZATION_CLAIM_UNREACHABLE');
  } finally { globalThis.fetch = realFetch; }
});

let pass = 0, fail = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m ' + name); pass++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m ' + name + '\n       ' + e.message); fail++; }
}
console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

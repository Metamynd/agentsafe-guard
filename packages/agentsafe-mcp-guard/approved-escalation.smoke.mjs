// approved-escalation.smoke.mjs — MAGP §8.7.18 (defect N-2 of the 2026-10-03 pre-beta evaluation). The agent escalated
// a high-risk purchase, its owner approved it, and the approval minted a hold. The agent then presented that hold to its
// gateway with the same context that escalated it — and the gateway's own policy said "escalate" again and refused
// RISK_REVIEW, so the approved action could only run if the agent re-signed it at a LOWER risk. Now the gateway asks the
// issuer whether a person approved that hold, and executes it only if so.
//
//   node approved-escalation.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), topic);
  return { did, sign: (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex') };
}
const agent = mint('0.0.111');
const service = mint('0.0.211');

const bundle = {
  subject: agent.did,
  standards: [],
  sops: [{ id: 'sop-1', document: { molecules: [
    { id: 'review', name: 'High-risk review', combinator: 'any', atoms: [{ id: 'a', predicate: 'risk-at-or-above', config: { level: 'high' } }], decision: 'escalate', reasonCode: 'RISK_REVIEW' },
    { id: 'cap', name: 'Per-transaction cap', combinator: 'any', atoms: [{ id: 'b', predicate: 'amount-over', config: { limit: 500 } }], decision: 'block', reasonCode: 'SOP_SPEND_CAP' },
  ] } }],
  mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] } }],
};

function signed({ amount = 300, riskLevel = 'high', authorizationId } = {}) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const base = { agentDid: agent.did, action: 'flight-purchase', amount, currency: 'USD', merchant: 'skyward-air', nonce, issuedAt };
  return { ...base, signature: agent.sign(buildAuthMessage(base)), itinerary: { riskLevel }, ...(authorizationId ? { authorizationId } : {}) };
}

/** The issuer, mocked: records every call; `claim` answers the dispatching transition. */
function issuer(claim) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const body = opts?.body ? JSON.parse(opts.body) : null;
    calls.push({ url: String(url), body });
    if (/\/effect\/dispatching$/.test(String(url))) {
      const { status, body: out } = claim(body);
      return { ok: status < 300, status, json: async () => out };
    }
    if (/\/void$/.test(String(url))) return { ok: true, status: 200, json: async () => ({ success: true, data: { voided: true } }) };
    throw new Error(`unexpected call ${url}`);
  };
  return { calls, restore: () => { globalThis.fetch = realFetch; } };
}
const grant = (extra = {}) => ({ status: 200, body: { success: true, data: { ok: true, effectState: 'dispatching', agentDid: agent.did, action: 'flight-purchase', amount: 300, currency: 'USD', merchant: 'skyward-air', payloadDigest: null, claimToken: 'tok-1', ...extra } } });
const mk = (opts = {}) => createMcpGuard({ serviceDid: service.did, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true, ...opts });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('the reproduced defect: an owner-approved escalation, presented with its original high risk, now executes', async () => {
  const io = issuer(() => grant({ approvedByHuman: true }));
  try {
    const r = await mk().verifyRequest(signed({ authorizationId: 'auth-approved' }));
    assert.equal(r.decision, 'allow');
    assert.equal(r.reasonCode, 'ESCALATION_APPROVED');
    assert.equal(r.escalatedFor, 'RISK_REVIEW');
    assert.equal(r.claimToken, 'tok-1'); // claimed once, settleable like any permit
    assert.equal(io.calls[0].body.requireHumanApproval, true); // asked the issuer for a PERSON's approval
  } finally { io.restore(); }
});

test('a hold no person approved keeps the escalate — and stays unclaimed (the issuer refused before claiming)', async () => {
  const io = issuer(() => ({ status: 409, body: { success: false, message: 'ESCALATION_NOT_APPROVED' } }));
  try {
    const r = await mk().verifyRequest(signed({ authorizationId: 'auth-ordinary' }));
    assert.equal(r.decision, 'escalate');
    assert.equal(r.reasonCode, 'RISK_REVIEW');
    assert.equal(io.calls.filter((c) => /\/void$/.test(c.url)).length, 0);
  } finally { io.restore(); }
});

test('an issuer that ignores the flag and grants without approvedByHuman: never executes, and the claim is released', async () => {
  const io = issuer(() => grant()); // no approvedByHuman field at all (pre-§8.7.18 issuer)
  try {
    const r = await mk().verifyRequest(signed({ authorizationId: 'auth-old-issuer' }));
    assert.equal(r.decision, 'escalate');
    const voids = io.calls.filter((c) => /\/void$/.test(c.url));
    assert.equal(voids.length, 1);
    assert.equal(voids[0].body.claimToken, 'tok-1');
  } finally { io.restore(); }
});

test('approvedByHuman must be literally true — a truthy string is not an approval', async () => {
  const io = issuer(() => grant({ approvedByHuman: 'yes' }));
  try {
    assert.equal((await mk().verifyRequest(signed({ authorizationId: 'auth-truthy' }))).decision, 'escalate');
  } finally { io.restore(); }
});

test('an approval of a DIFFERENT amount does not unlock this one — every claim binding still applies', async () => {
  const io = issuer(() => grant({ approvedByHuman: true, amount: 120 }));
  try {
    const r = await mk().verifyRequest(signed({ amount: 300, authorizationId: 'auth-cheap' }));
    assert.equal(r.decision, 'block');
    assert.equal(r.reasonCode, 'AUTHORIZATION_AMOUNT_MISMATCH');
  } finally { io.restore(); }
});

test('an escalate with no authorization attached is just an escalate — no network', async () => {
  const io = issuer(() => { throw new Error('must not claim'); });
  try {
    const r = await mk().verifyRequest(signed());
    assert.equal(r.decision, 'escalate');
    assert.equal(io.calls.length, 0);
  } finally { io.restore(); }
});

test('a BLOCK is never lifted by an approval given before it (over the cap, approved hold presented)', async () => {
  const io = issuer(() => { throw new Error('must not claim on a block'); });
  try {
    const r = await mk().verifyRequest(signed({ amount: 900, authorizationId: 'auth-approved' }));
    assert.equal(r.decision, 'block');
    assert.equal(r.reasonCode, 'SOP_SPEND_CAP');
    assert.equal(io.calls.length, 0);
  } finally { io.restore(); }
});

test('without requireAuthorization (trustless mode) nothing is claimed — an escalate stays an escalate', async () => {
  const io = issuer(() => { throw new Error('must not claim'); });
  try {
    const r = await mk({ requireAuthorization: false, allowUnverifiedBundle: true }).verifyRequest(signed({ authorizationId: 'auth-approved' }));
    assert.equal(r.decision, 'escalate');
    assert.equal(io.calls.length, 0);
  } finally { io.restore(); }
});

test('over a plain-http issuer link (not loopback) an escalate is never lifted — approvedByHuman could be forged in transit', async () => {
  const io = issuer(() => grant({ approvedByHuman: true }));
  try {
    const r = await mk({ issuerApi: 'http://issuer.example/api/v1' }).verifyRequest(signed({ authorizationId: 'auth-approved' }));
    assert.equal(r.decision, 'escalate');
    assert.equal(io.calls.length, 0);
  } finally { io.restore(); }
});

test('...but a loopback development issuer over http is fine', async () => {
  const io = issuer(() => grant({ approvedByHuman: true }));
  try {
    const r = await mk({ issuerApi: 'http://localhost:9926/api/v1' }).verifyRequest(signed({ authorizationId: 'auth-approved' }));
    assert.equal(r.decision, 'allow');
  } finally { io.restore(); }
});

test('an ordinary permit still claims WITHOUT the flag (nothing changes for allow/observe)', async () => {
  const io = issuer(() => grant());
  try {
    const r = await mk().verifyRequest(signed({ riskLevel: 'low', authorizationId: 'auth-low' }));
    assert.equal(r.decision, 'allow');
    assert.equal(io.calls[0].body.requireHumanApproval, undefined);
  } finally { io.restore(); }
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} approved-escalation cases.`);

// claim-expectations.smoke.mjs — MAGP §8.7.19 (defect N-3 of the 2026-10-03 pre-beta evaluation). Agent B presented
// agent A's authorization id at A's gateway. The gateway CLAIMED A's hold, then noticed the grant was A's and refused
// AUTHORIZATION_AGENT_MISMATCH — leaving A's hold stuck `dispatching` against A's cap with nothing executed. Now the claim
// states what it is about to execute (`expect`) so the issuer refuses BEFORE claiming; and a mismatch found only after a
// grant (an older issuer) releases the claim instead of stranding it.
//
//   node claim-expectations.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';
import { payloadDigestOf } from './payload-binding.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { did: buildHederaDid('testnet', spki.subarray(spki.length - 32), topic), sign: (m) => crypto.sign(null, Buffer.from(m, 'utf8'), privateKey).toString('hex') };
}
const victim = mint('0.0.121');
const attacker = mint('0.0.122');
const service = mint('0.0.221');

const bundleFor = (did) => ({
  subject: did, standards: [], sops: [],
  mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] } }],
});

function signedBy(who, { amount = 200, authorizationId = 'auth-victim' } = {}) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const base = { agentDid: who.did, action: 'flight-purchase', amount, currency: 'USD', merchant: 'skyward-air', nonce, issuedAt };
  return { ...base, signature: who.sign(buildAuthMessage(base)), authorizationId };
}

function issuer(claim) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const body = opts?.body ? JSON.parse(opts.body) : null;
    calls.push({ url: String(url), body });
    if (/\/effect\/dispatching$/.test(String(url))) { const { status, body: out } = claim(body); return { ok: status < 300, status, json: async () => out }; }
    if (/\/void$/.test(String(url))) return { ok: true, status: 200, json: async () => ({ success: true, data: { voided: true } }) };
    throw new Error(`unexpected ${url}`);
  };
  return { calls, voids: () => calls.filter((c) => /\/void$/.test(c.url)), restore: () => { globalThis.fetch = realFetch; } };
}
/** The victim's hold, as the issuer would grant it. */
const victimGrant = (extra = {}) => ({ status: 200, body: { success: true, data: { ok: true, agentDid: victim.did, action: 'flight-purchase', amount: 200, currency: 'USD', merchant: 'skyward-air', payloadDigest: null, claimToken: 'tok-v', ...extra } } });
const mk = (subject) => createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => bundleFor(subject), issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('the claim states what this gateway is about to execute — the SIGNED values', async () => {
  const io = issuer(() => victimGrant());
  try {
    await mk(victim.did).verifyRequest(signedBy(victim));
    // ...and the context it is about to execute (here none: {}), which the issuer compares for a person-approved hold (§9a.5).
    const contextDigest = payloadDigestOf({ 'MAGP-APPROVED-CONTEXT-v1': {} });
    assert.deepEqual(io.calls[0].body.expect, { agentDid: victim.did, action: 'flight-purchase', amount: 200, currency: 'USD', merchant: 'skyward-air', contextDigest });
  } finally { io.restore(); }
});

test('the reproduced defect, with a current issuer: another agent presenting the victim\'s id is refused BEFORE any claim', async () => {
  // The issuer compares `expect.agentDid` (the attacker) with the hold (the victim's) and refuses without claiming.
  const io = issuer((b) => (b.expect.agentDid !== victim.did ? { status: 403, body: { success: false, message: 'AUTHORIZATION_AGENT_MISMATCH' } } : victimGrant()));
  try {
    const r = await mk(attacker.did).verifyRequest(signedBy(attacker));
    assert.equal(r.decision, 'block');
    assert.equal(r.reasonCode, 'AUTHORIZATION_AGENT_MISMATCH');
    assert.equal(io.voids().length, 0); // nothing was claimed, so nothing to release — the victim's hold is untouched
  } finally { io.restore(); }
});

test('with an older issuer that ignores `expect` and grants the victim\'s hold: the claim is RELEASED, not stranded', async () => {
  const io = issuer(() => victimGrant());
  try {
    const r = await mk(attacker.did).verifyRequest(signedBy(attacker));
    assert.equal(r.reasonCode, 'AUTHORIZATION_AGENT_MISMATCH');
    assert.equal(io.voids().length, 1);
    assert.equal(io.voids()[0].body.claimToken, 'tok-v');
  } finally { io.restore(); }
});

test('every post-grant mismatch releases the claim (amount shown)', async () => {
  const io = issuer(() => victimGrant({ amount: 50 }));
  try {
    const r = await mk(victim.did).verifyRequest(signedBy(victim, { amount: 200 }));
    assert.equal(r.reasonCode, 'AUTHORIZATION_AMOUNT_MISMATCH');
    assert.equal(io.voids().length, 1);
  } finally { io.restore(); }
});

test('a matching claim is unchanged: allowed, nothing released', async () => {
  const io = issuer(() => victimGrant());
  try {
    const r = await mk(victim.did).verifyRequest(signedBy(victim));
    assert.equal(r.decision, 'allow');
    assert.equal(io.voids().length, 0);
  } finally { io.restore(); }
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} claim-expectation cases.`);

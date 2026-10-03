// a2a-approved-escalation.smoke.mjs — MAGP §8.7.18 on the A2A receiver. Same contract as agentsafe-mcp-guard's
// approved-escalation.smoke.mjs: an escalate with an authorization attached executes only when the ISSUER says a person
// approved that hold; otherwise it stays an escalate.
//
//   node a2a-approved-escalation.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createA2aGuard, MAGP_A2A_EXTENSION_URI } from './agentsafe-a2a-guard.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const agentDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.911');
const sign = (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex');
const ISSUER = 'https://issuer.example/api/v1';

const bundle = {
  subject: agentDid,
  standards: [],
  sops: [{ id: 'sop-1', document: { molecules: [{ id: 'review', name: 'High-risk review', combinator: 'any', atoms: [{ id: 'a', predicate: 'risk-at-or-above', config: { level: 'high' } }], decision: 'escalate', reasonCode: 'RISK_REVIEW' }] } }],
  mandates: [{ action: 'book-hotel', document: { permission: [{ target: 'book-hotel', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] } }],
};

function envelope() {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const signature = sign(buildAuthMessage({ agentDid, action: 'book-hotel', amount: 250, currency: 'USD', merchant: '', nonce, issuedAt }));
  return { agentDid, action: 'book-hotel', amount: 250, currency: 'USD', merchant: '', nonce, issuedAt, signature, authorizationId: 'auth-1', itinerary: { riskLevel: 'high' } };
}

function mockIssuer(claim) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const path = String(url).replace(ISSUER, '');
    calls.push({ path, body: opts?.body ? JSON.parse(opts.body) : null });
    const { status, body } = path.endsWith('/effect/dispatching') ? claim() : { status: 200, body: { success: true, data: {} } };
    return { ok: status < 300, status, json: async () => body };
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}
const grant = (extra = {}) => ({ status: 200, body: { success: true, data: { ok: true, agentDid, action: 'book-hotel', amount: 250, currency: 'USD', claimToken: 'tok', ...extra } } });
const mk = () => createA2aGuard({ issuerApi: ISSUER, fetchBundle: async () => bundle, requireAuthorization: true });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('the issuer says a person approved it: the escalated task executes, once', async () => {
  const io = mockIssuer(() => grant({ approvedByHuman: true }));
  try {
    const d = await mk().verifyRequest(envelope());
    assert.equal(d.decision, 'allow');
    assert.equal(d.reasonCode, 'ESCALATION_APPROVED');
    assert.deepEqual(io.calls[0].body, { requireHumanApproval: true });
  } finally { io.restore(); }
});

test('no person approved it: still an escalate, hold untouched', async () => {
  const io = mockIssuer(() => ({ status: 409, body: { success: false, message: 'ESCALATION_NOT_APPROVED' } }));
  try {
    const d = await mk().verifyRequest(envelope());
    assert.equal(d.decision, 'escalate');
    assert.equal(io.calls.some((c) => c.path.endsWith('/void')), false);
  } finally { io.restore(); }
});

test('an issuer that ignores the flag: never executes, the claim is released', async () => {
  const io = mockIssuer(() => grant());
  try {
    const d = await mk().verifyRequest(envelope());
    assert.equal(d.decision, 'escalate');
    assert.equal(io.calls.filter((c) => c.path.endsWith('/void')).length, 1);
  } finally { io.restore(); }
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} A2A approved-escalation cases.`);

// a2a-approved-escalation.smoke.mjs — MAGP §8.7.18 on the A2A receiver. Same contract as agentsafe-mcp-guard's
// approved-escalation.smoke.mjs: an escalate with an authorization attached executes only when the ISSUER says a person
// approved that hold; otherwise it stays an escalate.
//
//   node a2a-approved-escalation.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createA2aGuard, buildTaskStatus, MAGP_A2A_EXTENSION_URI } from './agentsafe-a2a-guard.mjs';
import { payloadDigestOf } from './payload-binding.mjs';

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
    const sent = opts?.body ? JSON.parse(opts.body) : null;
    const { status, body } = path.endsWith('/effect/dispatching') ? claim(sent) : { status: 200, body: { success: true, data: {} } };
    // A current issuer names, on a person-approved grant, the context it compared the claim's with (§9a.5) — the one stated.
    if (body?.data?.approvedByHuman === true && !('contextDigest' in body.data)) body.data.contextDigest = sent?.expect?.contextDigest;
    return { ok: status < 300, status, json: async () => body };
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}
const grant = (extra = {}) => ({ status: 200, body: { success: true, data: { ok: true, agentDid, action: 'book-hotel', amount: 250, currency: 'USD', claimToken: 'tok', ...extra } } });
const mk = () => createA2aGuard({ allowedAgents: 'any', issuerApi: ISSUER, fetchBundle: async () => bundle, requireAuthorization: true });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('the issuer says a person approved it: the escalated task executes, once', async () => {
  const io = mockIssuer(() => grant({ approvedByHuman: true }));
  try {
    const d = await mk().verifyRequest(envelope());
    assert.equal(d.decision, 'allow');
    assert.equal(d.reasonCode, 'ESCALATION_APPROVED');
    assert.equal(io.calls[0].body.requireHumanApproval, true);
  } finally { io.restore(); }
});

// F-1-NF (pre-beta rerun 5): a person-approved hold runs only the context that person approved (§9a.5).
const contextDigestOf = (itinerary) => payloadDigestOf({ 'MAGP-APPROVED-CONTEXT-v1': itinerary ?? {} });
test('the claim states the context digest; a person-approved grant naming another context (or none) is refused and released', async () => {
  for (const contextDigest of [contextDigestOf({ riskLevel: 'high', target: 'other' }), undefined]) {
    const io = mockIssuer(() => grant({ approvedByHuman: true, contextDigest }));
    try {
      const d = await mk().verifyRequest(envelope());
      assert.equal(io.calls[0].body.expect.contextDigest, contextDigestOf({ riskLevel: 'high' }));
      assert.equal(d.decision, 'block');
      assert.equal(d.reasonCode, 'AUTHORIZATION_CONTEXT_MISMATCH');
      assert.equal(io.calls.filter((c) => c.path.endsWith('/void')).length, 1);
    } finally { io.restore(); }
  }
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

// Pre-beta rerun 6 FW6-1 (as agentsafe-mcp-guard 0.29.0): an issuer's refusal of the claim carries a `detail` (for
// AUTHORIZATION_CONTEXT_REQUIRED, which gateway to upgrade). The receiver logs it in one line, the block carries it, and the
// refusal TaskStatus relays it in its MAGP metadata.
const withWarnings = async (fn) => { const warn = console.warn; const lines = []; console.warn = (...a) => lines.push(a.join(' ')); try { await fn(); } finally { console.warn = warn; } return lines; };
test('a refused claim carries the issuer detail on the block and the TaskStatus, and logs one line', async () => {
  const detail = 'AUTHORIZATION_CONTEXT_REQUIRED: ... Upgrade the gateway: @metamynd/agentsafe-a2a-guard >= 0.18.0';
  const io = mockIssuer(() => ({ status: 403, body: { success: false, message: 'AUTHORIZATION_CONTEXT_REQUIRED', data: { reasonCode: 'AUTHORIZATION_CONTEXT_REQUIRED', detail } } }));
  let d;
  try {
    const lines = await withWarnings(async () => { d = await mk().verifyRequest(envelope()); });
    assert.equal(d.decision, 'block'); assert.equal(d.reasonCode, 'AUTHORIZATION_CONTEXT_REQUIRED'); assert.equal(d.detail, detail);
    assert.equal(lines.filter((l) => l.includes('refused the claim of authorization auth-1') && l.includes('Upgrade the gateway')).length, 1);
  } finally { io.restore(); }
  const status = buildTaskStatus({ ...d, contextId: 'ctx', taskId: 'task' });
  assert.equal(status.state, 'TASK_STATE_REJECTED');
  assert.equal(status.message.metadata[MAGP_A2A_EXTENSION_URI].detail, detail);
});

test('a refusal without a detail logs the bare code and adds no detail; ESCALATION_NOT_APPROVED logs nothing', async () => {
  const io = mockIssuer(() => ({ status: 409, body: { success: false, message: 'AUTHORIZATION_ALREADY_CLAIMED', data: { reasonCode: 'AUTHORIZATION_ALREADY_CLAIMED' } } }));
  let d;
  try {
    const lines = await withWarnings(async () => { d = await mk().verifyRequest(envelope()); });
    assert.equal(d.reasonCode, 'AUTHORIZATION_ALREADY_CLAIMED'); assert.equal(d.detail, undefined);
    assert.ok(lines.some((l) => l.endsWith('auth-1: AUTHORIZATION_ALREADY_CLAIMED')));
    assert.equal('detail' in buildTaskStatus(d).message.metadata[MAGP_A2A_EXTENSION_URI], false);
  } finally { io.restore(); }
  const io2 = mockIssuer(() => ({ status: 409, body: { success: false, message: 'ESCALATION_NOT_APPROVED', data: { detail: 'not yet approved' } } }));
  try {
    const lines = await withWarnings(async () => { d = await mk().verifyRequest(envelope()); });
    assert.equal(d.decision, 'escalate'); assert.equal(lines.some((l) => l.includes('refused the claim')), false);
  } finally { io2.restore(); }
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} A2A approved-escalation cases.`);

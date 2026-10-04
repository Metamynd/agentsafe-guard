// resume-binding.smoke.mjs — resume() runs only the request the owner approved (0.24.0; pre-beta rerun 4, F-1).
//
// Before: resume() mapped whatever args it was given and ran the tool under the approval's authorization. An owner approved
// $5 to skyward-air; resume({ amount: 5000 }) or resume({ merchant: 'shadow-broker' }) ran an in-process tool, and the
// ledger recorded the $5. A gateway refused the same resume; an in-process tool had nothing else in the way.
//
//   node resume-binding.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { buildHederaDid } from './magp-did.mjs';
import { createGuard } from './agentsafe-guard.mjs';
import { buildResumeBindingMessage, resumeRequestDigest } from './resume-binding.mjs';
import { payloadDigestOf, toWireJson } from './payload-binding.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const agentDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.702');
const agentKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');

const HOLD = '1e7506c4-cdc6-40e0-a513-23a314535fb0';
const approvedPayload = { amount: 5, merchant: 'skyward-air', currency: 'USD' };

/** A fake issuer: the escalation is approved with the given status fields; captures and voids are recorded. */
function fakeIssuer(status) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    calls.push(u);
    const reply = (data, code = 200) => ({ ok: code < 400, status: code, json: async () => ({ success: code < 400, data }) });
    if (u.includes('/escalations/')) return reply({ escalationId: 'esc-1', status: 'approved', reasonCode: 'ESCALATION_APPROVED', authorizationId: HOLD, ...status });
    if (u.endsWith('/effect')) return reply({ outcome: 'not_started', effectState: 'authorized' });
    if (u.endsWith('/capture')) return reply({ captured: true });
    if (u.endsWith('/void')) return reply({ voided: true, reasonCode: 'HOLD_VOIDED' });
    return reply({}, 404);
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

const guard = createGuard({ api: 'http://issuer.test/api/v1', agentDid, agentKey, mode: 'remote' });
const mapArgs = (a) => ({ amount: a.amount, currency: 'USD', merchant: a.merchant, context: { riskLevel: a.riskLevel }, payload: { amount: a.amount, merchant: a.merchant, currency: 'USD' } });
const digestOf = (fields) => resumeRequestDigest({ authorizationId: HOLD, action: 'flight-purchase', currency: 'USD', resource: '', ...fields });
const bound = { payloadBound: true, requestDigest: digestOf({ amount: 5, merchant: 'skyward-air', payloadDigest: payloadDigestOf(toWireJson(approvedPayload)) }) };

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`ok    ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.stack ?? e.message}`); }
}
async function resumeWith(status, args) {
  const f = fakeIssuer(status);
  const ran = [];
  try {
    const tool = guard.guardTool('flight-purchase', async (a) => { ran.push(a); return { pnr: 'PNR-1' }; }, mapArgs);
    try { return { out: await tool.resume('esc-1', args, { timeoutMs: 1000 }), ran, calls: f.calls }; }
    catch (e) { return { err: e, ran, calls: f.calls }; }
  } finally { f.restore(); }
}

await check('the approved args run, once', async () => {
  const r = await resumeWith(bound, { amount: 5, merchant: 'skyward-air', riskLevel: 'high' });
  assert.equal(r.err, undefined, r.err?.message);
  assert.equal(r.ran.length, 1);
});

for (const [label, args] of [
  ['a larger amount (5000, over the cap)', { amount: 5000, merchant: 'skyward-air', riskLevel: 'high' }],
  ['a smaller amount (4)', { amount: 4, merchant: 'skyward-air', riskLevel: 'high' }],
  ['another merchant (shadow-broker)', { amount: 5, merchant: 'shadow-broker', riskLevel: 'high' }],
]) {
  await check(`${label} is refused ESCALATION_REQUEST_MISMATCH and the tool never runs`, async () => {
    const r = await resumeWith(bound, args);
    assert.equal(r.err?.governance?.reasonCode, 'ESCALATION_REQUEST_MISMATCH');
    assert.equal(r.err.governance.decision, 'block');
    assert.equal(r.ran.length, 0);
    assert.ok(!r.calls.some((u) => /\/(capture|void)$/.test(u)), 'the approved hold is left for the right request');
  });
}

await check('a different payload under the same amount and merchant is refused', async () => {
  const f = fakeIssuer(bound);
  const ran = [];
  try {
    const tool = guard.guardTool('flight-purchase', async (a) => { ran.push(a); return {}; }, (a) => ({ ...mapArgs(a), payload: { ...mapArgs(a).payload, payee: 'IBAN-X' } }));
    await assert.rejects(tool.resume('esc-1', { amount: 5, merchant: 'skyward-air' }, { timeoutMs: 1000 }), (e) => e.governance?.reasonCode === 'ESCALATION_REQUEST_MISMATCH');
    assert.equal(ran.length, 0);
  } finally { f.restore(); }
});

await check('the agent\'s riskLevel is not part of the binding (it is not what the hold authorizes)', async () => {
  const r = await resumeWith(bound, { amount: 5, merchant: 'skyward-air', riskLevel: 'low' });
  assert.equal(r.err, undefined, r.err?.message);
  assert.equal(r.ran.length, 1);
});

await check('a hold with no payload digest (a MODIFY) binds amount and merchant only', async () => {
  const modify = { payloadBound: false, requestDigest: digestOf({ amount: 3, merchant: 'skyward-air', payloadDigest: '' }) };
  assert.equal((await resumeWith(modify, { amount: 3, merchant: 'skyward-air' })).ran.length, 1);
  assert.equal((await resumeWith(modify, { amount: 5, merchant: 'skyward-air' })).err?.governance?.reasonCode, 'ESCALATION_REQUEST_MISMATCH');
});

await check('an issuer that predates requestDigest: resume behaves as before (the gateway still re-verifies)', async () => {
  const r = await resumeWith({ payloadBound: true }, { amount: 5000, merchant: 'skyward-air' });
  assert.equal(r.err, undefined);
  assert.equal(r.ran.length, 1);
});

await check('the bundled resume-binding reproduces docs/protocol/resume-binding-vectors.json', async () => {
  const v = JSON.parse(readFileSync(new URL('../../docs/protocol/resume-binding-vectors.json', import.meta.url), 'utf8'));
  for (const c of v.vectors) {
    assert.equal(buildResumeBindingMessage(c.fields), c.message, c.name);
    assert.equal(resumeRequestDigest(c.fields), c.digest, c.name);
  }
});

if (failed) { console.log(`\n${failed} FAILED`); process.exit(1); }
console.log('\nPASS resume-binding');

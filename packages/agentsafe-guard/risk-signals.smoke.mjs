// risk-signals.smoke.mjs — a refusal names the risk the issuer derived (0.25.0; pre-beta rerun 4, F-4).
//
// Before: a "low" $105 payment on a $150 cap came back ESCALATE RISK_REVIEW, exactly like a call the agent itself flagged
// high, and nothing on the refusal said the gate had derived the risk (70% of the cap). The gate now returns riskSignals;
// the guard keeps them on err.governance and names them in the message a model reads.
//
//   node risk-signals.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildHederaDid } from './magp-did.mjs';
import { createGuard, derivedRiskNote } from './agentsafe-guard.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const agentDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.703');
const agentKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
const SIGNAL = { signal: 'amount-share', level: 'high', detail: '70% of the 150 per-transaction cap (review from 70%)' };

function fakeIssuer(verdict) {
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    const reply = (data, code) => ({ ok: code < 400, status: code, json: async () => ({ success: code < 400, data }) });
    if (u.endsWith('/policy/mandate/authorize')) return reply(verdict, 403);
    return reply({}, 404);
  };
  return () => { globalThis.fetch = real; };
}

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`ok    ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.stack ?? e.message}`); }
}
const guard = createGuard({ api: 'http://issuer.test/api/v1', agentDid, agentKey, mode: 'remote' });
const tool = () => guard.guardTool('flight-purchase', async () => 'ran', (a) => ({ amount: a.amount, currency: 'USD', merchant: 'skyward-air', context: { riskLevel: 'low' } }));

await check('an issuer-derived escalation keeps riskSignals on err.governance and names them in the message', async () => {
  const restore = fakeIssuer({ decision: 'escalate', reasonCode: 'RISK_REVIEW', escalationId: 'esc-1', riskSignals: [SIGNAL] });
  try {
    await assert.rejects(tool()({ amount: 105 }), (e) => {
      assert.deepEqual(e.governance.riskSignals, [SIGNAL]);
      assert.match(e.message, /RISK_REVIEW \(risk derived by the issuer: amount-share: 70% of the 150 per-transaction cap/);
      return true;
    });
  } finally { restore(); }
});

await check('an escalation the agent asked for itself says nothing more', async () => {
  const restore = fakeIssuer({ decision: 'escalate', reasonCode: 'RISK_REVIEW', escalationId: 'esc-2' });
  try {
    await assert.rejects(tool()({ amount: 10 }), (e) => e.message.endsWith('RISK_REVIEW') && e.governance.riskSignals === undefined);
  } finally { restore(); }
});

await check('derivedRiskNote ignores anything that is not a list', async () => {
  assert.equal(derivedRiskNote({}), '');
  assert.equal(derivedRiskNote({ riskSignals: 'high' }), '');
  assert.equal(derivedRiskNote(null), '');
  assert.equal(derivedRiskNote({ riskSignals: [{ signal: 'owner-tier', level: 'high' }] }), ' (risk derived by the issuer: owner-tier: high)');
});

if (failed) { console.log(`\n${failed} FAILED`); process.exit(1); }
console.log('\nPASS risk-signals');

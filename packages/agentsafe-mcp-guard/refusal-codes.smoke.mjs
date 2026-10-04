// refusal-codes.smoke.mjs — defect N-6 of the 2026-10-03 pre-beta evaluation: two refusals named the wrong cause.
//   • A revoked mandate was refused NO_MANDATE ("never granted") while the owner's Activity Log said MANDATE_REVOKED. The
//     bundle now lists the revoked actions (`revokedActions`, §6.2.6) and the refusal names them.
//   • An issuer outage was refused GUARD_ERROR, which reads as a fault in this Service. A network failure or a 5xx on the
//     bundle fetch is now GATE_UNREACHABLE, the agent guard's code for the same outage. A 4xx is an answer and is unchanged.
// Only the reason code changes: every case here was, and still is, a block.
//
//   node refusal-codes.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const agentDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.131');
const ISSUER = 'https://issuer.example/api/v1';
const serviceDid = buildHederaDid('testnet', crypto.randomBytes(32), '0.0.231');
const hotel = { action: 'hotel-booking', document: { permission: [{ target: 'hotel-booking' }] } };

function signed(action) {
  const base = { agentDid, action, amount: 0, currency: 'USD', merchant: '', nonce: crypto.randomUUID(), issuedAt: new Date().toISOString() };
  return { ...base, signature: crypto.sign(null, Buffer.from(buildAuthMessage(base), 'utf8'), privateKey).toString('hex') };
}
const withBundle = (b) => createMcpGuard({ allowedAgents: 'any', serviceDid, issuerApi: ISSUER, fetchBundle: async () => ({ subject: agentDid, standards: [], sops: [], ...b }) });

/** The issuer's bundle endpoint, answering as `answer` does (a throw is a network failure). */
async function withIssuer(answer, fn) {
  const real = globalThis.fetch;
  globalThis.fetch = async () => answer();
  try { return await fn(createMcpGuard({ allowedAgents: 'any', serviceDid, issuerApi: ISSUER })); } finally { globalThis.fetch = real; }
}

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('a revoked action is refused MANDATE_REVOKED, not NO_MANDATE', async () => {
  const v = await withBundle({ mandates: [], revokedActions: ['flight-purchase'] }).verifyRequest(signed('flight-purchase'));
  assert.deepEqual([v.decision, v.reasonCode], ['block', 'MANDATE_REVOKED']);
});

test('... also while the agent still holds mandates for other actions', async () => {
  const v = await withBundle({ mandates: [hotel], revokedActions: ['flight-purchase'] }).verifyRequest(signed('flight-purchase'));
  assert.deepEqual([v.decision, v.reasonCode], ['block', 'MANDATE_REVOKED']);
});

test('a revoke never relabels an action that was never granted', async () => {
  const scoped = await withBundle({ mandates: [hotel], revokedActions: ['flight-purchase'] }).verifyRequest(signed('permissions.update'));
  assert.equal(scoped.reasonCode, 'NO_PERMISSION_FOR_ACTION');
  const none = await withBundle({ mandates: [], revokedActions: ['flight-purchase'] }).verifyRequest(signed('permissions.update'));
  assert.equal(none.reasonCode, 'NO_MANDATE');
});

test('a bundle without the field (an older issuer) reads exactly as before', async () => {
  assert.equal((await withBundle({ mandates: [] }).verifyRequest(signed('flight-purchase'))).reasonCode, 'NO_MANDATE');
  assert.equal((await withBundle({ mandates: [hotel] }).verifyRequest(signed('flight-purchase'))).reasonCode, 'NO_PERMISSION_FOR_ACTION');
});

test('the issuer is down (network failure): GATE_UNREACHABLE', async () => {
  const v = await withIssuer(() => { throw new TypeError('fetch failed'); }, (g) => g.verifyRequest(signed('flight-purchase')));
  assert.deepEqual([v.decision, v.reasonCode], ['block', 'GATE_UNREACHABLE']);
});

test('the issuer answers 503: GATE_UNREACHABLE', async () => {
  const v = await withIssuer(() => ({ ok: false, status: 503, json: async () => null }), (g) => g.verifyRequest(signed('flight-purchase')));
  assert.deepEqual([v.decision, v.reasonCode], ['block', 'GATE_UNREACHABLE']);
});

test('a 404 is an answer, not an outage: still GUARD_ERROR', async () => {
  const v = await withIssuer(() => ({ ok: false, status: 404, json: async () => ({ success: false }) }), (g) => g.verifyRequest(signed('flight-purchase')));
  assert.deepEqual([v.decision, v.reasonCode], ['block', 'GUARD_ERROR']);
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} refusal-code cases.`);

// settle-signature.smoke.mjs — an agent settling its OWN hold that nobody has claimed (MAGP §8.7.4; 2026-10-03 pre-beta
// rerun, N-8). The issuer used to accept an unsigned capture or void of an unclaimed hold from anyone holding the
// authorization id, which the agent hands to every gateway it asks to execute. It now takes one only from the hold's agent
// (MAGP-SETTLE-v1) or a counterparty the owner registered, on every owner. guard.capture() signs as
// the agent; a key provider that cannot (a caller's own, or a signer daemon older than 0.20.0) settles unsigned, as before.
//
//   node settle-signature.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAgentSettleMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createGuard } from './agentsafe-guard.mjs';
import { createStaticKeyProvider } from './key-providers.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const agentDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.700');
const agentKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
const AUTH = crypto.randomUUID();
const verifies = (message, sigHex) => crypto.verify(null, Buffer.from(message, 'utf8'), publicKey, Buffer.from(sigHex, 'hex'));

async function capturing(fn) {
  const real = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => { calls.push({ url: String(url), body: JSON.parse(init.body) }); return { ok: true, status: 200, json: async () => ({ success: true }) }; };
  try { await fn(); return calls; } finally { globalThis.fetch = real; }
}

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`ok    ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}

await check('capture() carries a MAGP-SETTLE-v1 signature over exactly that capture', async () => {
  const guard = createGuard({ api: 'http://issuer.test/api/v1', agentDid, agentKey });
  const [call] = await capturing(() => guard.capture(AUTH, 250, 'PNR-1'));
  const p = call.body.agentProof;
  assert.equal(p.agentDid, agentDid);
  assert.ok(verifies(buildAgentSettleMessage({ verb: 'capture', agentDid, authorizationId: AUTH, nonce: p.nonce, issuedAt: p.issuedAt, fields: ['250', 'PNR-1', ''] }), p.signature));
  assert.ok(!verifies(buildAgentSettleMessage({ verb: 'capture', agentDid, authorizationId: AUTH, nonce: p.nonce, issuedAt: p.issuedAt, fields: ['0', 'PNR-1', ''] }), p.signature), 'bound to the amount');
  assert.ok(!verifies(buildAgentSettleMessage({ verb: 'void', agentDid, authorizationId: AUTH, nonce: p.nonce, issuedAt: p.issuedAt, fields: ['250', 'PNR-1', ''] }), p.signature), 'bound to the verb');
});

await check('the static key provider signs the shared message (the issuer and the signer daemon build the same bytes)', async () => {
  const kp = createStaticKeyProvider(agentKey);
  const f = { verb: 'void', agentDid, authorizationId: AUTH, nonce: 'n-1', issuedAt: new Date().toISOString(), fields: ['why|not'] };
  assert.ok(verifies(buildAgentSettleMessage(f), await kp.signSettle(f)));
  assert.equal(buildAgentSettleMessage({ ...f, agentDid: 'did:x', authorizationId: 'a', nonce: 'n', issuedAt: 't' }), 'MAGP-SETTLE-v1|void|did:x|a|n|t|why\\|not');
});

await check('a key provider that cannot sign a settlement settles unsigned, as before (no throw)', async () => {
  const inner = createStaticKeyProvider(agentKey);
  const { signSettle: _omit, ...without } = inner;
  const guard = createGuard({ api: 'http://issuer.test/api/v1', agentDid, keyProvider: without });
  const [call] = await capturing(() => guard.capture(AUTH, 10));
  assert.equal(call.body.agentProof, undefined);
  const old = { ...inner, signSettle: async () => { throw Object.assign(new Error('old daemon'), { code: 'SETTLE_SIGNING_UNSUPPORTED' }); } };
  const [oldCall] = await capturing(() => createGuard({ api: 'http://issuer.test/api/v1', agentDid, keyProvider: old }).capture(AUTH, 10));
  assert.equal(oldCall.body.agentProof, undefined);
});

if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log('\nPASS — the agent signs the settlement of its own unclaimed hold.');

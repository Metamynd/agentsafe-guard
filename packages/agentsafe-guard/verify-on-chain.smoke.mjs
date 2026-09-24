// verify-on-chain.smoke.mjs — `verifyOnChain` trusts a local bundle only when it is the LATEST one anchored on the
// agent's Hedera topic (policy-update.sigDigest = sha256 of the compile's signature). The issuer now re-issues a
// compiled bundle at serve time (fresh issuedAt, re-signed, so maxStaleness bounds the copy rather than the compile)
// and carries the anchored compile signature as `compiledSignature`; an older issuer serves the compiled bundle
// itself. Both must match the anchor; anything else defers to the remote gate.
//
//   node verify-on-chain.smoke.mjs
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';
import { buildHederaDid } from './magp-did.mjs';

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}
const sha = (s) => 'sha256:' + crypto.createHash('sha256').update(String(s)).digest('hex');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const agentDid = buildHederaDid('testnet', publicKey.export({ format: 'der', type: 'spki' }).subarray(-32), '0.0.777');
const COMPILED_SIG = 'aa'.repeat(64);
const RESERVE_SIG = 'bb'.repeat(64);
const rules = {
  // Only flight-purchase is granted: 'vehicle-inspection' is a LOCAL block (NO_PERMISSION_FOR_ACTION) — if the guard
  // trusts the bundle it decides without the remote gate; if not, it defers to /policy/mandate/authorize.
  mandates: [{ action: 'flight-purchase', document: { uid: 'u', permission: [{ target: 'flight-purchase', action: 'execute', constraint: [] }] } }],
  sops: [],
  standards: [],
  maxStaleness: 'PT10M',
};

async function run(label, served, anchoredDigest) {
  const calls = { remote: 0 };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes('/policy/bundle/')) return { ok: true, json: async () => ({ data: served }) };
    if (u.includes('mirrornode.hedera.com') && u.includes('/topics/0.0.777/messages')) {
      const message = Buffer.from(JSON.stringify({ op: 'policy-update', did: agentDid, sigDigest: anchoredDigest })).toString('base64');
      return { ok: true, json: async () => ({ messages: [{ sequence_number: 7, message }] }) };
    }
    if (u.endsWith('/policy/mandate/authorize')) {
      calls.remote++;
      return { ok: true, status: 200, json: async () => ({ success: true, data: { decision: 'block', reasonCode: 'REMOTE_GATE' } }) };
    }
    if (u.endsWith('/policy/decisions/local')) return { ok: true, json: async () => ({}) };
    return { ok: false, status: 404, json: async () => null };
  };
  try {
    const guard = createGuard({ api: 'http://issuer.local/api/v1', agentDid, agentKey, verifyOnChain: true });
    const v = await guard.authorizeLocal({ action: 'vehicle-inspection', context: {} });
    return { v, calls };
  } finally {
    globalThis.fetch = realFetch;
  }
}

const reissued = { ...rules, issuedAt: new Date().toISOString(), compiledAt: '2026-09-24T06:00:00.000Z', compiledSignature: COMPILED_SIG, proof: { signature: RESERVE_SIG } };
const legacy = { ...rules, issuedAt: '2026-09-24T06:00:00.000Z', proof: { signature: COMPILED_SIG } };

let r = await run('reissued', reissued, sha(COMPILED_SIG));
check(r.calls.remote === 0 && r.v.reasonCode === 'NO_PERMISSION_FOR_ACTION', `re-issued bundle: compiledSignature matches the anchor → decided locally (${r.v.reasonCode}, remote calls ${r.calls.remote})`);

r = await run('legacy', legacy, sha(COMPILED_SIG));
check(r.calls.remote === 0 && r.v.reasonCode === 'NO_PERMISSION_FOR_ACTION', `issuer without re-issue: proof.signature matches the anchor → decided locally (${r.v.reasonCode})`);

r = await run('reissued-wrong-anchor', reissued, sha('cc'.repeat(64)));
check(r.calls.remote === 1, `anchor names another compile → defers to the remote gate (remote calls ${r.calls.remote})`);

r = await run('serve-signature-only', { ...reissued, compiledSignature: undefined }, sha(COMPILED_SIG));
check(r.calls.remote === 1, `the per-serve signature is never taken for the anchored one → defers (remote calls ${r.calls.remote})`);

if (failed) { console.log(`\n${failed} check(s) FAILED`); process.exit(1); }
console.log('\nverify-on-chain: all checks passed');

// refusal-codes.smoke.mjs — defect N-6 of the 2026-10-03 pre-beta evaluation, on the agent side. The owner revoked the
// agent's mandate; the agent's local evaluation said NO_MANDATE ("never granted") while the Activity Log said
// MANDATE_REVOKED. The bundle now lists the revoked actions (`revokedActions`, §6.2.6) and the local refusal names them.
// Only the reason code changes: every case here was, and still is, a block.
//
//   node refusal-codes.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';
import { buildHederaDid } from './magp-did.mjs';

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const agentDid = buildHederaDid('testnet', publicKey.export({ format: 'der', type: 'spki' }).subarray(-32), '0.0.1');
const hotel = { action: 'hotel-booking', document: { uid: 'u', permission: [{ target: 'hotel-booking', action: 'execute', constraint: [] }] } };

/** A guard whose issuer serves `bundle`; local decision reports are accepted and ignored. */
async function decide(bundle, action) {
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes('/policy/bundle/')) return { ok: true, json: async () => ({ data: { standards: [], sops: [], ...bundle } }) };
    return { ok: true, json: async () => ({ success: true, data: {} }) };
  };
  try {
    return await createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey }).authorizeLocal({ action, context: {} });
  } finally { globalThis.fetch = real; }
}

const revoked = await decide({ mandates: [], revokedActions: ['flight-purchase'] }, 'flight-purchase');
check(revoked.decision === 'block' && revoked.reasonCode === 'MANDATE_REVOKED', `a revoked action → block/MANDATE_REVOKED (got ${revoked.decision}/${revoked.reasonCode})`);

const revokedScoped = await decide({ mandates: [hotel], revokedActions: ['flight-purchase'] }, 'flight-purchase');
check(revokedScoped.reasonCode === 'MANDATE_REVOKED', `... also while other mandates remain (got ${revokedScoped.reasonCode})`);

const neverGranted = await decide({ mandates: [hotel], revokedActions: ['flight-purchase'] }, 'permissions.update');
check(neverGranted.reasonCode === 'NO_PERMISSION_FOR_ACTION', `a never-granted action is not relabelled by another action's revoke (got ${neverGranted.reasonCode})`);

const older = await decide({ mandates: [] }, 'flight-purchase');
check(older.reasonCode === 'NO_MANDATE', `a bundle without the field reads as before (got ${older.reasonCode})`);

if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log('\nPASS — agent-side refusal codes.');

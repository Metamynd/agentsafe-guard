// daemon-keyprovider.smoke.mjs — proves keyProvider:'daemon' actually works end to end: a real
// agentsafe-signer daemon signs, agentsafe-guard never sees the key, and the signature verifies.
//
// MONOREPO-ONLY: imports integrations/agentsafe-signer by relative path across the package
// boundary, which only works when both packages live side by side in this repo — never added to
// package.json's `files`/`test` script, since a published @metamynd/agentsafe-guard must not
// require @metamynd/agentsafe-signer to exist alongside it. Run directly: node daemon-keyprovider.smoke.mjs
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createGuard } from './agentsafe-guard.mjs';
import { createDaemonKeyProvider } from './key-providers.mjs';
import { verifyDidSignature, buildHederaDid } from './magp-did.mjs';
import { buildLocalDecisionMessage } from './policy-core.mjs';
import { SignerDaemon } from '../agentsafe-signer/daemon.mjs';

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}

async function main() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentsafe-guard-daemon-'));
  const daemon = new SignerDaemon({ stateDir, role: 'agent', kek: crypto.randomBytes(32) });
  await daemon.waitUntilUnlocked();
  const { publicKeyHex } = daemon.handleAdminRequest({ op: 'generate-key' });
  const raw = Buffer.from(publicKeyHex, 'hex').subarray(-32);
  const agentDid = buildHederaDid('testnet', raw, '0.0.1');
  daemon.setIdentity(agentDid);

  const socketPath = path.join(stateDir, 'signer.sock');
  await daemon.startSigningServer(socketPath);

  const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, keyProvider: 'daemon', daemonSocketPath: socketPath });

  const req = await guard.buildSignedRequest({ action: 'flight-purchase', amount: 100, merchant: 'amadeus' });
  const { buildAuthMessage } = await import('./policy-core.mjs');
  const message = buildAuthMessage(req);
  check(verifyDidSignature(agentDid, message, req.signature), 'buildSignedRequest via keyProvider:"daemon" produces a signature the backend-shaped verifier accepts');

  // Signed over the UTF-8 bytes of the challenge STRING, not its hex-decoded bytes — the real
  // convention both agentsafe-guard's original sign() and create-metamynd-agent's
  // signChallengeHex use. verifyDidSignature signs/verifies over UTF-8 message bytes, so this is
  // the correct, direct check — not the hex-decode this test caught the daemon getting wrong.
  const challengeHex = crypto.randomBytes(16).toString('hex');
  const sig = await guard.signChallenge(challengeHex);
  check(verifyDidSignature(agentDid, challengeHex, sig), 'signChallenge via keyProvider:"daemon" matches the real UTF-8-challenge convention (caught the daemon hex-decoding it instead)');

  // --- signLocalDecision via the daemon keyProvider: called directly against the keyProvider
  //     (not through guard.authorizeLocal()) since reportLocalDecision() is fire-and-forget and
  //     there's nothing to await on the guard's own surface — this is the same "test the
  //     keyProvider method directly" approach the plan calls for. Proves the daemon-custody agent
  //     now gets the same audit-visibility enhancement the static-key provider always had. ---
  {
    const keyProvider = createDaemonKeyProvider({ socketPath });
    const fields = { agentDid, action: 'vehicle-inspection', decision: 'block', reasonCode: 'NO_PERMISSION_FOR_ACTION', nonce: crypto.randomUUID(), issuedAt: new Date().toISOString() };
    const signature = await keyProvider.signLocalDecision(fields);
    const message = buildLocalDecisionMessage(fields);
    check(verifyDidSignature(agentDid, message, signature), 'keyProvider.signLocalDecision via the real daemon produces a signature that verifies against buildLocalDecisionMessage');

    let threw = null;
    try {
      await keyProvider.signLocalDecision({ ...fields, decision: 'quarantine' });
    } catch (err) {
      threw = err;
    }
    check(threw !== null && threw.code === 'DAEMON_MALFORMED_REQUEST', 'the daemon itself rejects a non-reportable decision (e.g. "quarantine") even when asked over the real socket, not just in-process');
  }

  if (failed) {
    console.error(`\n${failed} case(s) FAILED`);
    process.exit(1);
  }
  console.log('\nPASS — agentsafe-guard + agentsafe-signer daemon, wired end to end.');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

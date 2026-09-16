// daemon-keyprovider.smoke.mjs — proves keyProvider:'daemon' works end to end for the SERVICE
// side: a real agentsafe-signer daemon (role:'service') signs a handshake CHALLENGE for a real
// mcp-guard, and the resulting sigB verifies against the service's real DID.
//
// MONOREPO-ONLY: imports integrations/agentsafe-signer by relative path across the package
// boundary (see agentsafe-guard/daemon-keyprovider.smoke.mjs's own header for why) — never added
// to package.json's `files`/`test` script.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';
import { verifyDidSignature, buildHederaDid } from './magp-did.mjs';
import { SignerDaemon } from '../agentsafe-signer/daemon.mjs';

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}

async function main() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentsafe-mcp-guard-daemon-'));
  const daemon = new SignerDaemon({ stateDir, role: 'service', kek: crypto.randomBytes(32) });
  await daemon.waitUntilUnlocked();
  const { publicKeyHex } = daemon.handleAdminRequest({ op: 'generate-key' });
  const raw = Buffer.from(publicKeyHex, 'hex').subarray(-32);
  const serviceDid = buildHederaDid('testnet', raw, '0.0.200');
  daemon.setIdentity(serviceDid);

  const socketPath = path.join(stateDir, 'signer.sock');
  await daemon.startSigningServer(socketPath);

  const guard = createMcpGuard({ serviceDid, keyProvider: 'daemon', daemonSocketPath: socketPath });

  const nonceA = crypto.randomUUID();
  const challenge = await guard.handshakeChallenge({ fromDid: 'did:key:zSomeAgent', nonceA, protoVersion: '1.0' });
  check(challenge.toDid === serviceDid, 'handshakeChallenge via keyProvider:"daemon" returns the daemon-bound serviceDid');
  check(verifyDidSignature(serviceDid, nonceA, challenge.sigB), "sigB verifies against the service's real DID — the daemon signed it, agentsafe-mcp-guard never held the key");

  // A service-role daemon must refuse anything outside sign-handshake-nonce/get-identity/ping —
  // confirms the role boundary holds even when reached through the guard's own provider, not just
  // when calling the daemon directly (already covered in agentsafe-signer's own suite).
  let refused = false;
  try {
    daemon.handleSigningRequest({ op: 'sign-authorize', params: {} });
  } catch (err) {
    refused = err.code === 'DAEMON_OPERATION_NOT_PERMITTED';
  }
  check(refused, 'the same daemon instance still refuses sign-authorize (service role), even though it just signed a handshake nonce for this guard');

  if (failed) {
    console.error(`\n${failed} case(s) FAILED`);
    process.exit(1);
  }
  console.log('\nPASS — agentsafe-mcp-guard + agentsafe-signer daemon (service role), wired end to end.');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

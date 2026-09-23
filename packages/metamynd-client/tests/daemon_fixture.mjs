// daemon_fixture.mjs — a REAL agentsafe-signer daemon for the Python client's daemon-signer
// conformance test (test_daemon_signer.py). Not a stand-in: the actual SignerDaemon class from
// this repository, listening on a real socket (a real named pipe on Windows), the way
// `agentsafe-guard`'s own daemon-keyprovider tests use it.
//
//   node daemon_fixture.mjs <state-dir>
//
// Prints ONE line of JSON on stdout once listening — { socketPath, agentDid, publicKeyHex } — then
// stays alive until stdin closes (the parent process exited or dropped the pipe) or it is killed.
import { SignerDaemon } from '../../agentsafe-signer/daemon.mjs';
import { buildHederaDid } from '../../agentsafe-mcp-guard/magp-did.mjs';
import crypto from 'node:crypto';
import path from 'node:path';

const stateDir = process.argv[2];
if (!stateDir) {
  console.error('usage: node daemon_fixture.mjs <state-dir>');
  process.exit(2);
}

function didForPublicKeyHex(publicKeyHex, topic = '0.0.4242') {
  const spki = Buffer.from(publicKeyHex, 'hex');
  const raw = spki.subarray(spki.length - 32);
  return buildHederaDid('testnet', raw, topic);
}

async function main() {
  // Placeholder identity at construction (only real once the generated key's DID is known) — same
  // two-step provisioning the daemon's own smoke tests use (generate, then rebind to the real DID).
  const placeholder = didForPublicKeyHex(crypto.randomBytes(32).toString('hex').padStart(64, '0'));
  const daemon = new SignerDaemon({ stateDir, role: 'agent', agentDid: placeholder, kek: crypto.randomBytes(32) });
  await daemon.waitUntilUnlocked();
  const { publicKeyHex } = daemon.handleAdminRequest({ op: 'generate-key' });
  const agentDid = didForPublicKeyHex(publicKeyHex);
  daemon.setIdentity(agentDid);

  const socketPath = path.join(stateDir, 'signer.sock');
  await daemon.startSigningServer(socketPath);
  process.stdout.write(JSON.stringify({ socketPath, agentDid, publicKeyHex }) + '\n');

  // Stay alive until the parent closes stdin (its own subprocess.Popen teardown) or sends a signal.
  process.stdin.resume();
  process.stdin.on('end', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

main().catch((err) => {
  console.error(err?.stack || String(err));
  process.exit(1);
});

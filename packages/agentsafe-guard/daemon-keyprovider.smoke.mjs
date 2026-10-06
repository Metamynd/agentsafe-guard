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
import { spawn } from 'node:child_process';
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

  // The signed jurisdiction (MAGP 8.3.12) through the REAL daemon: the v2 message over exactly the value sent.
  const reqJ = await guard.buildSignedRequest({ action: 'flight-purchase', amount: 100, merchant: 'amadeus', jurisdiction: 'sg' });
  check(reqJ.jurisdiction === 'SG' && verifyDidSignature(agentDid, buildAuthMessage(reqJ), reqJ.signature) && buildAuthMessage(reqJ).endsWith('|MAGP-AUTH-v2|SG'), 'a jurisdiction signed via the daemon verifies as the v2 message over the value sent');

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
      await keyProvider.signLocalDecision({ ...fields, decision: 'decommission' });
    } catch (err) {
      threw = err;
    }
    check(threw !== null && threw.code === 'DAEMON_MALFORMED_REQUEST', 'the daemon itself rejects a non-reportable decision (e.g. "decommission") even when asked over the real socket, not just in-process');
  }

  // --- payload binding through the REAL daemon (MAGP 8.3.9 / 8.3.11): before signer 0.15.0 a daemon-custody agent asked to bind
  //     a payload failed closed; now `sign-payload` signs it without the key ever entering this process ---
  {
    const { buildPayloadBindingMessage, buildPayloadRebindMessage, payloadDigestOf } = await import('./payload-binding.mjs');
    const PAYLOAD = { payee: 'NL91ABNA0417164300', amount: 100 };
    const realFetch = globalThis.fetch;
    let sent = null;
    globalThis.fetch = async (url, opts) => { sent = { url: String(url), body: JSON.parse(opts.body) }; return { ok: true, status: 200, json: async () => ({ data: { decision: 'allow', authorizationId: '7f3c1d2e-9a4b-4c5d-8e6f-0a1b2c3d4e5f', payloadDigest: sent.body.payloadDigest ?? null } }) }; };
    try {
      const r = await guard.authorize({ action: 'flight-purchase', amount: 100, currency: 'USD', merchant: 'amadeus', payload: PAYLOAD });
      const b = sent.body;
      check(r.decision === 'allow' && b.payloadDigest === payloadDigestOf(PAYLOAD), 'guard.authorize({ payload }) through the daemon sends the digest of the payload');
      check(verifyDidSignature(agentDid, buildPayloadBindingMessage({ agentDid, action: b.action, nonce: b.nonce, issuedAt: b.issuedAt, payloadDigest: b.payloadDigest }), b.payloadSignature), 'the daemon-made binding signature verifies with the shared verifier (the key never entered this process)');

      const authorizationId = '7f3c1d2e-9a4b-4c5d-8e6f-0a1b2c3d4e5f';
      const late = await guard.bindPayload({ authorizationId, action: 'flight-purchase', payload: PAYLOAD });
      const c = sent.body;
      check(late.bound === true && sent.url.endsWith(`/authorize/${authorizationId}/payload-binding`), 'guard.bindPayload() through the daemon binds a hold that already exists');
      check(verifyDidSignature(agentDid, buildPayloadRebindMessage({ agentDid, action: c.action, authorizationId, nonce: c.nonce, issuedAt: c.issuedAt, payloadDigest: c.payloadDigest }), c.payloadSignature), 'the daemon-made LATE binding verifies over the rebind message naming the authorization');
      check(!verifyDidSignature(agentDid, buildPayloadBindingMessage({ agentDid, action: c.action, nonce: c.nonce, issuedAt: c.issuedAt, payloadDigest: c.payloadDigest }), c.payloadSignature), '...and not as an authorize-time binding');
    } finally { globalThis.fetch = realFetch; }
  }

  // --- A refused connect is retried, not fatal (Linux/macOS only: Windows pipes have no socket
  //     files). A daemon's Unix socket path exists from bind(), a moment before listen(), and a
  //     stale file left by a killed daemon refuses until a restarted one replaces it. Both answer
  //     ECONNREFUSED, which daemonRequest used to give up on at once (agentsafe-signer's own
  //     migrate.smoke.mjs flaked on exactly this in CI). Here a stale socket file refuses until a
  //     REAL daemon takes its path over 300ms later; the signing call must ride that out. ---
  if (process.platform !== 'win32') {
    const staleDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentsafe-guard-daemon-stale-'));
    const stalePath = path.join(staleDir, 'signer.sock');
    const stale = spawn(process.execPath, ['-e', `require('net').createServer().listen(${JSON.stringify(stalePath)}, () => process.kill(process.pid, 'SIGKILL'))`]);
    await new Promise((resolve) => stale.once('exit', resolve));
    check(fs.existsSync(stalePath), 'a stale socket file (no listener) is left behind for the refusal case');

    const late = new SignerDaemon({ stateDir: staleDir, role: 'agent', kek: crypto.randomBytes(32) });
    await late.waitUntilUnlocked();
    const lateRaw = Buffer.from(late.handleAdminRequest({ op: 'generate-key' }).publicKeyHex, 'hex').subarray(-32);
    const lateDid = buildHederaDid('testnet', lateRaw, '0.0.300');
    late.setIdentity(lateDid);
    const listenLater = setTimeout(() => late.startSigningServer(stalePath), 300);

    const nonce = crypto.randomUUID();
    let sig = null;
    let threw = null;
    try {
      sig = await createDaemonKeyProvider({ socketPath: stalePath }).signHandshakeNonce(nonce);
    } catch (err) {
      threw = err;
    }
    clearTimeout(listenLater);
    check(threw === null && verifyDidSignature(lateDid, nonce, sig), `a refused connect is retried until the daemon is listening, then signs${threw ? ` (got: ${threw.message})` : ''}`);
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

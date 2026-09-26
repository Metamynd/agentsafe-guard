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

  // --- Settlement-surface calls signed by the daemon (agentsafe-signer >= 0.16.0 sign-service-call) ---
  // Before this, the daemon provider could not sign a claim, so a daemon-custody Service claimed anonymously and
  // was refused (COUNTERPARTY_AUTH_REQUIRED) for every mainnet hold and for any owner with registered counterparties.
  const ISSUER = 'https://issuer.example/api/v1';
  const escape = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
  const issuerRebuilds = (h, action, authId, fields) =>
    ['MAGP-SERVICE-v1', action, authId, ...fields, h['x-magp-service-nonce'], h['x-magp-service-issued-at']].map(escape).join('|');
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    calls.push({ url: u, headers: opts?.headers ?? {}, body: opts?.body ? JSON.parse(opts.body) : null });
    const data = u.endsWith('/effect/dispatching') ? { agentDid: 'did:key:zAgent', action: 'book', amount: 250, currency: 'USD' } : { captured: true };
    return { ok: true, status: 200, json: async () => ({ success: true, data }) };
  };
  try {
    const signingGuard = createMcpGuard({ serviceDid, keyProvider: 'daemon', daemonSocketPath: socketPath, issuerApi: ISSUER });
    const authId = crypto.randomUUID();
    const claimed = await signingGuard.claimAuthorization({ authorizationId: authId });
    const ch = calls[0]?.headers ?? {};
    check(claimed.claimed === true && claimed.counterpartyAuthenticated === true, 'a daemon-custody Service now claims AUTHENTICATED (was anonymous)');
    check(ch['x-magp-service-did'] === serviceDid && verifyDidSignature(serviceDid, issuerRebuilds(ch, 'claim', authId, [ch['idempotency-key']]), ch['x-magp-service-signature']),
      "the claim's x-magp-service-signature verifies exactly as the issuer rebuilds it, under the Service's own DID");

    const cap = await signingGuard.captureAuthorization({ authorizationId: authId, amountCharged: 200, bookingRef: 'PNR|1', payTo: '0.0.5005' });
    const kh = calls[1]?.headers ?? {};
    check(cap.ok === true && verifyDidSignature(serviceDid, issuerRebuilds(kh, 'capture', authId, ['200', 'PNR|1', '']), kh['x-magp-service-signature']),
      'a lowered capture (with a | in the booking ref) is daemon-signed and verifies; payTo rides unsigned in the body');
    check(calls[1]?.body?.payTo === '0.0.5005', 'capture still sends payTo');

    // A Service whose daemon is down must not quietly fall back to an anonymous call (refused on mainnet anyway,
    // and it would hide the real fault): nothing is sent, and the helpers report SERVICE_SIGNING_FAILED without throwing.
    const before = calls.length;
    const downGuard = createMcpGuard({ serviceDid, keyProvider: 'daemon', daemonSocketPath: path.join(stateDir, 'no-such.sock'), issuerApi: ISSUER });
    const downClaim = await downGuard.claimAuthorization({ authorizationId: crypto.randomUUID() });
    const downCap = await downGuard.captureAuthorization({ authorizationId: authId, amountCharged: 200 });
    const downVoid = await downGuard.releaseAuthorization({ authorizationId: authId, reason: 'x' });
    const downUnknown = await downGuard.markAuthorizationUnknown({ authorizationId: authId, reason: 'x' });
    check(downClaim.claimed === false && downClaim.reasonCode === 'SERVICE_SIGNING_FAILED', 'daemon unreachable: the claim is refused locally as SERVICE_SIGNING_FAILED (not AUTHORIZATION_CLAIM_UNREACHABLE)');
    check([downCap, downVoid, downUnknown].every((r) => r.ok === false && r.reasonCode === 'SERVICE_SIGNING_FAILED'), 'daemon unreachable: capture / release / unknown report SERVICE_SIGNING_FAILED and do not throw');
    check(calls.length === before, 'daemon unreachable: no call reaches the issuer — nothing is sent anonymously');

    // A daemon bound to a DIFFERENT identity than the guard's serviceDid refuses to sign (DAEMON_IDENTITY_MISMATCH).
    const wrongDid = buildHederaDid('testnet', crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), '0.0.201');
    const wrongGuard = createMcpGuard({ serviceDid: wrongDid, keyProvider: 'daemon', daemonSocketPath: socketPath, issuerApi: ISSUER });
    const wrong = await wrongGuard.captureAuthorization({ authorizationId: authId, amountCharged: 1 });
    check(wrong.ok === false && wrong.reasonCode === 'SERVICE_SIGNING_FAILED' && /DAEMON_IDENTITY_MISMATCH|IDENTITY_MISMATCH/.test(wrong.error ?? ''),
      "a serviceDid that is not the daemon's own identity is refused by the daemon, not sent with a signature the issuer would reject");
  } finally {
    globalThis.fetch = realFetch;
  }

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

// passphrase-key.smoke.mjs — proves createGuardFromConfig's passphrase-encrypted managed key
// support (docs/design/passphrase-encrypted-key-delivery-plan.md): a config carrying
// `agentKeyEncrypted` (no plaintext `agentKey`) is decrypted in memory when `{ passphrase }` is
// given, produces a guard that actually signs with the real recovered key, and fails clearly
// when the passphrase is wrong or missing. Byte-compatibility with the REAL backend
// encryptWithPassword is proven separately in backend/src/util/encryption.interop.test.ts — this
// file only needs internally-consistent test ciphertext to exercise createGuardFromConfig's own
// wiring, so it builds that fixture with a local, self-contained encrypt matching the same
// PBKDF2-SHA512 + AES-256-GCM shape decryptAgentKeyWithPassword expects.
//
//   node passphrase-key.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { createGuardFromConfig } from './agentsafe-guard.mjs';
import { verifyDidSignature, buildHederaDid } from './magp-did.mjs';
import { buildAuthMessage } from './policy-core.mjs';

function encryptForTest(plaintext, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from('hedera-data', 'utf8'));
  const encrypted = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
  const tag = cipher.getAuthTag();
  return { ciphertext: `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted}`, salt };
}

let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const agentKeyHex = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const raw = spki.subarray(spki.length - 32);
const agentDid = buildHederaDid('testnet', raw, '0.0.1');
const passphrase = 'correct horse battery staple';
const { ciphertext, salt } = encryptForTest(agentKeyHex, passphrase);

/** Verifies a signed request the same way a trustless counterparty would: rebuild the
 *  canonical message from the object it received, then check it against the claimed DID. */
function signatureVerifies(signed) {
  const message = buildAuthMessage(signed);
  return verifyDidSignature(signed.agentDid, message, signed.signature);
}

async function main() {
  console.log('— passphrase-encrypted managed key —');
  {
    const cfg = { apiBase: 'https://issuer.example/api/v1', agentDid, agentKey: null, agentKeyEncrypted: { ciphertext, salt } };
    const guard = await createGuardFromConfig(cfg, { passphrase });
    // Prove the RECOVERED key is the real one, not a stand-in: a locally-built signed request
    // must verify against the agent's own DID (key-in-DID), the same check a real Service runs.
    const signed = await guard.buildSignedRequest({ action: 'read-report', amount: 0 });
    ok(signatureVerifies(signed), 'the decrypted key produces a signature that verifies against the agent\'s real DID');
  }

  console.log('\n— wrong passphrase is refused, not silently miscrypted —');
  {
    const cfg = { apiBase: 'https://issuer.example/api/v1', agentDid, agentKey: null, agentKeyEncrypted: { ciphertext, salt } };
    let threw = null;
    try { await createGuardFromConfig(cfg, { passphrase: 'not-the-right-passphrase' }); } catch (e) { threw = e; }
    ok(!!threw, 'a wrong passphrase throws instead of producing a guard');
  }

  console.log('\n— missing passphrase gets a clear, specific error —');
  {
    const cfg = { apiBase: 'https://issuer.example/api/v1', agentDid, agentKey: null, agentKeyEncrypted: { ciphertext, salt } };
    let message = null;
    try { await createGuardFromConfig(cfg); } catch (e) { message = e.message; }
    ok(/passphrase-encrypted.*pass \{ passphrase \}/i.test(message ?? ''), 'the error names the fix, not a generic "requires agentKey" message', message);
  }

  console.log('\n— a plaintext config (no agentKeyEncrypted) is unaffected —');
  {
    const cfg = { apiBase: 'https://issuer.example/api/v1', agentDid, agentKey: agentKeyHex, agentKeyEncrypted: null };
    const guard = await createGuardFromConfig(cfg);
    const signed = await guard.buildSignedRequest({ action: 'read-report', amount: 0 });
    ok(signatureVerifies(signed), 'a plaintext-key config still builds a guard that signs correctly, unchanged');
  }

  console.log('\n— an explicit { agentKey } override wins over agentKeyEncrypted, no passphrase needed —');
  {
    const otherKeyPair = crypto.generateKeyPairSync('ed25519');
    const otherKeyHex = otherKeyPair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
    const cfg = { apiBase: 'https://issuer.example/api/v1', agentDid, agentKey: null, agentKeyEncrypted: { ciphertext, salt } };
    const guard = await createGuardFromConfig(cfg, { agentKey: otherKeyHex });
    ok(!!guard, 'an explicit agentKey override does not require a passphrase');
  }

  if (failed) {
    console.error(`\n${failed} case(s) FAILED`);
    process.exit(1);
  }
  console.log('\nPASS — createGuardFromConfig decrypts a passphrase-protected managed key correctly, and fails clearly when it cannot.');
}

main().catch((e) => { console.error('ERROR', e); process.exit(1); });

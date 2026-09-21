// key-providers.mjs — the keyProvider seam (docs/design/agent-key-custody-local-signer-daemon-plan.md).
// A KeyProvider has four REQUIRED async methods, matching the four places this package always
// signs something (see agentsafe-guard.mjs: buildSignedRequest/authorize, the opt-in envelope
// signature, the mutual-handshake PROVE step, and BYOK key-control-proof) — every built-in
// provider implements all four, and a caller's own plain-object provider must too. `signLocalDecision`
// is a FIFTH, OPTIONAL method (both built-in providers implement it — see agentsafe-guard.mjs's
// authorizeLocal(), which checks for it before attempting to report a local decision) — a
// caller's own plain-object provider that omits it simply doesn't get that audit-visibility
// enhancement, with no change to its existing behavior otherwise.
import crypto from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import { buildAuthMessage, buildLocalDecisionMessage } from './policy-core.mjs';
import { envelopeHashFor } from './governance-envelope.mjs';
import { buildPayloadBindingMessage, buildPayloadRebindMessage } from './payload-binding.mjs';

/**
 * Today's default: the raw key lives in THIS process (see the design doc's "What this does not
 * do" for the confidentiality tradeoff that implies). Builds each canonical message locally with
 * the same policy-core/governance-envelope functions the backend verifies against, then signs.
 */
export function createStaticKeyProvider(agentKeyHex) {
  const privateKey = crypto.createPrivateKey({ key: Buffer.from(agentKeyHex, 'hex'), format: 'der', type: 'pkcs8' });
  const rawSign = (message) => crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('hex');
  return {
    async signAuthorize(fields) {
      return rawSign(buildAuthMessage(fields));
    },
    async signEnvelope(fields) {
      return rawSign(envelopeHashFor({ ...fields, signature: '' }));
    },
    async signHandshakeNonce(nonce) {
      return rawSign(nonce);
    },
    async signKeyControlChallenge(challengeHex) {
      return rawSign(challengeHex);
    },
    async signLocalDecision(fields) {
      return rawSign(buildLocalDecisionMessage(fields));
    },
    // Payload binding (spec 8.3.9): sign the digest of the COMPLETE payload, bound to this authorization. OPTIONAL like
    // signLocalDecision; the guard refuses (fail closed) to send an unbound request when a binding was asked for and the
    // provider cannot produce one. With an `authorizationId` it signs the LATE binding of a hold that already exists (8.3.11).
    async signPayloadBinding(fields) {
      return rawSign(fields.authorizationId === undefined ? buildPayloadBindingMessage(fields) : buildPayloadRebindMessage(fields));
    },
  };
}

/**
 * Same platform/path translation the signer daemon itself uses (integrations/agentsafe-signer/
 * daemon.mjs's toPlatformSocketPath) — must stay identical or client and server compute different
 * pipe names on Windows and never connect. Duplicated rather than imported: this package has no
 * dependency (workspace or npm) on agentsafe-signer, by design (see that package's own README).
 */
function toPlatformSocketPath(logicalPath) {
  if (process.platform !== 'win32') return logicalPath;
  const name = crypto.createHash('sha256').update(path.resolve(logicalPath)).digest('hex').slice(0, 32);
  return `\\\\.\\pipe\\agentsafe-signer-${name}`;
}

const PROTOCOL_VERSION = 1;

function daemonRequest(socketPath, op, params, { connectTimeoutMs = 3000 } = {}) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + connectTimeoutMs;
    function attempt() {
      const sock = net.connect(toPlatformSocketPath(socketPath));
      const requestId = crypto.randomUUID();
      let buf = '';
      const cleanup = () => sock.destroy();
      sock.once('error', (err) => {
        cleanup();
        // On Windows the signing socket is a pool of independent named-pipe instances (see
        // agentsafe-signer/windows-secure-pipe.mjs): each instance is consumed by exactly one
        // connection, then replaced asynchronously. Two requests arriving close enough together
        // can race that replacement window and transiently find zero live instances (ENOENT) even
        // though the daemon itself is up and healthy. Retrying briefly is the same tolerance any
        // client of a local, independently-started daemon needs — not a workaround for a broken
        // invariant — and matches only ENOENT so a daemon that is genuinely down still fails fast.
        if (err.code === 'ENOENT' && Date.now() < deadline) {
          setTimeout(attempt, 20);
          return;
        }
        reject(Object.assign(new Error(`agentsafe-signer daemon unreachable at ${socketPath}: ${err.message}`), { code: 'DAEMON_UNREACHABLE' }));
      });
      sock.once('connect', () => {
        sock.write(JSON.stringify({ protocolVersion: PROTOCOL_VERSION, requestId, op, params }) + '\n');
      });
      sock.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        const idx = buf.indexOf('\n');
        if (idx === -1) return;
        let res;
        try {
          res = JSON.parse(buf.slice(0, idx));
        } catch (err) {
          cleanup();
          reject(err);
          return;
        }
        cleanup();
        if (res.ok) resolve(res.result);
        else reject(Object.assign(new Error(res.error?.message || res.error?.code || 'daemon rejected request'), { code: res.error?.code }));
      });
    }
    attempt();
  });
}

/**
 * The key never enters this process at all — every signature is produced by a separate
 * agentsafe-signer daemon over a local socket, which builds the canonical message itself from
 * these structured fields (never a pre-built string) and returns only the signature.
 */
export function createDaemonKeyProvider({ socketPath }) {
  if (!socketPath) throw new Error('createDaemonKeyProvider requires { socketPath }');
  return {
    async signAuthorize(fields) {
      const { signature } = await daemonRequest(socketPath, 'sign-authorize', fields);
      return signature;
    },
    async signEnvelope(fields) {
      const { envelopeSignature } = await daemonRequest(socketPath, 'sign-envelope', fields);
      return envelopeSignature;
    },
    async signHandshakeNonce(nonce) {
      const { signature } = await daemonRequest(socketPath, 'sign-handshake-nonce', { nonce });
      return signature;
    },
    async signKeyControlChallenge(challengeHex) {
      const { signature } = await daemonRequest(socketPath, 'sign-key-control-challenge', { challenge: challengeHex });
      return signature;
    },
    async signLocalDecision(fields) {
      const { signature } = await daemonRequest(socketPath, 'sign-local-decision', fields);
      return signature;
    },
    // The daemon builds every message it signs from structured fields and will not sign arbitrary bytes, so payload binding
    // is its own operation there (`sign-payload`, signer 0.15.0). A daemon that predates it answers DAEMON_UNKNOWN_OPERATION:
    // that is reported as what it means — this signer cannot bind a payload — and a guard asked to bind must then FAIL CLOSED,
    // never fall back to sending the request unbound.
    async signPayloadBinding(fields) {
      try {
        const { signature } = await daemonRequest(socketPath, 'sign-payload', fields);
        return signature;
      } catch (err) {
        if (err?.code === 'DAEMON_UNKNOWN_OPERATION') {
          throw Object.assign(new Error('the agentsafe-signer daemon predates payload binding (sign-payload, signer 0.15.0); upgrade it, or omit `payload`'), { code: 'PAYLOAD_BINDING_UNSUPPORTED' });
        }
        throw err;
      }
    },
  };
}

/**
 * Passphrase-encrypted key delivery (docs/design/passphrase-encrypted-key-delivery-plan.md).
 * A byte-for-byte reimplementation of the backend's `decryptWithPassword`
 * (backend/src/util/encryption.ts) using only node:crypto — PBKDF2-SHA512/100k-iterations/
 * 32-byte key derived from (password, salt), then AES-256-GCM decrypt of the `iv:tag:encrypted`
 * hex-joined triple `encryptWithPassword` produces. MUST stay in lockstep with that function:
 * two independently-written implementations of "the same algorithm" silently diverging is
 * exactly the class of bug buildSignedRequest's bothOmitted case already caught once in this
 * package — see daemon-keyprovider.smoke.mjs's own cross-package pattern for why this is tested
 * against real backend-produced ciphertext, not just self-consistently.
 * @param {string} ciphertext  encryptWithPassword()'s combined "iv:tag:encrypted" hex string
 * @param {string} password    the operator's passphrase — never persisted, used only here
 * @param {string} salt        the salt returned alongside `ciphertext` at issuance time
 * @returns {string} the decrypted plaintext (the agent's private key hex)
 */
export function decryptAgentKeyWithPassword(ciphertext, password, salt) {
  const parts = String(ciphertext).split(':');
  if (parts.length !== 3) throw new Error('decryptAgentKeyWithPassword: invalid encrypted data format');
  const [ivHex, tagHex, encryptedHex] = parts;
  // Matches deriveKeyFromPassword exactly: salt is passed as-is (its own hex STRING, UTF-8
  // encoded by pbkdf2Sync's default), not decoded from hex to raw bytes first.
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAAD(Buffer.from('hedera-data', 'utf8'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return decipher.update(encryptedHex, 'hex', 'utf8') + decipher.final('utf8');
}

/** Resolves `opts.keyProvider`/`opts.agentKey` into a concrete KeyProvider for createGuard(). */
export function resolveKeyProvider(opts, cfg) {
  const kp = opts.keyProvider ?? cfg?.keyProvider;
  if (kp && typeof kp === 'object' && typeof kp.signAuthorize === 'function') return kp;
  if (kp === 'daemon' || (kp && typeof kp === 'object' && kp.type === 'daemon')) {
    const socketPath = opts.daemonSocketPath ?? cfg?.daemonSocketPath ?? (kp && kp.socketPath);
    return createDaemonKeyProvider({ socketPath });
  }
  const agentKey = opts.agentKey ?? cfg?.agentKey;
  if (!agentKey) throw new Error("createGuard requires a keyProvider, or { agentKey } for the default 'staticKey' provider");
  return createStaticKeyProvider(agentKey);
}

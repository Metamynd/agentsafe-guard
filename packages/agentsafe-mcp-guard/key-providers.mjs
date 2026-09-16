// key-providers.mjs — the keyProvider seam for the SERVICE side (docs/design/
// agent-key-custody-local-signer-daemon-plan.md). Much smaller than agentsafe-guard's own copy:
// serviceKey is only ever used for one thing (signing a handshake nonce, MAGP §8.2), so there is
// only one provider method here, not four.
import crypto from 'node:crypto';
import net from 'node:net';
import path from 'node:path';

export function createStaticKeyProvider(serviceKeyHex) {
  const privateKey = crypto.createPrivateKey({ key: Buffer.from(serviceKeyHex, 'hex'), format: 'der', type: 'pkcs8' });
  return {
    async signHandshakeNonce(nonce) {
      return crypto.sign(null, Buffer.from(nonce, 'utf8'), privateKey).toString('hex');
    },
  };
}

/** Must match agentsafe-guard/key-providers.mjs's and agentsafe-signer/daemon.mjs's own copy — see either's own comment for why this isn't a shared import. */
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
        // See agentsafe-guard/key-providers.mjs's own copy of this function for why: on Windows
        // the signing socket is a pool of independent named-pipe instances, each consumed by one
        // connection and replaced asynchronously, so a request can transiently race that
        // replacement window (ENOENT) even though the daemon is healthy. Only ENOENT retries — a
        // genuinely down daemon still fails fast.
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

/** The key never enters this process — a service-role agentsafe-signer daemon signs instead. */
export function createDaemonKeyProvider({ socketPath }) {
  if (!socketPath) throw new Error('createDaemonKeyProvider requires { socketPath }');
  return {
    async signHandshakeNonce(nonce) {
      const { signature } = await daemonRequest(socketPath, 'sign-handshake-nonce', { nonce });
      return signature;
    },
  };
}

/** Resolves a keyProvider from createMcpGuard's opts — null (not thrown) when neither
 *  keyProvider nor serviceKey is configured, matching today's "handshakeChallenge throws only if
 *  actually called without one" behavior rather than failing construction eagerly. */
export function resolveKeyProvider({ keyProvider, serviceKey, daemonSocketPath } = {}) {
  if (keyProvider && typeof keyProvider === 'object' && typeof keyProvider.signHandshakeNonce === 'function') return keyProvider;
  if (keyProvider === 'daemon') return createDaemonKeyProvider({ socketPath: daemonSocketPath });
  if (!serviceKey) return null;
  return createStaticKeyProvider(serviceKey);
}

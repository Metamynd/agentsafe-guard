// byok-daemon.smoke.mjs — proves --byok --daemon-socket end to end against a REAL running
// agentsafe-signer daemon (spawned as its own subprocess, matching agentsafe-signer's own
// migrate.smoke.mjs pattern) and a small fake backend that independently, cryptographically
// verifies the submitted signature — not just that some string arrived. This is the one place
// this new code path is exercised against a real daemon rather than trusted from reading the
// code: the exact class of bug this whole effort has repeatedly found only shows up when two
// sides are actually wired together (see agentsafe-signer/README.md's own history of this).
//
//   node byok-daemon.smoke.mjs
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CLI_PATH = path.join(process.cwd(), 'index.mjs');
const SIGNER_CLI_PATH = fileURLToPath(new URL('../agentsafe-signer/cli.mjs', import.meta.url));

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** A minimal fake MetaMynd backend implementing just the three routes this flow calls. Verifies
 *  the submitted verify-key signature FOR REAL against the publicKey the daemon generated (both
 *  are SPKI DER hex Ed25519 — the same format agentsafe-signer's keystore.mjs and this CLI's own
 *  generateAgentKeypair() both use), so a wrong-encoding or wrong-message bug is actually caught
 *  here, not just trusted. */
function startFakeBackend() {
  const received = { onboardBody: null, verifyBody: null };
  let mintedPublicKeyHex = null;
  const challenge = crypto.randomBytes(24).toString('hex');
  const identityId = 'identity-1';

  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    const json = body ? JSON.parse(body) : {};

    if (req.url === '/auth/login') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'ok', data: { accessToken: 'test-token' } }));
      return;
    }

    if (req.url === '/onboarding/agent') {
      received.onboardBody = json;
      mintedPublicKeyHex = json.publicKey;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          success: true,
          message: 'ok',
          data: {
            agentDid: 'did:key:zTestDaemonByok',
            identityId,
            mandate: { scope: json.scope },
            perTxnMax: json.perTxnMax,
            standards: [],
            challenge,
          },
        }),
      );
      return;
    }

    if (req.url === `/agent-identity/${identityId}/verify-key`) {
      received.verifyBody = json;
      let ok = false;
      try {
        const pub = crypto.createPublicKey({ key: Buffer.from(mintedPublicKeyHex, 'hex'), format: 'der', type: 'spki' });
        ok = crypto.verify(null, Buffer.from(challenge, 'utf8'), pub, Buffer.from(json.signature, 'hex'));
      } catch {
        ok = false;
      }
      res.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' });
      res.end(JSON.stringify(ok ? { success: true, message: 'ok', data: { verified: true } } : { success: false, message: 'signature invalid' }));
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: false, message: 'not found' }));
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, received, apiUrl: `http://127.0.0.1:${port}` });
    });
  });
}

/** Spawns the real agentsafe-signer daemon CLI as its own OS process — see that package's own
 *  migrate.smoke.mjs for why (in-process multi-daemon pipe contention caused real hangs there). */
function spawnDaemon(stateDir) {
  const child = spawn(
    process.execPath,
    [SIGNER_CLI_PATH, 'start', '--state-dir', stateDir, '--role', 'agent', '--admin', '--admin-timeout', '10000', '--kek-backend', 'passphrase'],
    { env: { ...process.env, AGENTSAFE_SIGNER_PASSPHRASE: 'byok-daemon-smoke-test-passphrase' }, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let stdout = '';
  let stderr = '';
  const readyWaiters = [];
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString('utf8');
    if (/admin socket open/.test(stdout)) while (readyWaiters.length) readyWaiters.shift()();
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString('utf8');
  });
  const ready = new Promise((resolve, reject) => {
    if (/admin socket open/.test(stdout)) return resolve();
    const timer = setTimeout(() => reject(new Error(`daemon never reached "admin socket open" within 15s.\nstdout:\n${stdout}\nstderr:\n${stderr}`)), 15_000);
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`daemon exited early (code ${code}) before "admin socket open".\nstdout:\n${stdout}\nstderr:\n${stderr}`));
    });
    readyWaiters.push(() => {
      clearTimeout(timer);
      resolve();
    });
  });
  return { child, ready, getStderr: () => stderr };
}

/** Runs the CLI as a genuine async subprocess (never execFileSync — the CLI's own fetch() calls
 *  back into THIS process's fake HTTP server below, and a synchronous, blocking spawn would
 *  freeze the event loop that server needs to ever respond, deadlocking both sides). Bounded by
 *  its own timeout so a real hang fails the test instead of the whole run. */
function runCli(args, { timeoutMs = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString('utf8'); });
    child.stderr.on('data', (c) => { stderr += c.toString('utf8'); });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`create-metamynd-agent did not exit within ${timeoutMs}ms.\nstdout:\n${stdout}\nstderr:\n${stderr}`));
    }, timeoutMs);
    child.once('exit', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`create-metamynd-agent exited with code ${code}.\nstdout:\n${stdout}\nstderr:\n${stderr}`));
    });
  });
}

function stopDaemon(child) {
  if (child.exitCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    child.once('exit', resolve);
    child.kill();
  });
}

async function main() {
  const daemonStateDir = tmpDir('agentsafe-signer-byok-smoke-');
  const socketPath = path.join(daemonStateDir, 'signer.sock');
  const adminSocketPath = path.join(daemonStateDir, 'signer-admin.sock');
  const { child, ready, getStderr } = spawnDaemon(daemonStateDir);
  const { server, received, apiUrl } = await startFakeBackend();
  const outDir = tmpDir('create-metamynd-agent-byok-smoke-');

  try {
    await ready;
    await runCli([
      '--byok',
      '--daemon-socket', socketPath,
      '--daemon-admin-socket', adminSocketPath,
      '--api', apiUrl,
      '--email', 'owner@example.com',
      '--password', 'irrelevant',
      '--name', 'Daemon BYOK Smoke Test',
      '--scope', 'flight-purchase',
      '--out', outDir,
      '--yes',
    ]);
  } catch (err) {
    check(false, `scaffold command itself failed — ${err.message.slice(0, 800)}`);
    console.error(`daemon stderr:\n${getStderr()}`);
    server.close();
    await stopDaemon(child);
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.rmSync(daemonStateDir, { recursive: true, force: true });
    process.exit(1);
  }

  server.close();
  await stopDaemon(child);

  const config = JSON.parse(fs.readFileSync(path.join(outDir, 'agent.metamynd.json'), 'utf8'));
  check(!!received.onboardBody?.publicKey, 'the onboarding request carried the daemon-generated publicKey');
  check(!!received.verifyBody?.signature, 'a real verify-key request followed, carrying a real signature');
  check(config.keyProvider === 'daemon', 'agent.metamynd.json sets keyProvider: "daemon"');
  check(config.daemonSocketPath === socketPath, 'agent.metamynd.json points at the real daemon socket used');
  check(!('agentKey' in config), 'agent.metamynd.json holds NO plaintext agentKey field at all');
  check(config.keyVerified === true, 'agent.metamynd.json records the key as verified');
  check(!('challenge' in config), 'the one-time challenge is not left lying around after verification');

  const readme = fs.readFileSync(path.join(outDir, 'README.md'), 'utf8');
  check(readme.includes('Holds no secret key'), 'the generated README correctly says this config holds no secret key');

  fs.rmSync(outDir, { recursive: true, force: true });
  fs.rmSync(daemonStateDir, { recursive: true, force: true });

  if (failed) {
    console.error(`\n${failed} case(s) FAILED`);
    process.exit(1);
  }
  console.log('\nPASS — --byok --daemon-socket generates via, and proves control through, a real agentsafe-signer daemon — no plaintext key ever written.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

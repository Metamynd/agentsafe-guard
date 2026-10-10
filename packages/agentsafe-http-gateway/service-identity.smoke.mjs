// service-identity.smoke.mjs — the gateway's own identity without hand-written key code (pre-beta 2026-10-09, M4):
// `service-id` makes a did:key + key file, `accept-challenge` signs the dashboard's registration challenge with it, and the
// signature verifies against the DID exactly as the issuer checks it.
//
//   node service-identity.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyDidSignature } from '@metamynd/agentsafe-mcp-guard/did';
import { acceptChallenge, checkServiceIdentity, createServiceIdentity, readServiceIdentity, writeServiceIdentity } from './service-identity.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, 'cli.mjs');
const dir = mkdtempSync(join(tmpdir(), 'svc-id-'));
const t = [];
const test = (name, fn) => t.push([name, fn]);

// The issuer's challenge format (backend counterparty-proof.ts buildAcceptMessage): each field escaped (\ then |), joined by |.
const escape = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
const challengeFor = (did, over = {}) => {
  const f = { prefix: 'MAGP-COUNTERPARTY-ACCEPT-v1', registrant: 'did:hedera:testnet:zOwner_0.0.1', did, purpose: 'claim', nonce: crypto.randomBytes(18).toString('base64url'), expiresAt: new Date(Date.now() + 600_000).toISOString(), ...over };
  return [f.prefix, f.registrant, f.did, f.purpose, f.nonce, f.expiresAt].map(escape).join('|');
};
const cli = (args, input) => execFileSync(process.execPath, [CLI, ...args], { cwd: dir, input, encoding: 'utf8', env: { ...process.env, SERVICE_DID: '', SERVICE_KEY: '', SERVICE_IDENTITY_FILE: '' } });

test('createServiceIdentity: a did:key whose key is the private key', () => {
  const id = createServiceIdentity();
  assert.match(id.serviceDid, /^did:key:z6Mk/);
  assert.doesNotThrow(() => checkServiceIdentity(id));
});

test('a key that does not belong to the DID is refused', () => {
  const a = createServiceIdentity();
  const b = createServiceIdentity();
  assert.throws(() => checkServiceIdentity({ serviceDid: a.serviceDid, serviceKey: b.serviceKey }), /does not belong/);
  assert.throws(() => checkServiceIdentity({ serviceDid: 'did:hedera:testnet:zX_0.0.1', serviceKey: a.serviceKey }), /did:key/);
});

test('write then read round-trips; an existing file is not overwritten without force', () => {
  const p = join(dir, 'id-a.json');
  const id = createServiceIdentity();
  writeServiceIdentity(p, id);
  assert.equal(readServiceIdentity(p).serviceDid, id.serviceDid);
  assert.throws(() => writeServiceIdentity(p, createServiceIdentity()), /already exists/);
  writeServiceIdentity(p, createServiceIdentity(), { force: true });
  assert.notEqual(readServiceIdentity(p).serviceDid, id.serviceDid);
  if (process.platform !== 'win32') assert.equal(statSync(p).mode & 0o777, 0o600);
});

test('acceptChallenge signs the registration challenge; the signature verifies against the DID', async () => {
  const id = createServiceIdentity();
  const m = challengeFor(id.serviceDid);
  const sig = await acceptChallenge(id, m);
  assert.match(sig, /^[0-9a-f]{128}$/);
  assert.ok(verifyDidSignature(id.serviceDid, m, sig));
});

test('a challenge for another DID is refused (the signature cannot be lifted)', async () => {
  const id = createServiceIdentity();
  await assert.rejects(() => acceptChallenge(id, challengeFor('did:key:z6MkOther')), /not this Service/);
});

test('CLI: service-id writes the file and prints the DID; accept-challenge signs from the file, by argument or stdin', () => {
  const out = cli(['service-id', '--out', 'gw.json']);
  const id = JSON.parse(readFileSync(join(dir, 'gw.json'), 'utf8'));
  assert.ok(out.includes(id.serviceDid), out);
  const m = challengeFor(id.serviceDid);
  const byArg = cli(['accept-challenge', '--identity', 'gw.json', m]).trim();
  assert.ok(verifyDidSignature(id.serviceDid, m, byArg));
  const byStdin = cli(['accept-challenge', '--identity', 'gw.json'], m + '\n').trim();
  assert.ok(verifyDidSignature(id.serviceDid, m, byStdin));
});

test('CLI: a second service-id refuses to replace the key; a broken identity file is reported, not signed with', () => {
  assert.throws(() => cli(['service-id', '--out', 'gw.json']), (e) => e.status === 1 && /already exists/.test(String(e.stderr)));
  writeFileSync(join(dir, 'bad.json'), '{"serviceDid":"did:key:z6MkNope","serviceKey":"00"}');
  assert.throws(() => cli(['accept-challenge', '--identity', 'bad.json', 'x']), (e) => e.status === 1);
});

let failed = 0;
for (const [name, fn] of t) {
  try {
    await fn();
    console.log(`ok    ${name}`);
  } catch (err) {
    failed++;
    console.log(`FAIL  ${name}\n      ${err?.message ?? err}`);
  }
}
rmSync(dir, { recursive: true, force: true });
if (failed) {
  console.log(`\n${failed} failed`);
  process.exit(1);
}
console.log(`\nPASS — ${t.length} service identity cases.`);

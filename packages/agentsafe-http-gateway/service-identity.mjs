// service-identity.mjs — the gateway's own identity: a did:key and the Ed25519 key it signs claims, reports and its
// counterparty acceptance with. Zero dependencies beyond agentsafe-mcp-guard.
//
// Putting a payment tool behind the gateway (so the API key lives with the gateway, never with the agent) used to take a
// hand-written did:key encoder and a signature produced in a REPL (pre-beta evaluation 2026-10-09, M4). This is that,
// once: `createServiceIdentity()` makes one, `writeServiceIdentity()` / `readServiceIdentity()` keep it in a file the
// server reads (SERVICE_IDENTITY_FILE), and `acceptChallenge()` signs the dashboard's registration challenge with it.

import crypto from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { buildDidKey, parseDidKey } from '@metamynd/agentsafe-mcp-guard/did';
import { createMcpGuard } from '@metamynd/agentsafe-mcp-guard';

export const SERVICE_IDENTITY_FORMAT = 'metamynd-service-identity/1';

/** A fresh identity: `serviceDid` (did:key) and `serviceKey` (PKCS#8 DER hex), the shapes SERVICE_DID / SERVICE_KEY take. */
export function createServiceIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return {
    format: SERVICE_IDENTITY_FORMAT,
    serviceDid: buildDidKey(spki.subarray(spki.length - 32)),
    serviceKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex'),
    createdAt: new Date().toISOString(),
  };
}

/** The public key the DID names, from the private key — so a file whose key does not match its DID is refused. */
function didOf(serviceKeyHex) {
  const key = crypto.createPrivateKey({ key: Buffer.from(serviceKeyHex, 'hex'), format: 'der', type: 'pkcs8' });
  const spki = crypto.createPublicKey(key).export({ type: 'spki', format: 'der' });
  return buildDidKey(spki.subarray(spki.length - 32));
}

/** Validate an identity object: a did:key whose key is the private key's own public key. Throws with what is wrong. */
export function checkServiceIdentity(id) {
  if (!id || typeof id !== 'object') throw new Error('service identity: not an object');
  if (typeof id.serviceDid !== 'string' || !id.serviceDid.startsWith('did:key:')) throw new Error('service identity: serviceDid must be a did:key');
  parseDidKey(id.serviceDid); // throws on a malformed did:key
  if (typeof id.serviceKey !== 'string' || !/^[0-9a-fA-F]+$/.test(id.serviceKey)) throw new Error('service identity: serviceKey must be PKCS#8 DER hex');
  let derived;
  try {
    derived = didOf(id.serviceKey);
  } catch {
    throw new Error('service identity: serviceKey is not an Ed25519 PKCS#8 key');
  }
  if (derived !== id.serviceDid) throw new Error('service identity: serviceKey does not belong to serviceDid');
  return id;
}

/** Write an identity to `path`, readable by the owner only. Refuses to overwrite unless `force`: a replaced key is a new gateway. */
export function writeServiceIdentity(path, id, { force = false } = {}) {
  if (existsSync(path) && !force) throw new Error(`${path} already exists — it holds a gateway identity; pass --force to replace it (the old DID stops being yours to sign as)`);
  writeFileSync(path, JSON.stringify(checkServiceIdentity(id), null, 2) + '\n', { mode: 0o600 });
  try {
    chmodSync(path, 0o600); // an existing file keeps its mode under writeFileSync
  } catch {
    // a filesystem without POSIX modes (Windows): the ACL is the operator's
  }
  return path;
}

export function readServiceIdentity(path) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    throw new Error(`cannot read the service identity file ${path}: ${err?.message ?? err}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${path} is not JSON`);
  }
  return checkServiceIdentity(parsed);
}

/**
 * Sign the registration challenge Trusted Counterparties shows (MAGP-COUNTERPARTY-ACCEPT-v1) as this identity. The guard
 * signs only that message, for this DID, unexpired and for a known purpose, so the signature cannot be lifted onto anything
 * else. Returns the 128-hex signature to paste back into the dashboard.
 */
export async function acceptChallenge(identity, message) {
  const { serviceDid, serviceKey } = checkServiceIdentity(identity);
  // This guard only signs; it never serves a request. Its construction warnings (allowedAgents 'any', no policy key) are
  // about serving, and printed by `accept-challenge` they read as a misconfigured gateway. Muted for the construction only.
  const warn = console.warn;
  let guard;
  console.warn = () => {};
  try {
    guard = createMcpGuard({ serviceDid, serviceKey, allowedAgents: 'any', fetchBundle: async () => ({}) });
  } finally {
    console.warn = warn;
  }
  return guard.acceptCounterpartyChallenge(String(message).trim());
}

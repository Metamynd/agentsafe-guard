// accept-challenge.smoke.mjs — counterparty proof of control (MAGP §8.7.6; Gateway Authority Refinement Plan, phase 2). An
// owner used to register any DID as its counterparty on the DID's text alone — how an attacker had a victim's gateway claim
// and run the attacker's hold (XT-1). Now the service signs an acceptance the owner obtained from the issuer:
//
//   MAGP-COUNTERPARTY-ACCEPT-v1 | registrant | serviceDid | purpose | nonce | expiresAt
//
// `guard.acceptCounterpartyChallenge(message)` signs exactly that, for this Service's own DID, an unexpired time and a known
// purpose — never anything else, so it cannot be used to obtain this Service's signature on some other message.
//
//   node accept-challenge.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildDidKey, verifyDidSignature } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const serviceDid = buildDidKey(spki.subarray(spki.length - 32));
const serviceKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
const guard = createMcpGuard({ serviceDid, serviceKey, allowedAgents: 'any', fetchBundle: async () => ({}) });
// The issuer's format (backend counterparty-proof.ts buildAcceptMessage): each field escaped (\ then |), joined by |.
const escape = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
const message = (over = {}) => {
  const f = { prefix: 'MAGP-COUNTERPARTY-ACCEPT-v1', registrant: 'did:hedera:testnet:zOwner_0.0.1', did: serviceDid, purpose: 'claim', nonce: crypto.randomBytes(18).toString('base64url'), expiresAt: new Date(Date.now() + 600_000).toISOString(), ...over };
  return [f.prefix, f.registrant, f.did, f.purpose, f.nonce, f.expiresAt].map(escape).join('|');
};

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('signs a valid acceptance for this Service, verifiable with the key in its DID (what the issuer checks)', async () => {
  const m = message();
  const sig = await guard.acceptCounterpartyChallenge(m);
  assert.ok(verifyDidSignature(serviceDid, m, sig));
});

test('a registrant with escaped characters still parses as six fields', async () => {
  const m = message({ registrant: 'odd|owner\\name' });
  assert.ok(verifyDidSignature(serviceDid, m, await guard.acceptCounterpartyChallenge(m)));
});

test('refuses a challenge naming another Service (an owner cannot make this Service accept for someone else)', async () => {
  await assert.rejects(() => guard.acceptCounterpartyChallenge(message({ did: 'did:key:z6MkOther' })), /not this Service/);
});

test('refuses anything that is not an acceptance message — no signing oracle', async () => {
  for (const m of ['MAGP-SERVICE-v1|claim|x|y|nonce|2026-01-01T00:00:00Z', 'hello', message({ prefix: 'MAGP-COUNTERPARTY-ACCEPT-v2' }), message() + '|extra']) {
    await assert.rejects(() => guard.acceptCounterpartyChallenge(m), /refusing to sign/);
  }
});

test('refuses an unknown purpose and an expired challenge', async () => {
  await assert.rejects(() => guard.acceptCounterpartyChallenge(message({ purpose: 'admin' })), /unknown purpose/);
  await assert.rejects(() => guard.acceptCounterpartyChallenge(message({ expiresAt: new Date(Date.now() - 1000).toISOString() })), /expired/);
});

test('without a serviceKey it says so instead of signing', async () => {
  const keyless = createMcpGuard({ serviceDid, allowedAgents: 'any', fetchBundle: async () => ({}) });
  await assert.rejects(() => keyless.acceptCounterpartyChallenge(message()), /serviceKey/);
});

const quiet = console.warn; console.warn = () => {};
let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
console.warn = quiet;
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} acceptCounterpartyChallenge cases.`);

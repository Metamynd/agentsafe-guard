// governance-headers.smoke.mjs — decision.governanceHeaders(): the headers a guarded Node tool hands a gateway (0.31.0;
// pre-beta rerun 5, FW N-3).
//
// Before: a Node guardTool handler received only the decision, so calling a gateway meant rebuilding and re-signing the
// request by hand (about a dozen lines in every scaffold) — Python's guarded tools have governance_headers(). Now the
// decision a tool receives carries governanceHeaders(): the same request, freshly signed with its payload bound, and the
// authorization the call was granted.
//
//   node governance-headers.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildPayloadBindingMessage, payloadDigestOf, toWireJson } from './payload-binding.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createGuard } from './agentsafe-guard.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const agentDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.703');
const agentKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
const verifies = (message, sigHex) => crypto.verify(null, Buffer.from(message, 'utf8'), publicKey, Buffer.from(sigHex, 'hex'));

const AUTH = crypto.randomUUID();
const real = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  const reply = (data, status = 200) => ({ ok: status < 400, status, json: async () => ({ success: status < 400, data }) });
  if (u.endsWith('/policy/mandate/authorize')) {
    // A current issuer echoes the payload digest it bound the hold to.
    const sent = JSON.parse(init.body);
    return reply({ decision: 'allow', reasonCode: 'AUTHORIZED', authorizationId: AUTH, eventId: 'e1', payloadDigest: sent.payloadDigest });
  }
  if (u.endsWith('/effect')) return reply({ outcome: 'not_started', effectState: 'authorized' });
  return reply({ captured: true });
};

const guard = createGuard({ api: 'http://issuer.test/api/v1', agentDid, agentKey, mode: 'remote', settle: 'none' });
const payloadOf = (a) => ({ amount: a.amount, merchant: a.merchant, currency: 'USD' });
const mapArgs = (a) => ({ amount: a.amount, currency: 'USD', merchant: a.merchant, context: { tool: 'book-flight', riskLevel: 'low' }, payload: payloadOf(a) });

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`ok    ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.stack ?? e.message}`); }
}

let seen;
const tool = guard.guardTool('flight-purchase', async (args, decision) => {
  seen = { decision, headers: await decision.governanceHeaders() };
  return 'booked';
}, mapArgs);
await tool({ amount: 120, merchant: 'skyward-air' });
const signed = JSON.parse(seen.headers['x-magp-request']);

await check('the tool gets an x-magp-request header carrying the authorization it was granted', async () => {
  assert.deepEqual(Object.keys(seen.headers), ['x-magp-request']);
  assert.equal(signed.authorizationId, AUTH);
  assert.equal(signed.agentDid, agentDid);
  assert.equal(signed.action, 'flight-purchase');
  assert.equal(signed.amount, 120);
  assert.equal(signed.merchant, 'skyward-air');
  assert.deepEqual(signed.itinerary, { tool: 'book-flight', riskLevel: 'low' });
});

await check('it is signed by the agent over exactly that request', async () => {
  const message = buildAuthMessage({ agentDid, action: 'flight-purchase', amount: 120, currency: 'USD', merchant: 'skyward-air', nonce: signed.nonce, issuedAt: signed.issuedAt });
  assert.ok(verifies(message, signed.signature));
});

await check('the payload the tool will send is bound, so a gateway requiring payload binding accepts it', async () => {
  assert.equal(signed.payloadDigest, payloadDigestOf(toWireJson(payloadOf({ amount: 120, merchant: 'skyward-air' }))));
  const binding = buildPayloadBindingMessage({ agentDid, action: 'flight-purchase', nonce: signed.nonce, issuedAt: signed.issuedAt, payloadDigest: signed.payloadDigest });
  assert.ok(verifies(binding, signed.payloadSignature));
});

await check('each call is freshly signed (a new nonce), so a gateway never sees a replay', async () => {
  const again = JSON.parse((await seen.decision.governanceHeaders())['x-magp-request']);
  assert.notEqual(again.nonce, signed.nonce);
});

await check('the method is not data: the decision still compares and serialises as before', async () => {
  assert.equal(Object.keys(seen.decision).includes('governanceHeaders'), false);
  assert.equal(JSON.stringify(seen.decision).includes('governanceHeaders'), false);
  assert.equal(seen.decision.authorizationId, AUTH);
});

await check('a real gateway guard (agentsafe-mcp-guard) verifies the headers and binds the body the tool sends', async () => {
  const { createMcpGuard } = await import('../agentsafe-mcp-guard/agentsafe-mcp-guard.mjs');
  const bundle = { subject: agentDid, standards: [], sops: [], mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [] }] } }] };
  const gateway = createMcpGuard({ serviceDid: 'did:key:z6MkGatewayUnderTest', allowedAgents: 'any', fetchBundle: async () => bundle, allowUnverifiedBundle: true });
  const body = payloadOf({ amount: 120, merchant: 'skyward-air' });
  const fresh = JSON.parse((await seen.decision.governanceHeaders())['x-magp-request']);
  const ok = await gateway.verifyRequest(fresh, { payloadDigest: payloadDigestOf(toWireJson(body)) });
  assert.equal(ok.decision, 'allow', JSON.stringify(ok));
  const swapped = await gateway.verifyRequest(fresh, { payloadDigest: payloadDigestOf(toWireJson({ ...body, merchant: 'shadow-broker' })) });
  assert.equal(swapped.decision, 'block');
});

globalThis.fetch = real;
if (failed) { console.log(`\n${failed} FAILED`); process.exit(1); }
console.log('\nPASS governance-headers');

// report-outcome.smoke.mjs — A-1 of the 2026-10-03 pre-beta rerun: a gateway that claims nothing (every non-financial
// agent's) ran requests the issuer never saw, so its owner's audit trail was empty even when another tenant's agent used
// it (XT-1). `guard.reportOutcome()` reports what this Service did, signed as this Service (MAGP-SERVICE-v1, action
// `report`), to POST /policy/gateway-reports (MAGP §16.4). This checks the wire: the report is filed for the right agent,
// signed over exactly the fields the issuer verifies, and never sent without a signing identity.
//
//   node report-outcome.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildDidKey, buildHederaDid, verifyDidSignature } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function agent(account) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), account);
  const sign = (action) => {
    const base = { agentDid: did, action, amount: 0, currency: 'USD', merchant: '', nonce: crypto.randomUUID(), issuedAt: new Date().toISOString() };
    return { ...base, signature: crypto.sign(null, Buffer.from(buildAuthMessage(base), 'utf8'), privateKey).toString('hex') };
  };
  return { did, sign };
}
const mine = agent('0.0.131');
const theirs = agent('0.0.132');
const svc = (() => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { did: buildDidKey(spki.subarray(spki.length - 32)), key: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex') };
})();
const ISSUER = 'https://issuer.example/api/v1';
const fetchBundle = async (did) => ({ subject: did, mandates: [], standards: [], sops: [] });

/** Run fn with fetch captured; the issuer answers `answer(callIndex)`. */
async function capturing(fn, answer = () => ({ status: 201, json: { success: true, data: { reasonCode: 'RECORDED' } } })) {
  const real = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), headers: init.headers, body: JSON.parse(init.body) });
    const a = answer(calls.length - 1);
    if (a instanceof Error) throw a;
    return { ok: a.status < 300, status: a.status, json: async () => a.json };
  };
  try { return { value: await fn(), calls }; } finally { globalThis.fetch = real; }
}
const escape = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
/** Recompute what the issuer verifies (counterparty-auth.ts buildCounterpartyMessage) and check the signature. */
function verifiesAsIssuer(call) {
  const h = call.headers; const b = call.body;
  const fields = [b.servedAgentDid, b.request.agentDid, b.request.action, b.outcome, b.reasonCode, b.httpStatus == null ? '' : String(b.httpStatus)];
  const msg = ['MAGP-SERVICE-v1', 'report', b.request.nonce, ...fields, h['x-magp-service-nonce'], h['x-magp-service-issued-at']].map(escape).join('|');
  return verifyDidSignature(h['x-magp-service-did'], msg, h['x-magp-service-signature']);
}

const t = [];
const test = (name, fn) => t.push([name, fn]);
const pinned = () => createMcpGuard({ serviceDid: svc.did, serviceKey: svc.key, issuerApi: ISSUER, fetchBundle, policyPublicKey: undefined, allowedAgents: [mine.did], gatewayOwnerPrincipal: 'did:hedera:testnet:zOwnerA_0.0.900' });

test('an execution for the agent it serves is reported, signed over exactly what the issuer verifies', async () => {
  const signed = mine.sign('records-update');
  const { value, calls } = await capturing(() => pinned().reportOutcome({ signed, outcome: 'executed', reasonCode: 'EXECUTED', httpStatus: 200 }));
  assert.deepEqual([value.ok, value.reasonCode], [true, 'RECORDED']);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${ISSUER}/policy/gateway-reports`);
  assert.equal(calls[0].body.servedAgentDid, mine.did);
  assert.equal(calls[0].body.request.signature, signed.signature, 'the agent\'s own signature travels, so the issuer can verify the caller');
  assert.equal(calls[0].headers['x-magp-service-did'], svc.did);
  assert.ok(verifiesAsIssuer(calls[0]), 'signature verifies over the issuer\'s message');
});

test('a foreign agent refused AGENT_NOT_ADMITTED is filed for the agent the gateway serves, not the caller', async () => {
  const { calls } = await capturing(() => pinned().reportOutcome({ signed: theirs.sign('records-update'), outcome: 'refused', reasonCode: 'AGENT_NOT_ADMITTED', httpStatus: 403 }));
  assert.equal(calls[0].body.servedAgentDid, mine.did);
  assert.equal(calls[0].body.request.agentDid, theirs.did);
  assert.ok(verifiesAsIssuer(calls[0]));
});

test('a LISTED agent of another owner (GATEWAY_OWNER_MISMATCH) is reported to the gateway owner, via an agent it really serves', async () => {
  const guard = createMcpGuard({ serviceDid: svc.did, serviceKey: svc.key, issuerApi: ISSUER, fetchBundle, allowedAgents: [mine.did, theirs.did], gatewayOwnerPrincipal: 'did:hedera:testnet:zOwnerA_0.0.900' });
  const { calls } = await capturing(() => guard.reportOutcome({ signed: theirs.sign('records-update'), outcome: 'refused', reasonCode: 'GATEWAY_OWNER_MISMATCH', httpStatus: 403 }));
  assert.equal(calls[0].body.servedAgentDid, mine.did, 'never filed under the caller (whose owner never registered this gateway)');
  assert.ok(verifiesAsIssuer(calls[0]));
});

test('no signing identity: nothing is sent (an unsigned report would be refused anyway)', async () => {
  const guard = createMcpGuard({ serviceDid: 'did:local:records-gateway', issuerApi: ISSUER, fetchBundle, allowedAgents: [mine.did], gatewayOwnerPrincipal: 'did:hedera:testnet:zOwnerA_0.0.900' });
  const { value, calls } = await capturing(() => guard.reportOutcome({ signed: mine.sign('records-update'), outcome: 'executed', reasonCode: 'EXECUTED', httpStatus: 200 }));
  assert.equal(value.reasonCode, 'SERVICE_IDENTITY_REQUIRED');
  assert.equal(calls.length, 0);
});

test('nothing to attribute, or an unknown outcome: not sent', async () => {
  const { value: a, calls } = await capturing(() => pinned().reportOutcome({ signed: { action: 'records-update' }, outcome: 'refused', reasonCode: 'MISSING_GOVERNANCE' }));
  assert.equal(a.reasonCode, 'NOTHING_TO_REPORT');
  const { value: b } = await capturing(() => pinned().reportOutcome({ signed: mine.sign('x'), outcome: 'maybe' }));
  assert.equal(b.reasonCode, 'REPORT_OUTCOME_INVALID');
  assert.equal(calls.length, 0);
});

test('a lost answer is retried once with the SAME signed headers (the issuer answers ALREADY_RECORDED if it landed)', async () => {
  const { value, calls } = await capturing(
    () => pinned().reportOutcome({ signed: mine.sign('records-update'), outcome: 'executed', reasonCode: 'EXECUTED', httpStatus: 200 }),
    (i) => (i === 0 ? new TypeError('fetch failed') : { status: 200, json: { success: true, data: { reasonCode: 'ALREADY_RECORDED' } } }),
  );
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1].headers, calls[0].headers);
  assert.deepEqual([value.ok, value.reasonCode], [true, 'ALREADY_RECORDED']);
});

test('a refusal from the issuer is reported back, never thrown', async () => {
  const { value } = await capturing(
    () => pinned().reportOutcome({ signed: mine.sign('records-update'), outcome: 'executed', reasonCode: 'EXECUTED', httpStatus: 200 }),
    () => ({ status: 403, json: { success: false, message: 'COUNTERPARTY_NOT_REGISTERED', data: { reasonCode: 'COUNTERPARTY_NOT_REGISTERED' } } }),
  );
  assert.deepEqual([value.ok, value.status, value.reasonCode], [false, 403, 'COUNTERPARTY_NOT_REGISTERED']);
});

const quiet = console.warn; console.warn = () => {};
let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log(`ok    ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}\n      ${err.message}`); }
}
console.warn = quiet;
if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log(`\nPASS — ${t.length} reportOutcome cases.`);

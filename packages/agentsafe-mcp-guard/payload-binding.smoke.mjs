// payload-binding.smoke.mjs — the mcp-guard side of payload binding (spec 8.3.9). The agent binds the digest of the COMPLETE
// payload with its own key; this Service digests what it is about to EXECUTE, refuses a difference locally, and states the
// digest in the CLAIM it signs so the issuer compares it against the one it stored at authorize time.
//
//   node payload-binding.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { buildPayloadBindingMessage, payloadDigestOf, claimDigestField, PAYLOAD_DIGEST_HEADER } from './payload-binding.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const raw = spki.subarray(spki.length - 32);
  const did = buildHederaDid('testnet', raw, topic);
  const sign = (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex');
  return { did, sign };
}
const agent = mint('0.0.101');
const service = mint('0.0.201');

const bundle = {
  subject: agent.did, standards: [], sops: [],
  mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] } }],
};

const PAYLOAD = { passenger: 'A. Traveller', payee: { iban: 'GB00AAAA', name: 'Skyward Air' }, amount: 250 };

/** A signed authorize request, optionally binding `payload` exactly as the guard's buildSignedRequest does. */
function signedRequest({ payload, amount = 250, authorizationId = 'auth-1', tamper = {} } = {}) {
  const action = 'flight-purchase';
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const req = { agentDid: agent.did, action, amount, currency: 'USD', merchant: 'skyward-air', nonce, issuedAt, authorizationId };
  req.signature = agent.sign(buildAuthMessage(req));
  if (payload !== undefined) {
    req.payloadDigest = payloadDigestOf(payload);
    req.payloadSignature = agent.sign(buildPayloadBindingMessage({ agentDid: agent.did, action, nonce, issuedAt, payloadDigest: req.payloadDigest }));
  }
  return { ...req, ...tamper };
}

/** Mock the ONE network call claimAuthorization makes, recording the headers it sent. */
function withMockClaim(responder) {
  const realFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, opts) => {
    seen.push({ url: String(url), headers: opts?.headers ?? {} });
    const { status, body } = responder({ url: String(url), headers: opts?.headers ?? {} });
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  return { seen, restore: () => { globalThis.fetch = realFetch; } };
}
// A compliant issuer echoes the digest the claim stated (null when it stated none): the hold is bound to exactly that.
const okClaim = (extra = {}) => ({ headers }) => ({ status: 200, body: { success: true, data: { ok: true, effectState: 'dispatching', agentDid: agent.did, action: 'flight-purchase', amount: 250, currency: 'USD', merchant: 'skyward-air', payloadDigest: headers[PAYLOAD_DIGEST_HEADER] ?? null, ...extra } } });

const mk = (opts = {}) => createMcpGuard({ serviceDid: service.did, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true, ...opts });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('the executed digest matching the signed one is permitted, and the claim states it in a header AND a signed field', async () => {
  const { seen, restore } = withMockClaim(okClaim({ payloadDigest: payloadDigestOf(PAYLOAD) }));
  try {
    const r = await mk().verifyRequest(signedRequest({ payload: PAYLOAD }), { payloadDigest: payloadDigestOf(PAYLOAD) });
    assert.equal(r.decision, 'allow');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].headers[PAYLOAD_DIGEST_HEADER], payloadDigestOf(PAYLOAD));
    assert.match(JSON.stringify(seen[0].headers), new RegExp(payloadDigestOf(PAYLOAD).replace('sha256:', 'sha256:')), 'the digest travels in the request');
  } finally { restore(); }
});

test('the executor digesting a DIFFERENT payload is refused locally (PAYLOAD_NOT_BOUND) before any claim is made', async () => {
  const { seen, restore } = withMockClaim(okClaim());
  try {
    const swapped = { ...PAYLOAD, payee: { iban: 'XX99EVIL', name: 'Skyward Air' } };
    const r = await mk().verifyRequest(signedRequest({ payload: PAYLOAD }), { payloadDigest: payloadDigestOf(swapped) });
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'PAYLOAD_NOT_BOUND');
    assert.equal(seen.length, 0, 'the hold must not be spent on a request that already fails the comparison');
  } finally { restore(); }
});

test('a digest with a bad signature over it binds nothing (PAYLOAD_BINDING_INVALID)', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const bad = signedRequest({ payload: PAYLOAD, tamper: { payloadSignature: 'ab'.repeat(64) } });
    assert.equal((await mk().verifyRequest(bad, { payloadDigest: payloadDigestOf(PAYLOAD) })).reasonCode, 'PAYLOAD_BINDING_INVALID');
  } finally { restore(); }
});

test('a digest lifted onto another authorization (different nonce) is refused', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const a = signedRequest({ payload: PAYLOAD });
    const b = signedRequest({ payload: { other: 1 } });
    // b's request with a's payload binding: the binding message names a's nonce/issuedAt, not b's.
    const lifted = { ...b, payloadDigest: a.payloadDigest, payloadSignature: a.payloadSignature };
    assert.equal((await mk().verifyRequest(lifted, { payloadDigest: a.payloadDigest })).reasonCode, 'PAYLOAD_BINDING_INVALID');
  } finally { restore(); }
});

test('a digest without a signature (or a signature without a digest) is refused', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const good = signedRequest({ payload: PAYLOAD });
    const noSig = { ...good }; delete noSig.payloadSignature;
    const noDigest = { ...good }; delete noDigest.payloadDigest;
    assert.equal((await mk().verifyRequest(noSig)).reasonCode, 'PAYLOAD_BINDING_INVALID');
    assert.equal((await mk().verifyRequest(noDigest)).reasonCode, 'PAYLOAD_BINDING_INVALID');
  } finally { restore(); }
});

test('an executor digest that is not a sha256: digest is refused (PAYLOAD_DIGEST_INVALID)', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    assert.equal((await mk().verifyRequest(signedRequest({ payload: PAYLOAD }), { payloadDigest: 'md5:abc' })).reasonCode, 'PAYLOAD_DIGEST_INVALID');
  } finally { restore(); }
});

test('an UNBOUND authorization is unchanged by default: permitted, and the claim carries no digest', async () => {
  const { seen, restore } = withMockClaim(okClaim());
  try {
    const r = await mk().verifyRequest(signedRequest(), { payloadDigest: payloadDigestOf(PAYLOAD) });
    assert.equal(r.decision, 'allow');
    assert.equal(seen[0].headers[PAYLOAD_DIGEST_HEADER], undefined, 'no binding was made, so none is asserted');
  } finally { restore(); }
});

test('requirePayloadBinding refuses an unbound authorization (PAYLOAD_BINDING_REQUIRED), with or without an executor digest', async () => {
  const { seen, restore } = withMockClaim(okClaim());
  try {
    assert.equal((await mk().verifyRequest(signedRequest(), { payloadDigest: payloadDigestOf(PAYLOAD), requirePayloadBinding: true })).reasonCode, 'PAYLOAD_BINDING_REQUIRED');
    assert.equal((await mk().verifyRequest(signedRequest(), { requirePayloadBinding: true })).reasonCode, 'PAYLOAD_BINDING_REQUIRED');
    assert.equal(seen.length, 0);
  } finally { restore(); }
});

test('a BOUND authorization but an executor that offers no digest is permitted only when binding is not required, and then claims without one', async () => {
  const { seen, restore } = withMockClaim(okClaim());
  try {
    const r = await mk().verifyRequest(signedRequest({ payload: PAYLOAD }));
    assert.equal(r.decision, 'allow');
    assert.equal(seen[0].headers[PAYLOAD_DIGEST_HEADER], undefined);
  } finally { restore(); }
});

test('the issuer refusing the claim digest surfaces its reason code (PAYLOAD_DIGEST_MISMATCH)', async () => {
  const { restore } = withMockClaim(() => ({ status: 403, body: { success: false, message: 'PAYLOAD_DIGEST_MISMATCH' } }));
  try {
    const r = await mk().verifyRequest(signedRequest({ payload: PAYLOAD }), { payloadDigest: payloadDigestOf(PAYLOAD) });
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'PAYLOAD_DIGEST_MISMATCH');
  } finally { restore(); }
});

test('a grant that reports a different bound digest than the one claimed is refused (defence in depth)', async () => {
  const { restore } = withMockClaim(okClaim({ payloadDigest: payloadDigestOf({ something: 'else' }) }));
  try {
    const r = await mk().verifyRequest(signedRequest({ payload: PAYLOAD }), { payloadDigest: payloadDigestOf(PAYLOAD) });
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'PAYLOAD_DIGEST_MISMATCH');
  } finally { restore(); }
});

test('an issuer that predates payload binding (its grant carries no digest) is REFUSED when the claim stated one: not enforced is not fine', async () => {
  const { restore } = withMockClaim(() => ({ status: 200, body: { success: true, data: { ok: true, effectState: 'dispatching', agentDid: agent.did, action: 'flight-purchase', amount: 250, currency: 'USD', merchant: 'skyward-air' } } }));
  try {
    const r = await mk().verifyRequest(signedRequest({ payload: PAYLOAD }), { payloadDigest: payloadDigestOf(PAYLOAD) });
    assert.equal(r.decision, 'block'); assert.equal(r.reasonCode, 'PAYLOAD_DIGEST_MISMATCH');
    // ...while an UNBOUND request against the same old issuer is exactly what it always was
    assert.equal((await mk().verifyRequest(signedRequest())).decision, 'allow');
  } finally { restore(); }
});
test('the digest is covered by the counterparty signature on the claim: it verifies WITH the payload field and not without it', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const svcDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.202');
  const serviceKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
  const { seen, restore } = withMockClaim(okClaim());
  try {
    const d = payloadDigestOf(PAYLOAD);
    const guard = createMcpGuard({ serviceDid: svcDid, serviceKey, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true });
    assert.equal((await guard.verifyRequest(signedRequest({ payload: PAYLOAD }), { payloadDigest: d })).decision, 'allow');
    const h = seen[0].headers;
    const esc = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
    const message = (fields) => ['MAGP-SERVICE-v1', 'claim', 'auth-1', ...fields, h['x-magp-service-nonce'], h['x-magp-service-issued-at']].map(esc).join('|');
    const verifies = (m) => crypto.verify(null, Buffer.from(m, 'utf8'), publicKey, Buffer.from(h['x-magp-service-signature'], 'hex'));
    assert.equal(claimDigestField(d), `payload=${d}`);
    assert.equal(verifies(message([h['idempotency-key'], claimDigestField(d)])), true, 'signed with the digest field');
    assert.equal(verifies(message([h['idempotency-key']])), false, 'a header stripped of its signed field would not verify');
    assert.equal(verifies(message([h['idempotency-key'], claimDigestField(payloadDigestOf({ other: 1 }))])), false, 'a different digest would not verify');
  } finally { restore(); }
});

// guardIncomingTool: the tool's own arguments are digested (bindPayload) — the Service executes exactly what it digested.
test('guardIncomingTool({ bindPayload: true }) digests the tool arguments: matching runs the handler, a swapped payee never does', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    let ran = 0;
    const tool = mk().guardIncomingTool('flight-purchase', async (_signed, args) => { ran++; return args; }, { bindPayload: true });
    assert.deepEqual(await tool(signedRequest({ payload: PAYLOAD }), PAYLOAD), PAYLOAD);
    assert.equal(ran, 1);
    await assert.rejects(
      () => tool(signedRequest({ payload: PAYLOAD }), { ...PAYLOAD, payee: { iban: 'XX99EVIL', name: 'Skyward Air' } }),
      (e) => e.name === 'GovernanceBlocked' && e.governance.reasonCode === 'PAYLOAD_NOT_BOUND',
    );
    assert.equal(ran, 1, 'the handler must not run on a payload that is not the one signed');
  } finally { restore(); }
});

test('guardIncomingTool: arguments JSON cannot carry are refused (PAYLOAD_NOT_CANONICALIZABLE), never skipped', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    let ran = 0;
    const tool = mk().guardIncomingTool('flight-purchase', async () => { ran++; }, { bindPayload: true });
    await assert.rejects(() => tool(signedRequest({ payload: PAYLOAD }), () => 1), (e) => e.governance?.reasonCode === 'PAYLOAD_NOT_CANONICALIZABLE');
    assert.equal(ran, 0);
  } finally { restore(); }
});

test('guardIncomingTool: requirePayloadBinding without bindPayload is a configuration error (it would compare nothing)', () => {
  assert.throws(() => mk().guardIncomingTool('flight-purchase', async () => 'x', { requirePayloadBinding: true }), /requirePayloadBinding needs bindPayload/);
});

test('guardIncomingTool: bindPayload:true digests exactly one argument; a second argument is refused, not executed unbound', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    let ran = 0;
    const tool = mk().guardIncomingTool('flight-purchase', async () => { ran++; }, { bindPayload: true });
    await assert.rejects(() => tool(signedRequest({ payload: PAYLOAD }), PAYLOAD, { account: 'EVIL' }), (e) => e.governance?.reasonCode === 'PAYLOAD_NOT_CANONICALIZABLE');
    await assert.rejects(() => tool(signedRequest({ payload: PAYLOAD })), (e) => e.governance?.reasonCode === 'PAYLOAD_NOT_CANONICALIZABLE');
    assert.equal(ran, 0);
  } finally { restore(); }
});

test('guardIncomingTool: the handler receives the JSON snapshot that was digested (toJSON and later mutation cannot diverge)', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const seen = [];
    const tool = mk().guardIncomingTool('flight-purchase', async (_s, args) => { seen.push(args); }, { bindPayload: true });
    const sneaky = { payee: 'EVIL', toJSON() { return PAYLOAD; } };
    await tool(signedRequest({ payload: PAYLOAD }), sneaky);
    assert.deepEqual(seen[0], PAYLOAD, 'the handler runs exactly what was digested, not the live object');
    assert.notEqual(seen[0], sneaky);
  } finally { restore(); }
});

test('guardIncomingTool: bindPayload as a function chooses what is digested', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const tool = mk().guardIncomingTool('flight-purchase', async () => 'done', { bindPayload: (_signed, args) => ({ payee: args.payee }) });
    assert.equal(await tool(signedRequest({ payload: { payee: PAYLOAD.payee } }), PAYLOAD), 'done');
  } finally { restore(); }
});

test('guardIncomingTool: requirePayloadBinding refuses an unbound authorization', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const tool = mk().guardIncomingTool('flight-purchase', async () => 'done', { bindPayload: true, requirePayloadBinding: true });
    await assert.rejects(() => tool(signedRequest(), PAYLOAD), (e) => e.governance?.reasonCode === 'PAYLOAD_BINDING_REQUIRED');
  } finally { restore(); }
});

let pass = 0, fail = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m ' + name); pass++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m ' + name + '\n       ' + (e.stack ?? e.message).split('\n').slice(0, 4).join('\n       ')); fail++; }
}
console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

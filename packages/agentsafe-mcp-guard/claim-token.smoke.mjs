// claim-token.smoke.mjs — the claim token the issuer hands the claiming Service is RELAYED to that
// Service (and only kept from the calling agent), and the Service has the calls it needs to settle,
// release or park the hold it just claimed.
//
// Background: the issuer now treats a CLAIMED hold as a commitment. Settling it below its amount, or
// voiding it, needs the claim token returned by that hold's successful claim; without it an agent
// could wait for the Service to execute and then capture $0 / void its own hold to get its budget
// back. This package used to discard the token, so a Service could neither settle below the hold nor
// release one after an upstream failure.
//
//   node claim-token.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), topic);
  return { did, sign: (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex') };
}
const agent = mint('0.0.101');
const service = mint('0.0.201');
const TOKEN = 'ab'.repeat(32);

const bundle = {
  subject: agent.did, standards: [], sops: [],
  mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] } }],
};

function signedRequest({ amount = 250, authorizationId = 'auth-1' } = {}) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const signature = agent.sign(buildAuthMessage({ agentDid: agent.did, action: 'flight-purchase', amount, currency: 'USD', merchant: 'skyward-air', nonce, issuedAt }));
  return { agentDid: agent.did, action: 'flight-purchase', amount, currency: 'USD', merchant: 'skyward-air', nonce, issuedAt, signature, authorizationId };
}

/** Record every issuer call; `respond(path)` returns { status, body }. */
function mockIssuer(respond) {
  const calls = [];
  const headers = []; // parallel to `calls`: the request headers of each issuer call
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const path = String(url).replace('https://issuer.example/api/v1', '');
    calls.push({ path, method: opts?.method, body: opts?.body ? JSON.parse(opts.body) : null });
    headers.push(opts?.headers ?? {});
    const answer = respond(path, calls.length - 1);
    if (answer === 'DROP') throw new Error('socket hang up'); // the response never arrives
    const { status, body } = answer;
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  return { calls, headers, restore: () => { globalThis.fetch = realFetch; } };
}

const claimOk = (extra = {}) => ({ status: 200, body: { success: true, data: { ok: true, effectState: 'dispatching', agentDid: agent.did, action: 'flight-purchase', amount: 250, currency: 'USD', merchant: 'skyward-air', ...extra } } });
const ok = (data = {}) => ({ status: 200, body: { success: true, data } });
const router = (over = {}) => (path) => {
  if (path.endsWith('/effect/dispatching')) return over.claim ?? claimOk({ claimToken: TOKEN });
  if (path.endsWith('/capture')) return over.capture ?? ok({ captured: true });
  if (path.endsWith('/void')) return over.void ?? ok({ voided: true });
  if (path.endsWith('/effect/unknown')) return over.unknown ?? ok({ effectState: 'unknown' });
  throw new Error('unexpected issuer call ' + path);
};
const mk = (opts = {}) => createMcpGuard({ serviceDid: service.did, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true, ...opts });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('the claim token is relayed on the permit verdict', async () => {
  const m = mockIssuer(router());
  try {
    const r = await mk().verifyRequest(signedRequest());
    assert.equal(r.decision, 'allow');
    assert.equal(r.claimToken, TOKEN);
    assert.equal(r.authorizationId, 'auth-1');
  } finally { m.restore(); }
});

test('...but never leaks when the verdict is echoed onward (JSON, spread, Object.keys)', async () => {
  const m = mockIssuer(router());
  try {
    const r = await mk().verifyRequest(signedRequest());
    assert.ok(!JSON.stringify(r).includes(TOKEN), 'JSON.stringify must not carry the token');
    assert.ok(!JSON.stringify({ ...r }).includes(TOKEN), 'a spread copy must not carry the token');
    assert.ok(!Object.keys(r).includes('claimToken'));
    assert.ok(!Object.keys(r).includes('authorizationId'), 'the verdict shape seen by existing consumers is unchanged');
  } finally { m.restore(); }
});

test('an older issuer that returns no token still permits, with no token to relay', async () => {
  const m = mockIssuer(router({ claim: claimOk() }));
  try {
    const r = await mk().verifyRequest(signedRequest());
    assert.equal(r.decision, 'allow');
    assert.equal(r.claimToken, undefined);
  } finally { m.restore(); }
});

test('a blocked or unclaimed request carries no token', async () => {
  const m = mockIssuer(router({ claim: { status: 409, body: { success: false, message: 'INVALID_EFFECT_TRANSITION' } } }));
  try {
    const r = await mk().verifyRequest(signedRequest());
    assert.equal(r.decision, 'block');
    assert.equal(r.claimToken, undefined);
  } finally { m.restore(); }
});

test('captureAuthorization presents the token and the amount, and reports ok', async () => {
  const m = mockIssuer(router());
  try {
    const r = await mk().captureAuthorization({ authorizationId: 'auth-1', claimToken: TOKEN, amountCharged: 200, bookingRef: 'PNR1' });
    assert.equal(r.ok, true);
    assert.deepEqual(m.calls[0], { path: '/policy/mandate/authorize/auth-1/capture', method: 'POST', body: { amountCharged: 200, bookingRef: 'PNR1', claimToken: TOKEN } });
  } finally { m.restore(); }
});

test('releaseAuthorization presents the token to void a claimed hold', async () => {
  const m = mockIssuer(router());
  try {
    const r = await mk().releaseAuthorization({ authorizationId: 'auth-1', claimToken: TOKEN, reason: 'upstream-rejected' });
    assert.equal(r.ok, true);
    assert.deepEqual(m.calls[0], { path: '/policy/mandate/authorize/auth-1/void', method: 'POST', body: { reason: 'upstream-rejected', claimToken: TOKEN } });
  } finally { m.restore(); }
});

test('markAuthorizationUnknown parks the effect without releasing it', async () => {
  const m = mockIssuer(router());
  try {
    const r = await mk().markAuthorizationUnknown({ authorizationId: 'auth-1', reason: 'HTTP_502' });
    assert.equal(r.ok, true);
    assert.equal(m.calls[0].path, '/policy/mandate/authorize/auth-1/effect/unknown');
  } finally { m.restore(); }
});

test('the settlement helpers never throw: refusals, void-not-applied, and an unreachable issuer are reported', async () => {
  let m = mockIssuer(router({ capture: { status: 400, body: { success: false, message: 'amountCharged (0) is below the claimed hold (250)' } }, void: { status: 200, body: { success: false, message: 'Not voided (NOT_HELD)', data: { voided: false, reasonCode: 'NOT_HELD' } } } }));
  try {
    const g = mk();
    const cap = await g.captureAuthorization({ authorizationId: 'a', amountCharged: 0 });
    assert.equal(cap.ok, false); assert.match(cap.reasonCode, /below the claimed hold/);
    const rel = await g.releaseAuthorization({ authorizationId: 'a', claimToken: TOKEN });
    assert.equal(rel.ok, false); assert.equal(rel.reasonCode, 'NOT_HELD');
  } finally { m.restore(); }
  const real = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('connect ECONNREFUSED'); };
  try {
    const r = await mk().releaseAuthorization({ authorizationId: 'a', claimToken: TOKEN });
    assert.equal(r.ok, false); assert.equal(r.reasonCode, 'ISSUER_UNREACHABLE');
  } finally { globalThis.fetch = real; }
});

test('the helpers validate their input instead of calling the issuer', async () => {
  const m = mockIssuer(router());
  try {
    const g = mk();
    assert.equal((await g.captureAuthorization({})).reasonCode, 'AUTHORIZATION_REQUIRED');
    assert.equal((await g.captureAuthorization({ authorizationId: 'a' })).reasonCode, 'AMOUNT_CHARGED_REQUIRED');
    assert.equal((await g.releaseAuthorization({})).reasonCode, 'AUTHORIZATION_REQUIRED');
    assert.equal(m.calls.length, 0);
  } finally { m.restore(); }
});

test('guardIncomingTool({ settle: true }) settles a handler that returns, at the authorized amount', async () => {
  const m = mockIssuer(router());
  try {
    const tool = mk().guardIncomingTool('flight-purchase', async () => 'BOOKED', { settle: true });
    assert.equal(await tool(signedRequest({ amount: 250 })), 'BOOKED');
    const capture = m.calls.find((c) => c.path.endsWith('/capture'));
    assert.deepEqual(capture.body, { amountCharged: 250, claimToken: TOKEN });
    assert.ok(!m.calls.some((c) => c.path.endsWith('/void')), 'a successful call is never voided');
  } finally { m.restore(); }
});

test('guardIncomingTool({ settle: true }) parks a handler that throws as UNKNOWN — never voids it', async () => {
  const m = mockIssuer(router());
  try {
    const tool = mk().guardIncomingTool('flight-purchase', async () => { throw new Error('upstream exploded'); }, { settle: true });
    await assert.rejects(() => tool(signedRequest()), /upstream exploded/);
    assert.ok(m.calls.some((c) => c.path.endsWith('/effect/unknown')));
    assert.ok(!m.calls.some((c) => c.path.endsWith('/void')), 'a throw does not prove nothing executed, so it must not release the budget');
    assert.ok(!m.calls.some((c) => c.path.endsWith('/capture')));
  } finally { m.restore(); }
});

test('guardIncomingTool without { settle } behaves exactly as before: only the claim is made', async () => {
  const m = mockIssuer(router());
  try {
    const tool = mk().guardIncomingTool('flight-purchase', async () => 'BOOKED');
    assert.equal(await tool(signedRequest()), 'BOOKED');
    assert.deepEqual(m.calls.map((c) => c.path), ['/policy/mandate/authorize/auth-1/effect/dispatching']);
  } finally { m.restore(); }
});

// --- authenticated counterparty identity: the Service signs its own settlement-surface calls ---
const svcKeys = crypto.generateKeyPairSync('ed25519');
const svcRaw = svcKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
const SVC_DID = buildHederaDid('testnet', svcRaw, '0.0.4242');
const SVC_KEY_HEX = svcKeys.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
const mkSigned = (opts = {}) => createMcpGuard({ serviceDid: SVC_DID, serviceKey: SVC_KEY_HEX, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true, ...opts });
const claimNoToken = claimOk(); // an authenticated claim is answered without a bearer token
const escapeField = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
/** Independently verify a signed call the way the issuer does: rebuild the message, check it against the key in the DID. */
function verifiesAs(h, action, authorizationId, fields) {
  const message = ['MAGP-SERVICE-v1', action, authorizationId, ...fields, h['x-magp-service-nonce'], h['x-magp-service-issued-at']].map(escapeField).join('|');
  return h['x-magp-service-did'] === SVC_DID && crypto.verify(null, Buffer.from(message, 'utf8'), svcKeys.publicKey, Buffer.from(h['x-magp-service-signature'], 'hex'));
}

test('a Service with a key SIGNS its claim as its own DID, and the signature verifies against the key in that DID', async () => {
  const m = mockIssuer(router({ claim: claimNoToken }));
  try {
    await mkSigned().verifyRequest(signedRequest());
    assert.ok(verifiesAs(m.headers[0], 'claim', 'auth-1', [m.headers[0]['idempotency-key']]), 'the claim carries a valid x-magp-service-* signature, over its idempotency key');
    assert.ok(!verifiesAs(m.headers[0], 'claim', 'auth-1', ['0'.repeat(32)]), 'and the signature does not verify for any other key');
  } finally { m.restore(); }
});

test('an authenticated claim yields a verdict with NO token but the authenticated flag (non-enumerable)', async () => {
  const m = mockIssuer(router({ claim: claimNoToken }));
  try {
    const r = await mkSigned().verifyRequest(signedRequest());
    assert.equal(r.decision, 'allow');
    assert.equal(r.claimToken, undefined);
    assert.equal(r.counterpartyAuthenticated, true);
    assert.equal(r.authorizationId, 'auth-1');
    assert.ok(!Object.keys(r).includes('counterpartyAuthenticated'));
  } finally { m.restore(); }
});

test('capture, release and unknown are each signed over their own values', async () => {
  const m = mockIssuer(router());
  try {
    const g = mkSigned();
    await g.captureAuthorization({ authorizationId: 'a9', amountCharged: 200, bookingRef: 'PNR1' });
    await g.releaseAuthorization({ authorizationId: 'a9', reason: 'rejected' });
    await g.markAuthorizationUnknown({ authorizationId: 'a9', reason: 'HTTP_502' });
    assert.ok(verifiesAs(m.headers[0], 'capture', 'a9', ['200', 'PNR1', '']), 'capture is bound to its amount and refs');
    assert.ok(verifiesAs(m.headers[1], 'void', 'a9', ['rejected']));
    assert.ok(verifiesAs(m.headers[2], 'unknown', 'a9', ['HTTP_502']));
    assert.ok(!verifiesAs(m.headers[0], 'capture', 'a9', ['0', 'PNR1', '']), 'the same signature does not verify for a different amount');
    assert.ok(!verifiesAs(m.headers[0], 'void', 'a9', ['200', 'PNR1', '']), 'nor as a different action');
  } finally { m.restore(); }
});

test('every signed call uses a fresh nonce', async () => {
  const m = mockIssuer(router());
  try {
    const g = mkSigned();
    await g.markAuthorizationUnknown({ authorizationId: 'a9' });
    await g.markAuthorizationUnknown({ authorizationId: 'a9' });
    assert.notEqual(m.headers[0]['x-magp-service-nonce'], m.headers[1]['x-magp-service-nonce']);
  } finally { m.restore(); }
});

test('without a service key, or with a DID that is not self-certifying, calls stay anonymous (no service headers)', async () => {
  let m = mockIssuer(router());
  try {
    await mk().verifyRequest(signedRequest()); // mk(): a DID but NO key
    await mk().markAuthorizationUnknown({ authorizationId: 'a9' });
    assert.ok(m.headers.every((h) => !('x-magp-service-did' in h)));
  } finally { m.restore(); }
  m = mockIssuer(router());
  try {
    await mkSigned({ serviceDid: 'did:local:my-gateway' }).markAuthorizationUnknown({ authorizationId: 'a9' });
    assert.ok(!('x-magp-service-did' in m.headers[0]), 'a did:local identity cannot be checked without a registry, so it is not presented');
  } finally { m.restore(); }
});

test('guardIncomingTool({ settle: true }) settles an AUTHENTICATED claim with a signed capture (no token involved)', async () => {
  const m = mockIssuer(router({ claim: claimNoToken }));
  try {
    const tool = mkSigned().guardIncomingTool('flight-purchase', async () => 'BOOKED', { settle: true });
    assert.equal(await tool(signedRequest({ amount: 250 })), 'BOOKED');
    const i = m.calls.findIndex((c) => c.path.endsWith('/capture'));
    assert.ok(i > 0);
    assert.equal(m.calls[i].body.claimToken, undefined);
    assert.ok(verifiesAs(m.headers[i], 'capture', 'auth-1', ['250', '', '']));
  } finally { m.restore(); }
});

// --- exactly-once: idempotent claim retry, stable refusal, outcome lookup ---
const claimPath = '/policy/mandate/authorize/auth-1/effect/dispatching';
const isClaim = (c) => c.path === claimPath;

test('every claim carries a fresh unguessable Idempotency-Key (32 hex), anonymous or signed', async () => {
  const m = mockIssuer(router());
  try {
    await mk().verifyRequest(signedRequest());
    await mk().verifyRequest(signedRequest());
    const keys = m.headers.map((h) => h['idempotency-key']);
    assert.match(keys[0], /^[0-9a-f]{32}$/);
    assert.match(keys[1], /^[0-9a-f]{32}$/);
    assert.notEqual(keys[0], keys[1], 'a new claim call never reuses another call\'s key');
  } finally { m.restore(); }
});

test('a claim whose response is LOST is retried once with the SAME key (re-signed with a fresh nonce) and the replayed grant is used', async () => {
  const m = mockIssuer((path, i) => (isClaim({ path }) ? (i === 0 ? 'DROP' : claimOk({ replayed: true })) : router()(path)));
  try {
    const r = await mkSigned().verifyRequest(signedRequest());
    assert.equal(r.decision, 'allow');
    const claims = m.calls.map((c, i) => [c, i]).filter(([c]) => isClaim(c));
    assert.equal(claims.length, 2, 'exactly one retry');
    const [h0, h1] = claims.map(([, i]) => m.headers[i]);
    assert.equal(h0['idempotency-key'], h1['idempotency-key'], 'the retry reuses the key so the issuer can recognise it');
    assert.notEqual(h0['x-magp-service-nonce'], h1['x-magp-service-nonce'], 'but is a new signed call');
    assert.ok(verifiesAs(h1, 'claim', 'auth-1', [h1['idempotency-key']]));
    const direct = mockIssuer((path, i) => (i === 0 ? 'DROP' : claimOk({ replayed: true })));
    try { assert.equal((await mk().claimAuthorization({ authorizationId: 'auth-1' })).replayed, true); } finally { direct.restore(); }
  } finally { m.restore(); }
});

test('a 5xx on the claim is ambiguous too: retried once with the same key', async () => {
  const m = mockIssuer((path, i) => (isClaim({ path }) ? (i === 0 ? { status: 502, body: null } : claimOk({ claimToken: TOKEN, replayed: true })) : router()(path)));
  try {
    const r = await mk().verifyRequest(signedRequest());
    assert.equal(r.decision, 'allow');
    assert.equal(r.claimToken, TOKEN);
    assert.equal(m.calls.filter(isClaim).length, 2);
    assert.equal(m.headers[0]['idempotency-key'], m.headers[1]['idempotency-key']);
  } finally { m.restore(); }
});

test('it gives up after one retry: two lost responses in a row block, and never a third try', async () => {
  const m = mockIssuer(() => 'DROP');
  try {
    const r = await mk().verifyRequest(signedRequest());
    assert.equal(r.decision, 'block');
    assert.equal(r.reasonCode, 'AUTHORIZATION_CLAIM_UNREACHABLE');
    assert.equal(m.calls.length, 2);
  } finally { m.restore(); }
});

test('EFFECT_TRANSITION_CONTENDED (an overlapping attempt of mine is mid-claim) is retried once with the same key, and the grant used', async () => {
  const contended = { status: 409, body: { success: false, message: 'EFFECT_TRANSITION_CONTENDED' } };
  const m = mockIssuer((path, i) => (isClaim({ path }) ? (i === 0 ? contended : claimOk({ claimToken: TOKEN, replayed: true })) : router()(path)));
  try {
    const r = await mk().verifyRequest(signedRequest());
    assert.equal(r.decision, 'allow');
    assert.equal(m.calls.filter(isClaim).length, 2);
    assert.equal(m.headers[0]['idempotency-key'], m.headers[1]['idempotency-key']);
  } finally { m.restore(); }
});

test('a DEFINITE answer is final: AUTHORIZATION_ALREADY_CLAIMED is surfaced as it is and is never retried', async () => {
  const m = mockIssuer(router({ claim: { status: 409, body: { success: false, message: 'AUTHORIZATION_ALREADY_CLAIMED' } } }));
  try {
    const r = await mk().verifyRequest(signedRequest());
    assert.equal(r.decision, 'block');
    assert.equal(r.reasonCode, 'AUTHORIZATION_ALREADY_CLAIMED');
    assert.equal(m.calls.length, 1, 'retrying a refusal would only be a second claim');
  } finally { m.restore(); }
});

test('lookupOutcome reads the public effect status and never signs or throws', async () => {
  const data = { authorizationId: 'auth-1', outcome: 'unknown', nothingExecuted: false, claimed: true };
  let m = mockIssuer(() => ({ status: 200, body: { success: true, data } }));
  try {
    const r = await mkSigned().lookupOutcome({ authorizationId: 'auth-1' });
    assert.deepEqual(r, { ok: true, ...data });
    assert.equal(m.calls[0].path, '/policy/mandate/authorize/auth-1/effect');
    assert.ok(!('x-magp-service-did' in (m.headers[0] ?? {})), 'a public read is not signed');
  } finally { m.restore(); }
  m = mockIssuer(() => ({ status: 404, body: { success: false, message: 'Not found' } }));
  try { assert.deepEqual(await mk().lookupOutcome({ authorizationId: 'nope' }), { ok: false, status: 404, reasonCode: 'Not found' }); } finally { m.restore(); }
  m = mockIssuer(() => 'DROP');
  try { assert.equal((await mk().lookupOutcome({ authorizationId: 'a' })).reasonCode, 'ISSUER_UNREACHABLE'); } finally { m.restore(); }
  assert.equal((await mk().lookupOutcome({})).reasonCode, 'AUTHORIZATION_REQUIRED');
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  ok   ' + name); }
  catch (err) { failed++; console.log('  FAIL ' + name + '\n       ' + (err?.stack ?? err)); }
}
if (failed) { console.log(`\n${failed} of ${t.length} FAILED`); process.exit(1); }
console.log(`\nPASS — ${t.length} claim-token cases`);

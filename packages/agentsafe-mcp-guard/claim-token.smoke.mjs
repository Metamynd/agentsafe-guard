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
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const path = String(url).replace('https://issuer.example/api/v1', '');
    calls.push({ path, method: opts?.method, body: opts?.body ? JSON.parse(opts.body) : null });
    const { status, body } = respond(path);
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  return { calls, restore: () => { globalThis.fetch = realFetch; } };
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

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  ok   ' + name); }
  catch (err) { failed++; console.log('  FAIL ' + name + '\n       ' + (err?.stack ?? err)); }
}
if (failed) { console.log(`\n${failed} of ${t.length} FAILED`); process.exit(1); }
console.log(`\nPASS — ${t.length} claim-token cases`);

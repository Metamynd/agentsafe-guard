// a2a-claim-token.smoke.mjs — the A2A guard relays the issuer's claim token to the skill that executes
// (and keeps it off any echoed verdict), and can settle / release / park the hold it claimed.
// Same contract as agentsafe-mcp-guard's claim-token.smoke.mjs; see that file for the background.
//
//   node a2a-claim-token.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createA2aGuard, MAGP_A2A_EXTENSION_URI } from './agentsafe-a2a-guard.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const agentDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.910');
const sign = (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex');
const TOKEN = 'ef'.repeat(32);
const ISSUER = 'https://issuer.example/api/v1';

const bundle = { subject: agentDid, standards: [], sops: [], mandates: [{ action: 'book-hotel', document: { permission: [{ target: 'book-hotel', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] } }] };

function message(amount = 250) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const signature = sign(buildAuthMessage({ agentDid, action: 'book-hotel', amount, currency: 'USD', merchant: '', nonce, issuedAt }));
  const envelope = { agentDid, action: 'book-hotel', amount, currency: 'USD', merchant: '', nonce, issuedAt, signature, authorizationId: 'auth-9' };
  return { contextId: 'c', taskId: 't', metadata: { [MAGP_A2A_EXTENSION_URI]: envelope } };
}

function mockIssuer(respond) {
  const calls = [];
  const real = globalThis.fetch;
  const headers = [];
  globalThis.fetch = async (url, opts) => {
    const path = String(url).replace(ISSUER, '');
    calls.push({ path, body: opts?.body ? JSON.parse(opts.body) : null });
    headers.push(opts?.headers ?? {});
    const answer = respond(path, calls.length - 1);
    if (answer === 'DROP') throw new Error('socket hang up'); // the response never arrives
    const { status, body } = answer;
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  return { calls, headers, restore: () => { globalThis.fetch = real; } };
}
const claim = (extra = {}) => ({ status: 200, body: { success: true, data: { ok: true, agentDid, action: 'book-hotel', amount: 250, currency: 'USD', ...extra } } });
const ok200 = (data = {}) => ({ status: 200, body: { success: true, data } });
/** An issuer refusal in the one shape the settlement / effect routes answer with (MAGP 8.7.8): bare code as `message`. */
const refusal = (status, flag, reasonCode, sentence, authorizationId = 'a1') => ({
  status,
  body: { success: false, message: reasonCode, data: { ...(flag ? { [flag]: false } : {}), authorizationId, reasonCode, detail: `${reasonCode}: ${sentence}` } },
});
const route = (over = {}) => (path) => {
  if (path.endsWith('/effect/dispatching')) return over.claim ?? claim({ claimToken: TOKEN });
  if (path.endsWith('/capture')) return over.capture ?? ok200({});
  if (path.endsWith('/void')) return over.void ?? ok200({});
  if (path.endsWith('/effect/unknown')) return ok200({});
  throw new Error('unexpected ' + path);
};
const mk = () => createA2aGuard({ allowedAgents: 'any', issuerApi: ISSUER, fetchBundle: async () => bundle, requireAuthorization: true });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('x402: true marks the claim x402-bound (claimAuthorization, verifyRequest, guardA2ATask); unset, the claim request is unchanged', async () => {
  const m = mockIssuer(route());
  try {
    // verifyRequest's claim states what it is about to execute (`expect`, §8.7.19) — never x402 unless asked.
    await mk().verifyRequest({ ...message().metadata[MAGP_A2A_EXTENSION_URI] });
    assert.equal(m.calls[0].body.x402, undefined);
    assert.equal(m.calls[0].body.expect.action, 'book-hotel');
    await mk().claimAuthorization({ authorizationId: 'auth-2', x402: true });
    assert.deepEqual(m.calls[1].body, { x402: true });
    assert.equal(m.headers[1]['Content-Type'], 'application/json');
    await mk().verifyRequest({ ...message().metadata[MAGP_A2A_EXTENSION_URI] }, { x402: true });
    assert.equal(m.calls[2].body.x402, true);
    assert.equal(await mk().guardA2ATask('book-hotel', async () => 'BOOKED', { x402: true })(message(250), { id: 't' }), 'BOOKED');
    assert.equal(m.calls[3].body.x402, true);
  } finally { m.restore(); }
});

test('the permit verdict carries the claim token, non-enumerably', async () => {
  const m = mockIssuer(route());
  try {
    const d = await mk().verifyRequest({ ...message().metadata[MAGP_A2A_EXTENSION_URI] });
    assert.equal(d.decision, 'allow');
    assert.equal(d.claimToken, TOKEN);
    assert.ok(!JSON.stringify(d).includes(TOKEN));
    assert.ok(!Object.keys(d).includes('claimToken'));
  } finally { m.restore(); }
});

test('an older issuer that returns no token still permits', async () => {
  const m = mockIssuer(route({ claim: claim() }));
  try {
    const d = await mk().verifyRequest({ ...message().metadata[MAGP_A2A_EXTENSION_URI] });
    assert.equal(d.decision, 'allow');
    assert.equal(d.claimToken, undefined);
  } finally { m.restore(); }
});

test('capture / release / unknown present the right call, and never throw', async () => {
  const m = mockIssuer(route());
  try {
    const g = mk();
    assert.equal((await g.captureAuthorization({ authorizationId: 'a1', claimToken: TOKEN, amountCharged: 100 })).ok, true);
    assert.equal((await g.releaseAuthorization({ authorizationId: 'a1', claimToken: TOKEN, reason: 'rejected' })).ok, true);
    assert.equal((await g.markAuthorizationUnknown({ authorizationId: 'a1' })).ok, true);
    assert.deepEqual(m.calls.map((c) => c.path), ['/policy/mandate/authorize/a1/capture', '/policy/mandate/authorize/a1/void', '/policy/mandate/authorize/a1/effect/unknown']);
    assert.deepEqual(m.calls[0].body, { amountCharged: 100, claimToken: TOKEN });
    assert.deepEqual(m.calls[1].body, { reason: 'rejected', claimToken: TOKEN });
    assert.equal((await g.captureAuthorization({})).reasonCode, 'AUTHORIZATION_REQUIRED');
  } finally { m.restore(); }
  const real = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('ECONNREFUSED'); };
  try { assert.equal((await mk().releaseAuthorization({ authorizationId: 'a', claimToken: TOKEN })).reasonCode, 'ISSUER_UNREACHABLE'); }
  finally { globalThis.fetch = real; }
});

test('captureAuthorization sends payTo when given (payee directory, MAGP 8.7.14), nothing otherwise; a 409 void refusal reads as not applied', async () => {
  let m = mockIssuer(route());
  try {
    await mk().captureAuthorization({ authorizationId: 'a1', claimToken: TOKEN, amountCharged: 80, payTo: '0.0.5005' });
    assert.deepEqual(m.calls[0].body, { amountCharged: 80, claimToken: TOKEN, payTo: '0.0.5005' });
    await mk().captureAuthorization({ authorizationId: 'a1', claimToken: TOKEN, amountCharged: 100 });
    assert.equal('payTo' in m.calls[1].body, false);
  } finally { m.restore(); }
  m = mockIssuer(route({ void: refusal(409, 'voided', 'HOLD_UNDER_RECONCILIATION', 'the owner has put this hold into reconciliation') }));
  try {
    const r = await mk().releaseAuthorization({ authorizationId: 'a1', claimToken: TOKEN, reason: 'x' });
    assert.equal(r.ok, false);
    assert.equal(r.status, 409);
    assert.equal(r.reasonCode, 'HOLD_UNDER_RECONCILIATION');
  } finally { m.restore(); }
});

test('settlement refusals read as their stable code and status (MAGP 8.7.8); a 200 NOT_HELD void reads its code from data', async () => {
  for (const [call, status, flag, code] of [
    ['capture', 409, 'captured', 'NOT_HELD'], ['capture', 403, 'captured', 'COUNTERPARTY_MISMATCH'], ['capture', 404, 'captured', 'AUTHORIZATION_NOT_FOUND'],
    ['capture', 409, 'captured', 'MANDATE_REVOKED'], ['refund', 409, 'refunded', 'NOT_CAPTURED'], ['refund', 409, 'refunded', 'ALREADY_REFUNDED'],
  ]) {
    const m = mockIssuer(() => refusal(status, flag, code, 'a sentence for people'));
    try {
      const r = call === 'capture' ? await mk().captureAuthorization({ authorizationId: 'a1', claimToken: TOKEN, amountCharged: 100 }) : await mk().refundAuthorization({ authorizationId: 'a1' });
      assert.deepEqual(r, { ok: false, status, reasonCode: code, detail: `${code}: a sentence for people` }, `${call} ${code}`);
    } finally { m.restore(); }
  }
  let m = mockIssuer(route({ void: { status: 200, body: { success: false, message: 'Not voided (NOT_HELD)', data: { voided: false, authorizationId: 'a1', status: 'captured', reasonCode: 'NOT_HELD' } } } }));
  try {
    const r = await mk().releaseAuthorization({ authorizationId: 'a1', claimToken: TOKEN });
    assert.equal(r.ok, false);
    assert.equal(r.reasonCode, 'NOT_HELD');
  } finally { m.restore(); }
  // An older issuer put a sentence in `message` and the code only in data.reasonCode: the code still wins.
  m = mockIssuer(() => ({ status: 400, body: { success: false, message: 'Authorization already settled', data: { reasonCode: 'NOT_HELD' } } }));
  try { assert.equal((await mk().captureAuthorization({ authorizationId: 'a1', amountCharged: 100 })).reasonCode, 'NOT_HELD'); } finally { m.restore(); }
  m = mockIssuer(() => refusal(404, null, 'AUTHORIZATION_NOT_FOUND', 'no authorization with this id'));
  try { assert.deepEqual(await mk().lookupOutcome({ authorizationId: 'a1' }), { ok: false, status: 404, reasonCode: 'AUTHORIZATION_NOT_FOUND' }); } finally { m.restore(); }
});

test('captureAuthorization surfaces settlementEvidence at the top level, same convention as lookupOutcome', async () => {
  const m = mockIssuer(route({ capture: ok200({ captured: true, amountCharged: 100, authorizedAmount: 250, settlementEvidence: 'counterparty_attested' }) }));
  try {
    const r = await mk().captureAuthorization({ authorizationId: 'a1', claimToken: TOKEN, amountCharged: 100 });
    assert.equal(r.ok, true);
    assert.equal(r.settlementEvidence, 'counterparty_attested');
    assert.equal(r.amountCharged, 100);
    assert.equal(r.data.settlementEvidence, 'counterparty_attested'); // .data is unchanged
  } finally { m.restore(); }
});

test('guardA2ATask({ settle: true }) settles a skill that returns and parks one that throws UNKNOWN', async () => {
  let m = mockIssuer(route());
  try {
    const ran = await mk().guardA2ATask('book-hotel', async () => 'BOOKED', { settle: true })(message(250), { id: 't' });
    assert.equal(ran, 'BOOKED');
    assert.deepEqual(m.calls.find((c) => c.path.endsWith('/capture')).body, { amountCharged: 250, claimToken: TOKEN });
  } finally { m.restore(); }
  m = mockIssuer(route());
  try {
    await assert.rejects(() => mk().guardA2ATask('book-hotel', async () => { throw new Error('boom'); }, { settle: true })(message(250), { id: 't' }), /boom/);
    assert.ok(m.calls.some((c) => c.path.endsWith('/effect/unknown')));
    assert.ok(!m.calls.some((c) => c.path.endsWith('/void') || c.path.endsWith('/capture')));
  } finally { m.restore(); }
});

test('without { settle } only the claim is made', async () => {
  const m = mockIssuer(route());
  try {
    assert.equal(await mk().guardA2ATask('book-hotel', async () => 'BOOKED')(message(250), { id: 't' }), 'BOOKED');
    assert.deepEqual(m.calls.map((c) => c.path), ['/policy/mandate/authorize/auth-9/effect/dispatching']);
  } finally { m.restore(); }
});

// --- exactly-once: idempotent claim retry, stable refusal, outcome lookup ---
const isClaimPath = (p) => p.endsWith('/effect/dispatching');

test('the claim carries an Idempotency-Key, and a claim whose response is LOST is retried once with the SAME key', async () => {
  const m = mockIssuer((path, i) => (isClaimPath(path) ? (i === 0 ? 'DROP' : claim({ claimToken: TOKEN, replayed: true })) : route()(path)));
  try {
    const d = await mk().verifyRequest({ ...message().metadata[MAGP_A2A_EXTENSION_URI] });
    assert.equal(d.decision, 'allow');
    assert.equal(d.claimToken, TOKEN);
    const claims = m.calls.map((c, i) => [c, i]).filter(([c]) => isClaimPath(c.path));
    assert.equal(claims.length, 2, 'exactly one retry');
    const [k0, k1] = claims.map(([, i]) => m.headers[i]['idempotency-key']);
    assert.match(k0, /^[0-9a-f]{32}$/);
    assert.equal(k0, k1);
  } finally { m.restore(); }
});

test('a definite refusal (AUTHORIZATION_ALREADY_CLAIMED) is final — never retried', async () => {
  const m = mockIssuer(route({ claim: refusal(409, null, 'AUTHORIZATION_ALREADY_CLAIMED', 'the authorization was already claimed (or settled)', 'auth-9') }));
  try {
    const d = await mk().verifyRequest({ ...message().metadata[MAGP_A2A_EXTENSION_URI] });
    assert.equal(d.decision, 'block');
    assert.equal(d.reasonCode, 'AUTHORIZATION_ALREADY_CLAIMED');
    assert.equal(m.calls.length, 1);
  } finally { m.restore(); }
});

test('lookupOutcome reads the public effect status and never throws', async () => {
  const data = { authorizationId: 'a1', outcome: 'settled', nothingExecuted: false };
  let m = mockIssuer(() => ok200(data));
  try {
    assert.deepEqual(await mk().lookupOutcome({ authorizationId: 'a1' }), { ok: true, ...data });
    assert.equal(m.calls[0].path, '/policy/mandate/authorize/a1/effect');
  } finally { m.restore(); }
  m = mockIssuer(() => 'DROP');
  try { assert.equal((await mk().lookupOutcome({ authorizationId: 'a1' })).reasonCode, 'ISSUER_UNREACHABLE'); } finally { m.restore(); }
  assert.equal((await mk().lookupOutcome({})).reasonCode, 'AUTHORIZATION_REQUIRED');
});

// --- refund: record-only reversal of a captured hold ---
test('refundAuthorization posts amount/reason to /refund, validates locally, and never throws', async () => {
  const m = mockIssuer(() => ok200({ refunded: true, refundAmount: 40, remainingCaptured: 60 }));
  try {
    const g = mk();
    const r = await g.refundAuthorization({ authorizationId: 'a1', amount: 40, reason: 'returned' });
    assert.equal(r.ok, true);
    assert.equal(r.remainingCaptured, 60);
    await g.refundAuthorization({ authorizationId: 'a1', claimToken: TOKEN });
    assert.deepEqual(m.calls.map((c) => [c.path, c.body]), [['/policy/mandate/authorize/a1/refund', { amount: 40, reason: 'returned' }], ['/policy/mandate/authorize/a1/refund', { claimToken: TOKEN }]]);
    assert.equal((await g.refundAuthorization({})).reasonCode, 'AUTHORIZATION_REQUIRED');
    assert.equal((await g.refundAuthorization({ authorizationId: 'a1', amount: 0 })).reasonCode, 'REFUND_AMOUNT_INVALID');
    assert.equal(m.calls.length, 2, 'invalid input never reaches the issuer');
  } finally { m.restore(); }
  const d = mockIssuer(() => 'DROP');
  try { assert.equal((await mk().refundAuthorization({ authorizationId: 'a1' })).reasonCode, 'ISSUER_UNREACHABLE'); } finally { d.restore(); }
});

test('a keyed receiver signs its refund under the dedicated "refund" action over [amount, reason], never as a void', async () => {
  const svc = crypto.generateKeyPairSync('ed25519');
  const svcDid = buildHederaDid('testnet', svc.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), '0.0.911');
  const g = createA2aGuard({ allowedAgents: 'any', issuerApi: ISSUER, fetchBundle: async () => bundle, serviceDid: svcDid, serviceKey: svc.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex') });
  const m = mockIssuer(() => ok200({ refunded: true }));
  try {
    await g.refundAuthorization({ authorizationId: 'a1', amount: 10, reason: 'partial' });
    const h = m.headers[0];
    const esc = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
    const msg = (action, fields) => ['MAGP-SERVICE-v1', action, 'a1', ...fields, h['x-magp-service-nonce'], h['x-magp-service-issued-at']].map(esc).join('|');
    const verifies = (m) => crypto.verify(null, Buffer.from(m, 'utf8'), svc.publicKey, Buffer.from(h['x-magp-service-signature'], 'hex'));
    assert.equal(h['x-magp-service-did'], svcDid);
    assert.ok(verifies(msg('refund', ['10', 'partial'])));
    assert.ok(!verifies(msg('void', ['partial'])), 'never replayable as a void');
  } finally { m.restore(); }
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  ok   ' + name); }
  catch (err) { failed++; console.log('  FAIL ' + name + '\n       ' + (err?.stack ?? err)); }
}
if (failed) { console.log(`\n${failed} of ${t.length} FAILED`); process.exit(1); }
console.log(`\nPASS — ${t.length} a2a claim-token cases`);

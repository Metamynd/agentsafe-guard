// payload-binding.smoke.mjs — the agent side of payload binding (spec 8.3.9): pass `payload` to authorize()/buildSignedRequest()
// and the guard signs, with the agent's own key, a digest of the COMPLETE payload bound to that one authorization. Nothing
// here touches a network except through a mocked fetch.
//
//   node payload-binding.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';
import { buildPayloadBindingMessage, payloadDigestOf } from './payload-binding.mjs';

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const agentDid = 'did:hedera:testnet:z6MkSmoke_0.0.2';
const verifies = (message, sigHex) => crypto.verify(null, Buffer.from(message, 'utf8'), publicKey, Buffer.from(sigHex, 'hex'));

let failed = 0;
function check(ok, name) { if (!ok) failed++; console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`); }

const PAYLOAD = { passenger: 'A. Traveller', payee: { iban: 'GB00AAAA', name: 'Skyward Air' }, amount: 250 };
const base = { action: 'flight-purchase', amount: 250, merchant: 'skyward-air' };
const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });

// --- no payload: nothing about payload binding appears (legacy wire body) ---
{
  const req = await guard.buildSignedRequest(base);
  check(req.payloadDigest === undefined && req.payloadSignature === undefined, 'no payload → no payloadDigest / payloadSignature');
  check(!JSON.stringify(req).includes('payload'), 'no payload → the serialised request mentions no payload field at all');
}

// --- with a payload: digest is the RFC 8785 digest, signature genuinely verifies for THIS authorization ---
{
  const req = await guard.buildSignedRequest({ ...base, payload: PAYLOAD });
  check(req.payloadDigest === payloadDigestOf(PAYLOAD), 'payloadDigest is the canonical digest of the payload');
  const msg = buildPayloadBindingMessage({ agentDid, action: req.action, nonce: req.nonce, issuedAt: req.issuedAt, payloadDigest: req.payloadDigest });
  check(verifies(msg, req.payloadSignature), 'payloadSignature verifies over the domain-separated binding message');
  check(!verifies(buildPayloadBindingMessage({ agentDid, action: req.action, nonce: 'another-nonce', issuedAt: req.issuedAt, payloadDigest: req.payloadDigest }), req.payloadSignature), 'the signature does not verify for another nonce (cannot be lifted onto another authorization)');
  check(!verifies(buildPayloadBindingMessage({ agentDid, action: 'wire-transfer', nonce: req.nonce, issuedAt: req.issuedAt, payloadDigest: req.payloadDigest }), req.payloadSignature), 'the signature does not verify for another action');
  check(!verifies(req.payloadDigest, req.payloadSignature), 'the signature is not over the bare digest (domain separated)');
}

// --- key order and whitespace are not part of the payload: same digest ---
{
  const a = await guard.buildSignedRequest({ ...base, payload: { b: 1, a: [1, 2, { y: 1, x: 2 }] } });
  const b = await guard.buildSignedRequest({ ...base, payload: { a: [1, 2, { x: 2, y: 1 }], b: 1 } });
  check(a.payloadDigest === b.payloadDigest, 'the digest is independent of key order');
  const c = await guard.buildSignedRequest({ ...base, payload: { a: [1, 2, { x: 2, y: 1 }], b: 2 } });
  check(a.payloadDigest !== c.payloadDigest, 'a changed value changes the digest');
}

// --- authorize(): the binding rides on the wire body; a payload that cannot be bound is a BLOCK, never an unbound send ---
{
  const realFetch = globalThis.fetch;
  let sent = null;
  let voided = null; let echo = true;
  globalThis.fetch = async (url, opts) => {
    if (String(url).endsWith('/void')) { voided = String(url); return { status: 200, json: async () => ({}) }; }
    sent = JSON.parse(opts.body);
    // A compliant gate acknowledges the binding by echoing the digest it stored (null when unbound).
    return { status: 200, json: async () => ({ data: { decision: 'allow', authorizationId: 'auth-1', ...(echo ? { payloadDigest: sent.payloadDigest ?? null } : {}) } }) };
  };
  try {
    const r = await guard.authorize({ ...base, payload: PAYLOAD });
    check(r.decision === 'allow' && sent.payloadDigest === payloadDigestOf(PAYLOAD) && typeof sent.payloadSignature === 'string', 'authorize() sends payloadDigest and payloadSignature on the wire');
    check(verifies(buildPayloadBindingMessage({ agentDid, action: sent.action, nonce: sent.nonce, issuedAt: sent.issuedAt, payloadDigest: sent.payloadDigest }), sent.payloadSignature), 'the wire signature verifies against the wire nonce/issuedAt');

    sent = null;
    await guard.authorize(base);
    check(sent && !('payloadDigest' in sent) && !('payloadSignature' in sent), 'authorize() without a payload sends the legacy body');

    // A gate that does not acknowledge the binding (an older backend, or a hop stripped the fields): the request was never bound.
    echo = false; voided = null;
    const unconfirmed = await guard.authorize({ ...base, payload: PAYLOAD });
    check(unconfirmed.decision === 'block' && unconfirmed.reasonCode === 'PAYLOAD_BINDING_NOT_CONFIRMED' && unconfirmed.authorizationId === null, 'a permit that does not echo the digest is refused PAYLOAD_BINDING_NOT_CONFIRMED');
    await new Promise((r) => setTimeout(r, 20));
    check(!!voided && voided.endsWith('/policy/mandate/authorize/auth-1/void'), '...and the hold it just got is released (best effort)');
    voided = null;
    const unboundOld = await guard.authorize(base);
    check(unboundOld.decision === 'allow' && voided === null, 'an UNBOUND request against the same gate is unaffected');
    echo = true;

    sent = null;
    const bad = await guard.authorize({ ...base, payload: { a: '\ud800' } });
    check(bad.decision === 'block' && bad.reasonCode === 'PAYLOAD_NOT_CANONICALIZABLE' && sent === null, 'a payload JSON cannot carry (lone surrogate) blocks and sends NOTHING');

    sent = null;
    const fn = await guard.authorize({ ...base, payload: () => 1 });
    check(fn.decision === 'block' && fn.reasonCode === 'PAYLOAD_NOT_CANONICALIZABLE' && sent === null, 'a bare function payload blocks and sends NOTHING');
  } finally { globalThis.fetch = realFetch; }
}

// --- a keyProvider that cannot sign a binding fails CLOSED, with the real cause (not GATE_UNREACHABLE, not an unbound send) ---
{
  const inner = (await import('./key-providers.mjs')).createStaticKeyProvider(agentKey);
  const { signPayloadBinding: _omit, ...withoutBinding } = inner;
  const g = createGuard({ api: 'http://unused.local/api/v1', agentDid, keyProvider: withoutBinding });
  const realFetch = globalThis.fetch; let called = false;
  globalThis.fetch = async () => { called = true; return { status: 200, json: async () => ({ data: { decision: 'allow' } }) }; };
  try {
    const r = await g.authorize({ ...base, payload: PAYLOAD });
    check(r.decision === 'block' && r.reasonCode === 'PAYLOAD_BINDING_UNSUPPORTED' && !called, 'a provider without signPayloadBinding blocks with PAYLOAD_BINDING_UNSUPPORTED and sends nothing');
    called = false;
    const ok = await g.authorize(base);
    check(ok.decision === 'allow' && called, 'the same provider still authorizes an unbound request');
  } finally { globalThis.fetch = realFetch; }
}

// --- the daemon provider: an unreachable signer is its own failure; a signer that PREDATES sign-payload is "unsupported" and
//     fails closed (never an unbound send). The real-daemon round trip lives in daemon-keyprovider.smoke.mjs (monorepo-only). ---
{
  const net = await import('node:net');
  const os = await import('node:os');
  const path = await import('node:path');
  const fs = await import('node:fs');
  const { createDaemonKeyProvider } = await import('./key-providers.mjs');

  let code = null;
  try { await createDaemonKeyProvider({ socketPath: path.join(os.tmpdir(), 'no-such-signer.sock') }).signPayloadBinding({}); } catch (e) { code = e.code; }
  check(code === 'DAEMON_UNREACHABLE', 'an unreachable signer daemon is DAEMON_UNREACHABLE (not "unsupported")');

  // A minimal stand-in for an OLD daemon: it answers every op with DAEMON_UNKNOWN_OPERATION. The socket name follows the same
  // platform translation the real daemon and client use.
  const logical = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'old-signer-')), 'signer.sock');
  const listenOn = process.platform === 'win32'
    ? `\\\\.\\pipe\\agentsafe-signer-${(await import('node:crypto')).createHash('sha256').update(path.resolve(logical)).digest('hex').slice(0, 32)}`
    : logical;
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (c) => {
      buf += c.toString('utf8');
      if (!buf.includes('\n')) return;
      const req = JSON.parse(buf.slice(0, buf.indexOf('\n')));
      // An OLD daemon still signs everything it knew about; it just has no `sign-payload`.
      const reply = req.op === 'sign-payload'
        ? { ok: false, error: { code: 'DAEMON_UNKNOWN_OPERATION', message: `unknown operation ${req.op}` } }
        : { ok: true, result: { signature: 'ab'.repeat(64), envelopeSignature: 'ab'.repeat(64) } };
      sock.end(JSON.stringify({ protocolVersion: 1, requestId: req.requestId, ...reply }) + '\n');
    });
  });
  await new Promise((r) => server.listen(listenOn, r));
  try {
    const old = createDaemonKeyProvider({ socketPath: logical });
    let unsupported = null;
    try { await old.signPayloadBinding({ agentDid, action: 'a', nonce: 'n', issuedAt: 't', payloadDigest: 'sha256:' + '0'.repeat(64) }); } catch (e) { unsupported = e; }
    check(unsupported?.code === 'PAYLOAD_BINDING_UNSUPPORTED' && /upgrade/.test(unsupported.message), 'a daemon that predates sign-payload is reported as PAYLOAD_BINDING_UNSUPPORTED, naming the fix');

    const realFetch = globalThis.fetch; let sent = false;
    globalThis.fetch = async () => { sent = true; return { status: 200, json: async () => ({ data: { decision: 'allow' } }) }; };
    try {
      const g = createGuard({ api: 'http://unused.local/api/v1', agentDid, keyProvider: old });
      const r = await g.authorize({ ...base, payload: PAYLOAD });
      check(r.decision === 'block' && r.reasonCode === 'PAYLOAD_BINDING_UNSUPPORTED' && !sent, 'authorize() with payload against an old daemon blocks PAYLOAD_BINDING_UNSUPPORTED and sends nothing');
    } finally { globalThis.fetch = realFetch; }
  } finally { server.close(); }
}

// --- bindPayload(): the late binding of a hold that already exists (a reviewer's MODIFY minted it with no digest) ---
{
  const { buildPayloadRebindMessage } = await import('./payload-binding.mjs');
  const AUTH_ID = '7f3c1d2e-9a4b-4c5d-8e6f-0a1b2c3d4e5f';
  const realFetch = globalThis.fetch;
  let call = null; let answer = null;
  globalThis.fetch = async (url, opts) => { call = { url: String(url), body: JSON.parse(opts.body) }; return answer(call); };
  try {
    answer = (c) => ({ ok: true, status: 200, json: async () => ({ data: { authorizationId: AUTH_ID, payloadDigest: c.body.payloadDigest } }) });
    const r = await guard.bindPayload({ authorizationId: AUTH_ID, action: base.action, payload: PAYLOAD });
    check(r.bound === true && r.payloadDigest === payloadDigestOf(PAYLOAD), 'bindPayload() binds and reports the digest');
    check(call.url.endsWith(`/policy/mandate/authorize/${AUTH_ID}/payload-binding`), '...to the hold it names');
    const b = call.body;
    check(verifies(buildPayloadRebindMessage({ agentDid, action: b.action, authorizationId: AUTH_ID, nonce: b.nonce, issuedAt: b.issuedAt, payloadDigest: b.payloadDigest }), b.payloadSignature), 'the signature verifies over the REBIND message, which names the authorization id');
    check(!verifies(buildPayloadBindingMessage({ agentDid, action: b.action, nonce: b.nonce, issuedAt: b.issuedAt, payloadDigest: b.payloadDigest }), b.payloadSignature), 'and NOT over the authorize-time binding message (its own domain)');
    check(!verifies(buildPayloadRebindMessage({ agentDid, action: b.action, authorizationId: '00000000-0000-4000-8000-000000000000', nonce: b.nonce, issuedAt: b.issuedAt, payloadDigest: b.payloadDigest }), b.payloadSignature), 'nor for another authorization id (cannot be lifted onto another hold)');

    answer = (c) => ({ ok: true, status: 200, json: async () => ({ data: { authorizationId: AUTH_ID, payloadDigest: c.body.payloadDigest, alreadyBound: true } }) });
    check((await guard.bindPayload({ authorizationId: AUTH_ID, action: base.action, payload: PAYLOAD })).alreadyBound === true, 'an idempotent retry is reported as alreadyBound');

    answer = () => ({ ok: false, status: 409, json: async () => ({ message: 'PAYLOAD_ALREADY_BOUND', data: { reasonCode: 'PAYLOAD_ALREADY_BOUND' } }) });
    const refused = await guard.bindPayload({ authorizationId: AUTH_ID, action: base.action, payload: PAYLOAD });
    check(refused.bound === false && refused.reasonCode === 'PAYLOAD_ALREADY_BOUND', 'a gate refusal is bound:false with its reason code, never a throw');

    answer = () => ({ ok: true, status: 200, json: async () => ({ data: { decision: 'allow' } }) });
    check((await guard.bindPayload({ authorizationId: AUTH_ID, action: base.action, payload: PAYLOAD })).reasonCode === 'PAYLOAD_BINDING_NOT_CONFIRMED', 'a 200 that does not echo our digest (an issuer that predates late binding) is NOT bound');

    call = null;
    check((await guard.bindPayload({ authorizationId: AUTH_ID, action: base.action, payload: { a: '\ud800' } })).reasonCode === 'PAYLOAD_NOT_CANONICALIZABLE' && call === null, 'a payload JSON cannot carry is refused locally and sends nothing');
    check((await guard.bindPayload({ action: base.action, payload: PAYLOAD })).reasonCode === 'MALFORMED_REQUEST' && call === null, 'a missing authorizationId is refused locally');

    const inner = (await import('./key-providers.mjs')).createStaticKeyProvider(agentKey);
    const { signPayloadBinding: _omit, ...without } = inner;
    const g = createGuard({ api: 'http://unused.local/api/v1', agentDid, keyProvider: without });
    check((await g.bindPayload({ authorizationId: AUTH_ID, action: base.action, payload: PAYLOAD })).reasonCode === 'PAYLOAD_BINDING_UNSUPPORTED' && call === null, 'a provider that cannot sign a binding is PAYLOAD_BINDING_UNSUPPORTED and sends nothing');

    globalThis.fetch = async () => { throw new Error('connect ECONNREFUSED'); };
    check((await guard.bindPayload({ authorizationId: AUTH_ID, action: base.action, payload: PAYLOAD })).reasonCode === 'GATE_UNREACHABLE', 'an unreachable gate is GATE_UNREACHABLE');
  } finally { globalThis.fetch = realFetch; }
}

console.log(failed ? `\nFAIL — ${failed} check(s) failed` : '\nPASS');
process.exit(failed ? 1 : 0);

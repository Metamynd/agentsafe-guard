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

// --- the daemon provider refuses loudly until the signer daemon supports it ---
{
  const { createDaemonKeyProvider } = await import('./key-providers.mjs');
  const daemon = createDaemonKeyProvider({ socketPath: '/nonexistent.sock' });
  let code = null;
  try { await daemon.signPayloadBinding({}); } catch (e) { code = e.code; }
  check(code === 'PAYLOAD_BINDING_UNSUPPORTED', 'the daemon key provider refuses payload binding with PAYLOAD_BINDING_UNSUPPORTED');
}

console.log(failed ? `\nFAIL — ${failed} check(s) failed` : '\nPASS');
process.exit(failed ? 1 : 0);

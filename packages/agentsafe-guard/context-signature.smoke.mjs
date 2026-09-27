// context-signature.smoke.mjs — proves the Tier 1 context-claim binding opt-in
// (docs/design/context-claim-binding.md): with signContext:true the guard signs the
// GovernanceEnvelope hash (context included) with the same agent key, the signature
// genuinely verifies against that hash, and it changes when context changes — the
// property the original tester report found missing. Off by default: no network.
//
//   node context-signature.smoke.mjs
//
// Exits 0 and prints PASS when every case matches; exits 1 on the first mismatch.
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';
import { envelopeHashFor } from './governance-envelope.mjs';
import { createStaticKeyProvider } from './key-providers.mjs';
import { buildHederaDid, verifyDidSignature } from './magp-did.mjs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { existsSync, readFileSync } from 'node:fs';

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const agentDid = 'did:hedera:testnet:z6MkSmoke_0.0.2';

function verifies(hash, sigHex) {
  return crypto.verify(null, Buffer.from(hash, 'utf8'), publicKey, Buffer.from(sigHex, 'hex'));
}

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}

// --- opt-out (signContext: false): no envelopeSignature at all, the legacy wire body ---
{
  const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey, signContext: false });
  const req = await guard.buildSignedRequest({ action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } });
  check(req.envelopeSignature === undefined, 'signContext: false → no envelopeSignature field');
  check(!('envelopeSignature' in JSON.parse(JSON.stringify(req))), 'signContext: false → JSON.stringify drops the field entirely (legacy wire body)');
}

// --- the default (0.17.0: ON): envelopeSignature is present and genuinely verifies ---
{
  const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });
  const request = { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } };
  const req = await guard.buildSignedRequest(request);
  check(typeof req.envelopeSignature === 'string' && req.envelopeSignature.length > 0, 'default → envelopeSignature present');
  const explicit = await createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey, signContext: true }).buildSignedRequest(request);
  check(typeof explicit.envelopeSignature === 'string', 'signContext: true → envelopeSignature present (same as the default)');

  const expectedHash = envelopeHashFor({
    agentDid, action: req.action, amount: req.amount, currency: req.currency, merchant: req.merchant,
    itinerary: req.itinerary, trace: req.trace, materiality: req.materiality, nonce: req.nonce, issuedAt: req.issuedAt,
    signature: '',
  });
  check(verifies(expectedHash, req.envelopeSignature), 'envelopeSignature genuinely verifies against the envelope hash (same key as the action signature)');

  // The exact case the external tester found unsigned: swap context after the fact.
  const tamperedHash = envelopeHashFor({
    agentDid, action: req.action, amount: req.amount, currency: req.currency, merchant: req.merchant,
    itinerary: { riskLevel: 'high' }, trace: req.trace, materiality: req.materiality, nonce: req.nonce, issuedAt: req.issuedAt,
    signature: '',
  });
  check(!verifies(tamperedHash, req.envelopeSignature), 'a context swap after signing fails verification (this is what riskLevel low→high after signing now catches)');

  // Action-subset signature is unaffected — same as always.
  check(typeof req.signature === 'string' && req.signature.length > 0, 'action-subset signature is still present and separate');
}

// --- what is signed is what the gate hashes: JSON values, and only the trace keys the gate's schema keeps ---
{
  const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });
  const when = new Date('2026-01-02T03:04:05.000Z');
  const req = await guard.buildSignedRequest({ action: 'a', amount: 1, currency: 'USD', context: { when, gone: undefined }, trace: { workflowId: 'w', custom: 'x' }, materiality: { at: when } });
  check(req.itinerary.when === when.toISOString() && !('gone' in req.itinerary), 'the itinerary is sent as its JSON (a Date as its string, an undefined member dropped)');
  check(req.trace.workflowId === 'w' && !('custom' in req.trace), 'a trace key the gate would strip is not sent (or signed)');
  // What the gate does: parse the JSON body, strip unknown trace keys (zod), hash with envelopeHashFor.
  const wire = JSON.parse(JSON.stringify(req));
  check(verifies(envelopeHashFor({ ...wire, signature: '' }), req.envelopeSignature), 'the signature verifies over the request as the gate parses it');
  const optOut = await createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey, signContext: false }).buildSignedRequest({ action: 'a', trace: { custom: 'x' } });
  check(optOut.trace.custom === 'x', 'signContext: false → fields sent exactly as given, as before');
}

// --- authorize() posts a verifying envelopeSignature by default, none with signContext: false ---
{
  const realFetch = globalThis.fetch;
  const posted = [];
  globalThis.fetch = async (_url, init) => { posted.push(JSON.parse(init.body)); return new Response(JSON.stringify({ data: { decision: 'allow', reasonCode: 'AUTHORIZED' } }), { status: 200 }); };
  try {
    await createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid, agentKey }).authorize({ action: 'lookup', context: { riskLevel: 'low' } });
    const body = posted.at(-1);
    check(typeof body.envelopeSignature === 'string' && verifies(envelopeHashFor({ ...body, signature: '' }), body.envelopeSignature), 'authorize() default: the posted body carries an envelopeSignature over its own envelope (amount/currency omitted)');
    await createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid, agentKey }).authorize({ action: 'pay', amount: 5, context: { riskLevel: 'low' } });
    const b2 = posted.at(-1);
    check(b2.currency === undefined && verifies(envelopeHashFor({ ...b2, signature: '' }), b2.envelopeSignature), 'authorize() default, currency omitted: verifies over the wire (no USD default in the hash)');
    await createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid, agentKey, signContext: false }).authorize({ action: 'lookup' });
    check(!('envelopeSignature' in posted.at(-1)), 'authorize() with signContext: false posts no envelopeSignature');
  } finally {
    globalThis.fetch = realFetch;
  }
}

// --- a key provider that cannot sign the context: fail CLOSED, never send it unsigned ---
{
  const custom = { async signAuthorize() { return 'aa'; } };
  const guard = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid, keyProvider: custom });
  let code;
  try { await guard.buildSignedRequest({ action: 'a' }); } catch (e) { code = e.code; }
  check(code === 'CONTEXT_SIGNING_UNSUPPORTED', 'a custom keyProvider without signEnvelope → buildSignedRequest throws CONTEXT_SIGNING_UNSUPPORTED');
  const d = await guard.authorize({ action: 'a' });
  check(d.decision === 'block' && d.reasonCode === 'CONTEXT_SIGNING_UNSUPPORTED', 'and authorize() refuses locally with CONTEXT_SIGNING_UNSUPPORTED (nothing sent)');
  const off = await createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid, keyProvider: custom, signContext: false }).buildSignedRequest({ action: 'a' });
  check(off.signature === 'aa' && off.envelopeSignature === undefined, 'the same provider with signContext: false signs as before');
}

// --- the daemon key provider: an older signer's context signature is checked, not trusted ---
{
  const { publicKey: dPub, privateKey: dPriv } = crypto.generateKeyPairSync('ed25519');
  const dSpki = dPub.export({ type: 'spki', format: 'der' });
  const dDid = buildHederaDid('testnet', dSpki.subarray(dSpki.length - 32), '0.0.7');
  const dSign = (m) => crypto.sign(null, Buffer.from(m, 'utf8'), dPriv).toString('hex');
  const socketFor = (logical) => (process.platform !== 'win32' ? logical : `\\\\.\\pipe\\agentsafe-signer-${crypto.createHash('sha256').update(path.resolve(logical)).digest('hex').slice(0, 32)}`);
  // mode: 'current' (signer >= 0.19.0), 'old' (hashes currency as 'USD', refuses an omitted amount), 'none' (no op).
  async function withDaemon(mode, fn) {
    const logical = path.join(os.tmpdir(), `agentsafe-ctx-${process.pid}-${crypto.randomUUID().slice(0, 8)}.sock`);
    const server = net.createServer((sock) => {
      let buf = '';
      sock.on('data', (chunk) => {
        buf += chunk;
        const i = buf.indexOf('\n');
        if (i < 0) return;
        const req = JSON.parse(buf.slice(0, i));
        const reply = (o) => sock.end(JSON.stringify({ requestId: req.requestId, ...o }) + '\n');
        const p = req.params;
        if (req.op === 'sign-authorize') return reply({ ok: true, result: { signature: 'aa' } });
        if (mode === 'none') return reply({ ok: false, error: { code: 'DAEMON_UNKNOWN_OPERATION' } });
        if (mode === 'old' && p.amount === undefined) return reply({ ok: false, error: { code: 'DAEMON_MALFORMED_REQUEST', message: 'amount must be finite and non-negative' } });
        const fields = mode === 'old' ? { ...p, currency: p.currency ?? 'USD' } : p;
        return reply({ ok: true, result: { envelopeSignature: dSign(envelopeHashFor({ ...fields, signature: '' })) } });
      });
    });
    await new Promise((r) => server.listen(socketFor(logical), r));
    try {
      return await fn(createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: dDid, keyProvider: 'daemon', daemonSocketPath: logical }));
    } finally {
      await new Promise((r) => server.close(r));
    }
  }
  const codeOf = async (p) => { try { await p; return 'ok'; } catch (e) { return e.code; } };
  await withDaemon('current', async (g) => {
    const r = await g.buildSignedRequest({ action: 'a', amount: 5, context: { riskLevel: 'low' } });
    check(verifyDidSignature(dDid, envelopeHashFor({ ...JSON.parse(JSON.stringify(r)), signature: '' }), r.envelopeSignature), 'a current daemon: the default context signature verifies (currency omitted)');
    check((await codeOf(g.buildSignedRequest({ action: 'a' }))) === 'ok', 'a current daemon signs a request with amount and currency omitted');
  });
  await withDaemon('old', async (g) => {
    check((await codeOf(g.buildSignedRequest({ action: 'a', amount: 5, currency: 'USD' }))) === 'ok', 'an older daemon still signs a request whose amount and currency are both sent');
    check((await codeOf(g.buildSignedRequest({ action: 'a', amount: 5 }))) === 'ok', 'an older daemon, buildSignedRequest with amount only (it sends currency USD) → signed');
    check((await codeOf(g.buildSignedRequest({ action: 'a' }))) === 'CONTEXT_SIGNING_UNSUPPORTED', 'an older daemon, amount omitted (it refuses) → CONTEXT_SIGNING_UNSUPPORTED');
    const d = await g.authorize({ action: 'a', amount: 5 });
    check(d.reasonCode === 'CONTEXT_SIGNING_UNSUPPORTED', 'authorize() through it, currency omitted on the wire (it would hash USD) → refused locally CONTEXT_SIGNING_UNSUPPORTED, not a wrong signature');
  });
  await withDaemon('none', async (g) => {
    check((await codeOf(g.buildSignedRequest({ action: 'a', amount: 5, currency: 'USD' }))) === 'CONTEXT_SIGNING_UNSUPPORTED', 'a daemon with no sign-envelope → CONTEXT_SIGNING_UNSUPPORTED');
  });
}

// --- the shared vectors (docs/protocol/context-signature-vectors.json, generated from the backend's envelopeHashFor):
// this package's signer reproduces the gate's hash and, Ed25519 being deterministic, the exact envelopeSignature the
// receivers (agentsafe-mcp-guard, agentsafe-a2a-guard) and the gate verify against the same file ---
{
  // The vectors live in the monorepo's docs/protocol/; a copy of this package without them (the public mirror) skips this block.
  const vectorsUrl = new URL('../../docs/protocol/context-signature-vectors.json', import.meta.url);
  const doc = existsSync(vectorsUrl) ? JSON.parse(readFileSync(vectorsUrl, 'utf8')) : (console.log('SKIP  docs/protocol/context-signature-vectors.json not present'), { vectors: [] });
  const provider = createStaticKeyProvider(Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(doc.seed, 'hex')]).toString('hex'));
  for (const v of doc.vectors) {
    const { signature: _s, envelopeSignature, resource: _r, jurisdiction: _j, payloadDigest: _d, payloadSignature: _p, ...fields } = v.request;
    check(envelopeHashFor({ ...fields, signature: '' }) === v.envelopeHash, `vector "${v.name}": envelopeHashFor reproduces the backend's hash`);
    check((await provider.signEnvelope(fields)) === envelopeSignature, `vector "${v.name}": the guard's signer reproduces the envelopeSignature`);
  }
}

if (failed) {
  console.error(`\n${failed} case(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS - context-claim binding: on by default (signContext: false opts out), the envelope signature verifies, detects context tampering, and fails closed when it cannot be produced.');

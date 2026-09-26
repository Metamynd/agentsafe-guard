// jurisdiction.smoke.mjs — the signed jurisdiction (MAGP 8.3.12) end to end in the guard, with no network:
//   1. the static key provider reproduces BOTH shared vector files byte for byte (v1: docs/protocol/authorize-vectors.json,
//      v2: authorize-v2-vectors.json);
//   2. buildSignedRequest / authorize normalise a caller's jurisdiction, send it top-level and sign the v2 message over the
//      SAME value; absent → the v1 message and no field; malformed → refused locally, never sent;
//   3. a context `jurisdiction` is never promoted, signed, or judged;
//   4. local evaluation judges the signed value only (mandate term + SOP atom), JURISDICTION_REQUIRED as at the gate;
//   5. the daemon key provider refuses (JURISDICTION_SIGNING_UNSUPPORTED) a daemon that did not sign the jurisdiction.
//
//   node jurisdiction.smoke.mjs
import crypto from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import os from 'node:os';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createGuard, normalizeJurisdiction, JURISDICTION_REASON_CODES } from './agentsafe-guard.mjs';
import { createStaticKeyProvider, createDaemonKeyProvider, authorizeFieldsOf } from './key-providers.mjs';
import { buildAuthMessage } from './policy-core.mjs';
import { verifyDidSignature } from './magp-did.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsOf = (name) => JSON.parse(readFileSync(path.join(here, '..', '..', 'docs', 'protocol', name), 'utf8'));
const v1 = vectorsOf('authorize-vectors.json');
const v2 = vectorsOf('authorize-v2-vectors.json');

let failed = 0;
const check = (ok, label) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) failed++;
};

// --- 1. the shared vectors ---------------------------------------------------------------------------------------
const DER_PREFIX = '302e020100300506032b657004220420';
for (const [file, doc] of [['authorize-vectors.json', v1], ['authorize-v2-vectors.json', v2]]) {
  const provider = createStaticKeyProvider(DER_PREFIX + doc.seed);
  for (const v of doc.vectors) {
    const fields = authorizeFieldsOf(v.fields);
    check(buildAuthMessage(fields) === v.message, `${file} "${v.name}": message rebuilt byte for byte`);
    check((await provider.signAuthorize(v.fields)) === v.signature, `${file} "${v.name}": signature reproduced byte for byte`);
  }
}
check(v2.vectors.some((v) => v.fields.jurisdiction) && v2.vectors.some((v) => v.fields.jurisdiction === null), 'the v2 file carries both v2 vectors and a v1 control');

// --- 2 + 3. buildSignedRequest / authorize ---------------------------------------------------------------------------
const agentKey = DER_PREFIX + v2.seed;
const agentDid = v2.vectors[0].fields.agentDid; // did:key of the RFC 8032 test key
const guard = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid, agentKey, mode: 'remote' });

const withJ = await guard.buildSignedRequest({ action: 'flight-purchase', amount: 150, merchant: 'skyward-air', jurisdiction: ' sg ' });
check(withJ.jurisdiction === 'SG', 'jurisdiction normalised (trimmed, upper-cased) and sent top-level');
check(verifyDidSignature(agentDid, buildAuthMessage(withJ), withJ.signature), 'the request verifies as the v2 message over exactly what was sent');
check(buildAuthMessage(withJ).endsWith('|MAGP-AUTH-v2|SG'), 'the signed message is v2 (tag, then the jurisdiction)');
const { jurisdiction: _dropped, ...stripped } = withJ;
check(!verifyDidSignature(agentDid, buildAuthMessage(stripped), withJ.signature), 'stripping the field breaks the signature (no v1 fallback)');
check(!verifyDidSignature(agentDid, buildAuthMessage({ ...withJ, jurisdiction: 'DE' }), withJ.signature), 'changing the field breaks the signature');

const without = await guard.buildSignedRequest({ action: 'flight-purchase', amount: 150, merchant: 'skyward-air' });
check(!('jurisdiction' in without), 'no jurisdiction given → no field on the wire');
check(verifyDidSignature(agentDid, buildAuthMessage(without), without.signature) && !buildAuthMessage(without).includes('MAGP-AUTH-v2'), 'no jurisdiction → the v1 message, as before');

const ctxOnly = await guard.buildSignedRequest({ action: 'flight-purchase', amount: 150, context: { jurisdiction: 'SG' } });
check(!('jurisdiction' in ctxOnly) && !buildAuthMessage(ctxOnly).includes('MAGP-AUTH-v2'), 'a context jurisdiction is never promoted to the signed field');

for (const bad of ['SGP', 'S', '', 'ß', 'S1', 42, 'é']) {
  let code = null;
  try {
    await guard.buildSignedRequest({ action: 'flight-purchase', amount: 1, jurisdiction: bad });
  } catch (err) {
    code = err.code;
  }
  check(code === 'MALFORMED_REQUEST', `buildSignedRequest refuses jurisdiction ${JSON.stringify(bad)} locally`);
}
check(normalizeJurisdiction(null) === undefined && normalizeJurisdiction('de') === 'DE', 'normalizeJurisdiction: null → none, "de" → "DE"');
check(JSON.stringify(JURISDICTION_REASON_CODES) === JSON.stringify(['JURISDICTION_REQUIRED', 'JURISDICTION_NOT_ALLOWED', 'JURISDICTION_MISMATCH']), 'the three gate codes are exported');

const realFetch = globalThis.fetch;
const posted = [];
globalThis.fetch = async (url, init) => {
  posted.push({ url: String(url), body: JSON.parse(init.body) });
  return new Response(JSON.stringify({ success: false, data: { decision: 'block', reasonCode: 'JURISDICTION_MISMATCH' } }), { status: 403, headers: { 'content-type': 'application/json' } });
};
try {
  const verdict = await guard.authorize({ action: 'flight-purchase', amount: 99, merchant: 'skyward-air', jurisdiction: 'de', context: { riskLevel: 'low', jurisdiction: 'SG' } });
  const body = posted.at(-1)?.body;
  // Reconstructed as the gate does: an omitted amount/currency defaults to 0/USD before the message is rebuilt.
  const asGate = { ...body, amount: body?.amount ?? 0, currency: body?.currency ?? 'USD' };
  check(body?.jurisdiction === 'DE' && verifyDidSignature(agentDid, buildAuthMessage(asGate), body.signature), 'authorize() posts the normalised jurisdiction and signs the v2 message over it');
  check(body?.itinerary?.jurisdiction === 'SG', "authorize() leaves the caller's context untouched (the gate ignores its jurisdiction)");
  check(verdict.reasonCode === 'JURISDICTION_MISMATCH' && verdict.decision === 'block', "a gate's JURISDICTION_MISMATCH comes back to the caller as the verdict");
  const before = posted.length;
  const refused = await guard.authorize({ action: 'flight-purchase', amount: 99, jurisdiction: 'Singapore' });
  check(refused.decision === 'block' && refused.reasonCode === 'MALFORMED_REQUEST' && posted.length === before, 'authorize() refuses a malformed jurisdiction without calling the gate');
  await guard.authorize({ action: 'flight-purchase', amount: 99 });
  check(!('jurisdiction' in posted.at(-1).body), 'authorize() without a jurisdiction sends none');
} finally {
  globalThis.fetch = realFetch;
}

// --- 4. local evaluation ---------------------------------------------------------------------------------------------
const mandate = { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:jurisdiction', operator: 'isAnyOf', rightOperand: ['DE', 'FR'] }] }] };
const local = (request, extra = {}) => guard.evaluateLocally({ mandate, ...extra, request: { action: 'flight-purchase', amount: 10, context: { riskLevel: 'low' }, ...request } });
check(local({ jurisdiction: 'de' }).decision === 'allow', 'mandate term: signed DE (on the list) → allow');
check(local({ jurisdiction: 'SG' }).reasonCode === 'JURISDICTION_NOT_ALLOWED', 'mandate term: signed SG (off the list) → JURISDICTION_NOT_ALLOWED');
check(local({}).reasonCode === 'JURISDICTION_REQUIRED', 'mandate term: nothing signed → JURISDICTION_REQUIRED');
check(local({ context: { riskLevel: 'low', jurisdiction: 'DE', 'mm:jurisdiction': 'DE' } }).reasonCode === 'JURISDICTION_REQUIRED', 'mandate term: a context jurisdiction does not stand in for a signed one');

const sops = [{ standardKey: 'sop:j', document: { molecules: [{ id: 'j', combinator: 'any', atoms: [{ id: 'a', predicate: 'jurisdiction-not-allowed', config: { allowed: ['SG', 'MY'] } }], decision: 'block', reasonCode: 'SOP_JURISDICTION' }] } }];
const open = { permission: [{ target: 'flight-purchase', constraint: [] }] };
const withSop = (request) => guard.evaluateLocally({ mandate: open, sops, request: { action: 'flight-purchase', amount: 10, context: { riskLevel: 'low' }, ...request } });
check(withSop({ jurisdiction: 'SG' }).decision === 'allow', 'SOP atom: signed SG → allow');
check(withSop({ jurisdiction: 'RU' }).reasonCode === 'SOP_JURISDICTION', 'SOP atom: signed RU → the rule fires');
check(withSop({}).reasonCode === 'JURISDICTION_REQUIRED', 'SOP atom enforced, nothing signed → JURISDICTION_REQUIRED');
check(withSop({ context: { riskLevel: 'low', jurisdiction: 'RU' } }).reasonCode === 'JURISDICTION_REQUIRED', 'SOP atom: an unsigned context RU is never judged (and never satisfies the requirement)');

// --- 5. daemon key provider against a fake daemon ---------------------------------------------------------------------
// Same pipe-name derivation as key-providers.mjs / the signer daemon, so the fake is reachable on every platform.
function platformSocketPath(logical) {
  if (process.platform !== 'win32') return logical;
  return `\\\\.\\pipe\\agentsafe-signer-${crypto.createHash('sha256').update(path.resolve(logical)).digest('hex').slice(0, 32)}`;
}
async function withFakeDaemon(echo, fn) {
  const logical = path.join(os.tmpdir(), `agentsafe-jur-${process.pid}-${crypto.randomUUID().slice(0, 8)}.sock`);
  const seen = [];
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (chunk) => {
      buf += chunk;
      const i = buf.indexOf('\n');
      if (i < 0) return;
      const req = JSON.parse(buf.slice(0, i));
      seen.push(req.params);
      const result = { signature: 'aa' };
      if (echo && req.params.jurisdiction !== undefined) result.jurisdiction = req.params.jurisdiction;
      sock.end(JSON.stringify({ ok: true, requestId: req.requestId, result }) + '\n');
    });
  });
  await new Promise((r) => server.listen(platformSocketPath(logical), r));
  try {
    return await fn(createDaemonKeyProvider({ socketPath: logical }), seen);
  } finally {
    await new Promise((r) => server.close(r));
  }
}
const base = { agentDid, action: 'a', amount: 1, currency: 'USD', nonce: 'n', issuedAt: new Date().toISOString() };
await withFakeDaemon(false, async (kp, seen) => {
  let code = null;
  try {
    await kp.signAuthorize({ ...base, jurisdiction: 'SG' });
  } catch (err) {
    code = err.code;
  }
  check(code === 'JURISDICTION_SIGNING_UNSUPPORTED', 'a daemon that does not echo the jurisdiction (predates it) is refused, not trusted');
  check((await kp.signAuthorize(base)) === 'aa' && !('jurisdiction' in seen.at(-1)), 'the same daemon still signs a v1 request (no jurisdiction sent to it)');
  await kp.signAuthorize({ ...base, jurisdiction: null, stray: 'x' });
  check(!('jurisdiction' in seen.at(-1)) && !('stray' in seen.at(-1)), 'only the named authorize fields reach the daemon (a null jurisdiction is none)');
});
await withFakeDaemon(true, async (kp, seen) => {
  check((await kp.signAuthorize({ ...base, jurisdiction: 'SG' })) === 'aa' && seen.at(-1).jurisdiction === 'SG', 'a current daemon (echoes it) signs the v2 request');
});

if (failed) {
  console.error(`\n${failed} check(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — signed jurisdiction: vectors, wire, local evaluation, daemon echo.');

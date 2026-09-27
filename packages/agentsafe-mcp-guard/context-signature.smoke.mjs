// context-signature.smoke.mjs — a Service re-verifies the agent's context signature (context-claim binding,
// docs/design/context-claim-binding.md Tier 1) before it judges the agent's unsigned `itinerary`, as the issuer's gate does.
// The requests are built by the real agentsafe-guard (`signContext: true`), cross-package, no hand-rolled signer.
//
// Before mcp-guard 0.17.0 the Service never looked at `envelopeSignature`: a relay between agent and Service could rewrite
// the itinerary (a blocked tool into an allowed one, riskLevel high into low) and the Service judged — and ran — the
// rewritten context. The "altered in transit" checks below fail on 0.16.0.
//
//   node context-signature.smoke.mjs
import crypto from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';
import { envelopeHashFor } from './governance-envelope.mjs';
import { createGuard } from '../agentsafe-guard/agentsafe-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { did: buildHederaDid('testnet', spki.subarray(spki.length - 32), topic), keyHex: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex') };
}
const agent = mint('0.0.100');
const other = mint('0.0.101');
const service = mint('0.0.200');
// agentsafe-guard >= 0.17.0 signs the context by default (signing); plain opts out.
const plain = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: agent.did, agentKey: agent.keyHex, signContext: false });
const signing = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: agent.did, agentKey: agent.keyHex });
const otherSigning = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: other.did, agentKey: other.keyHex, signContext: true });

const mol = (id, predicate, config, decision, reasonCode) => ({ id, combinator: 'any', atoms: [{ id: 'a', predicate, config }], decision, reasonCode });
const open = [{ action: 'book', document: { permission: [{ target: 'book', constraint: [] }] } }];
const bundle = {
  subject: agent.did,
  standards: [{ key: 'risk', document: { molecules: [mol('r', 'risk-at-or-above', { level: 'high' }, 'escalate', 'RISK_REVIEW')] } }],
  sops: [{ id: 't', document: { molecules: [mol('t', 'tool-not-allowed', { allowed: ['book-flight'] }, 'block', 'TOOL_BLOCKED')] } }],
  mandates: open,
};
let evaluations = 0;
const fetchBundle = async () => { evaluations++; return bundle; };
const svc = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle });
const strict = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle, requireContextSignature: true });

let failed = 0;
const check = (ok, label, got) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `  (got ${JSON.stringify(got)})`}`); if (!ok) failed++; };
const sign = (g, context, extra = {}) => g.buildSignedRequest({ action: 'book', amount: 0, context, ...extra });
const code = (d) => (d.decision === 'allow' ? 'allow' : `${d.decision}/${d.reasonCode}`);

console.log('— a context-signed request is judged on its signed itinerary —');
{
  let r;
  check((r = code(await svc.verifyRequest(await sign(signing, { tool: 'book-flight', riskLevel: 'low' })))) === 'allow', 'valid context signature, allowed tool → allow', r);
  check((r = code(await svc.verifyRequest(await sign(signing, { tool: 'wire-funds', riskLevel: 'low' })))) === 'block/TOOL_BLOCKED', 'valid context signature, blocked tool → the rule still judges it', r);
  check((r = code(await svc.verifyRequest(await sign(signing, { tool: 'book-flight', riskLevel: 'high' })))) === 'escalate/RISK_REVIEW', 'valid context signature, riskLevel high → RISK_REVIEW', r);
  check((r = code(await svc.verifyRequest(await sign(signing, undefined)))) === 'escalate/CONTEXT_UNVERIFIABLE', 'no itinerary at all, signed → verifies (evaluated as empty context)', r);
  check((r = code(await svc.verifyRequest(await sign(signing, {})))) === 'escalate/CONTEXT_UNVERIFIABLE', 'an empty itinerary, signed → verifies', r);
  const withTrace = await sign(signing, { tool: 'book-flight', riskLevel: 'low' }, { trace: { workflowId: 'w1', workflowStep: 2 }, materiality: { reversible: false } });
  check((r = code(await svc.verifyRequest(withTrace))) === 'allow', 'trace + materiality ride under the same signature → allow', r);
}

console.log('\n— the itinerary altered in transit (a relay between agent and Service) —');
{
  let r;
  const toolSwap = await sign(signing, { tool: 'wire-funds', riskLevel: 'low' });
  const before = evaluations;
  check((r = code(await svc.verifyRequest({ ...toolSwap, itinerary: { tool: 'book-flight', riskLevel: 'low' } }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'blocked tool rewritten to an allowed one → CONTEXT_SIGNATURE_INVALID (was allow)', r);
  const riskSwap = await sign(signing, { tool: 'book-flight', riskLevel: 'high' });
  check((r = code(await svc.verifyRequest({ ...riskSwap, itinerary: { tool: 'book-flight', riskLevel: 'low' } }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'riskLevel high rewritten to low → CONTEXT_SIGNATURE_INVALID (was allow)', r);
  check((r = code(await svc.verifyRequest({ ...riskSwap, itinerary: { tool: 'book-flight', riskLevel: 'high', extra: 1 } }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'a key added to the itinerary → CONTEXT_SIGNATURE_INVALID', r);
  const { itinerary: _drop, ...stripped } = riskSwap;
  check((r = code(await svc.verifyRequest(stripped))) === 'block/CONTEXT_SIGNATURE_INVALID', 'the itinerary dropped entirely → CONTEXT_SIGNATURE_INVALID', r);
  const traced = await sign(signing, { tool: 'book-flight', riskLevel: 'low' }, { trace: { workflowId: 'w1' } });
  check((r = code(await svc.verifyRequest({ ...traced, trace: { workflowId: 'w2' } }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'the trace altered → CONTEXT_SIGNATURE_INVALID', r);
  check(evaluations === before, 'no bundle was fetched (and so no rule evaluated) for any altered request', evaluations - before);
  // Via the tool wrapper, the handler never runs.
  let ran = false;
  const tool = svc.guardIncomingTool('book', async () => { ran = true; return 'RAN'; });
  let err;
  try { await tool({ ...toolSwap, itinerary: { tool: 'book-flight', riskLevel: 'low' } }); } catch (e) { err = e; }
  check(!ran && err?.governance?.reasonCode === 'CONTEXT_SIGNATURE_INVALID', 'guardIncomingTool: the altered request never reaches the handler', err?.governance);
}

console.log('\n— a context signature that is not the agent\'s —');
{
  let r;
  const good = await sign(signing, { tool: 'book-flight', riskLevel: 'low' });
  const foreign = await sign(otherSigning, { tool: 'book-flight', riskLevel: 'low' });
  check((r = code(await svc.verifyRequest({ ...good, envelopeSignature: foreign.envelopeSignature }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'another key\'s context signature → CONTEXT_SIGNATURE_INVALID', r);
  check((r = code(await svc.verifyRequest({ ...good, envelopeSignature: good.signature }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'the action signature passed off as the context signature → CONTEXT_SIGNATURE_INVALID', r);
  check((r = code(await svc.verifyRequest({ ...good, envelopeSignature: 'zz' }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'a non-hex context signature → CONTEXT_SIGNATURE_INVALID', r);
  check((r = code(await svc.verifyRequest({ ...good, envelopeSignature: '' }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'an empty context signature → CONTEXT_SIGNATURE_INVALID (never read as absent)', r);
  check((r = code(await svc.verifyRequest({ ...good, envelopeSignature: 42 }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'a non-string context signature → CONTEXT_SIGNATURE_INVALID', r);
  check((r = code(await svc.verifyRequest({ ...good, signature: '00'.repeat(64) }))) === 'block/SIGNATURE_INVALID', 'a bad action signature is still SIGNATURE_INVALID (checked first)', r);
}

console.log('\n— no context signature (it is optional) —');
{
  let r;
  check((r = code(await svc.verifyRequest(await sign(plain, { tool: 'book-flight', riskLevel: 'low' })))) === 'allow', 'signContext off → judged as before', r);
  check((r = code(await svc.verifyRequest(await sign(plain, { tool: 'wire-funds', riskLevel: 'low' })))) === 'block/TOOL_BLOCKED', 'signContext off, blocked tool → the rule judges it as before', r);
  const unsigned = await sign(plain, { tool: 'wire-funds', riskLevel: 'low' });
  check((r = code(await svc.verifyRequest({ ...unsigned, envelopeSignature: null }))) === 'block/TOOL_BLOCKED', 'envelopeSignature: null reads as absent', r);
  const stripped = await sign(signing, { tool: 'book-flight', riskLevel: 'low' });
  delete stripped.envelopeSignature;
  check((r = code(await svc.verifyRequest(stripped))) === 'allow', 'a stripped context signature reads as absent (what requireContextSignature is for)', r);
}

console.log('\n— requireContextSignature —');
{
  let r;
  check((r = code(await strict.verifyRequest(await sign(plain, { tool: 'book-flight', riskLevel: 'low' })))) === 'block/CONTEXT_SIGNATURE_REQUIRED', 'factory option: no context signature → CONTEXT_SIGNATURE_REQUIRED', r);
  const stripped = await sign(signing, { tool: 'book-flight', riskLevel: 'low' });
  delete stripped.envelopeSignature;
  check((r = code(await strict.verifyRequest(stripped))) === 'block/CONTEXT_SIGNATURE_REQUIRED', 'factory option: a stripped context signature → CONTEXT_SIGNATURE_REQUIRED', r);
  check((r = code(await strict.verifyRequest(await sign(signing, { tool: 'book-flight', riskLevel: 'low' })))) === 'allow', 'factory option: a valid context signature → allow', r);
  const tampered = await sign(signing, { tool: 'wire-funds', riskLevel: 'low' });
  check((r = code(await strict.verifyRequest({ ...tampered, itinerary: { tool: 'book-flight' } }))) === 'block/CONTEXT_SIGNATURE_INVALID', 'factory option: an altered context → CONTEXT_SIGNATURE_INVALID', r);
  check((r = code(await svc.verifyRequest(await sign(plain, { tool: 'book-flight', riskLevel: 'low' }), { requireContextSignature: true }))) === 'block/CONTEXT_SIGNATURE_REQUIRED', 'per-call option overrides the factory default (on)', r);
  check((r = code(await strict.verifyRequest(await sign(plain, { tool: 'book-flight', riskLevel: 'low' }), { requireContextSignature: false }))) === 'allow', 'per-call option overrides the factory default (off)', r);
  const tool = svc.guardIncomingTool('book', async () => 'RAN', { requireContextSignature: true });
  let err;
  try { await tool(await sign(plain, { tool: 'book-flight', riskLevel: 'low' })); } catch (e) { err = e; }
  check(err?.governance?.reasonCode === 'CONTEXT_SIGNATURE_REQUIRED', 'guardIncomingTool({ requireContextSignature: true }) refuses an unsigned context', err?.governance);
  check((await tool(await sign(signing, { tool: 'book-flight', riskLevel: 'low' }))) === 'RAN', 'guardIncomingTool({ requireContextSignature: true }) runs a signed one');
}

console.log('\n— the shared conformance vectors (docs/protocol/context-signature-vectors.json) —');
{
  // The vectors live in the monorepo's docs/protocol/; a copy of this package without them (the public mirror) skips this block.
  const vectorsUrl = new URL('../../docs/protocol/context-signature-vectors.json', import.meta.url);
  const doc = existsSync(vectorsUrl) ? JSON.parse(readFileSync(vectorsUrl, 'utf8')) : (console.log('SKIP  docs/protocol/context-signature-vectors.json not present'), { vectors: [] });
  for (const v of doc.vectors) {
    const hash = envelopeHashFor({ ...v.request, signature: '' });
    check(hash === v.envelopeHash, `${v.name}: this package's envelopeHashFor reproduces the backend's envelope hash`, hash);
    // The vectors are fixed in time, so a request that passes BOTH signature checks stops at freshness.
    let r;
    check((r = code(await svc.verifyRequest(v.request))) === 'block/REQUEST_EXPIRED', `${v.name}: both signatures verify (stops at freshness)`, r);
    const altered = { ...v.request, itinerary: { ...(v.request.itinerary ?? {}), riskLevel: 'critical' } };
    check((r = code(await svc.verifyRequest(altered))) === 'block/CONTEXT_SIGNATURE_INVALID', `${v.name}: the itinerary altered → CONTEXT_SIGNATURE_INVALID`, r);
  }
}

if (failed) {
  console.error(`\n${failed} check(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — the Service verifies the agent\'s context signature before it judges the context.');

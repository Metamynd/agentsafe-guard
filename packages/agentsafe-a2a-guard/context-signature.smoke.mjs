// context-signature.smoke.mjs — the A2A receiver verifies the calling agent's context signature (context-claim binding,
// docs/design/context-claim-binding.md Tier 1) before it judges the agent's unsigned `itinerary`, as the issuer's gate does.
// The envelope is built by the real agentsafe-guard (`buildA2AEnvelope` over `buildSignedRequest({ signContext: true })`),
// carried in a real A2A Message, and judged by the real `guardA2ATask`.
//
// Before a2a-guard 0.12.0 the receiver never looked at `envelopeSignature`: anything relaying the A2A message could rewrite
// the itinerary (a blocked tool into an allowed one, riskLevel high into low) and the receiver judged — and RAN — the
// rewritten context. The "altered in transit" checks below fail on 0.11.0.
//
//   node context-signature.smoke.mjs
import crypto from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { buildHederaDid } from './magp-did.mjs';
import { createA2aGuard, buildA2AEnvelope, extractEnvelope, unsignedContextOf, MAGP_A2A_EXTENSION_URI, TASK_STATE, CONTEXT_SIGNATURE_REASON_CODES, mapDecisionToTaskState } from './agentsafe-a2a-guard.mjs';
import { envelopeHashFor } from './governance-envelope.mjs';
import { createGuard } from '../agentsafe-guard/agentsafe-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { did: buildHederaDid('testnet', spki.subarray(spki.length - 32), topic), keyHex: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex'), publicKey };
}
const agent = mint('0.0.100');
const other = mint('0.0.101');
// agentsafe-guard >= 0.17.0 signs the context by default (signing); plain opts out.
const plain = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: agent.did, agentKey: agent.keyHex, signContext: false });
const signing = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: agent.did, agentKey: agent.keyHex });
const otherSigning = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: other.did, agentKey: other.keyHex, signContext: true });

const mol = (id, predicate, config, decision, reasonCode) => ({ id, combinator: 'any', atoms: [{ id: 'a', predicate, config }], decision, reasonCode });
const bundle = {
  subject: agent.did,
  standards: [{ key: 'risk', document: { molecules: [mol('r', 'risk-at-or-above', { level: 'high' }, 'escalate', 'RISK_REVIEW')] } }],
  sops: [{ id: 't', document: { molecules: [mol('t', 'tool-not-allowed', { allowed: ['book-flight'] }, 'block', 'TOOL_BLOCKED')] } }],
  mandates: [{ action: 'book', document: { permission: [{ target: 'book', constraint: [] }] } }],
};
let evaluations = 0;
const fetchBundle = async () => { evaluations++; return bundle; };
const receiver = createA2aGuard({ fetchBundle });
const strict = createA2aGuard({ fetchBundle, requireContextSignature: true });

let failed = 0;
const check = (ok, label, got) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `  (got ${JSON.stringify(got)})`}`); if (!ok) failed++; };
const outcome = (out) => (out === 'RAN' ? 'RAN' : `${out.state}/${out.message.metadata[MAGP_A2A_EXTENSION_URI].reasonCode}`);
const AUTH = TASK_STATE.AUTH_REQUIRED;
/** A real envelope from agentsafe-guard, optionally rewritten in transit, sent through a real receiver's task. */
async function send(context, { g = signing, rewrite, guard = receiver, taskOpts } = {}) {
  const env = await buildA2AEnvelope(g, { action: 'book', amount: 0, context });
  if (rewrite) env.metadata[MAGP_A2A_EXTENSION_URI] = rewrite(env.metadata[MAGP_A2A_EXTENSION_URI]);
  const task = guard.guardA2ATask('book', async () => 'RAN', taskOpts);
  return outcome(await task({ contextId: 'c', taskId: 't', parts: [{ kind: 'text', text: 'go' }], ...env }));
}

console.log('— a context-signed envelope is judged on its signed itinerary —');
{
  let r;
  check((r = await send({ tool: 'book-flight', riskLevel: 'low' })) === 'RAN', 'valid context signature, allowed tool → runs', r);
  check((r = await send({ tool: 'wire-funds', riskLevel: 'low' })) === `${TASK_STATE.REJECTED}/TOOL_BLOCKED`, 'valid context signature, blocked tool → the rule still judges it', r);
  check((r = await send({ tool: 'book-flight', riskLevel: 'high' })) === `${TASK_STATE.INPUT_REQUIRED}/RISK_REVIEW`, 'valid context signature, riskLevel high → RISK_REVIEW', r);
  check((r = await send(undefined)) === `${TASK_STATE.INPUT_REQUIRED}/CONTEXT_UNVERIFIABLE`, 'no itinerary at all, signed → verifies (evaluated as empty context)', r);
  check((r = await send({})) === `${TASK_STATE.INPUT_REQUIRED}/CONTEXT_UNVERIFIABLE`, 'an empty itinerary, signed → verifies', r);
  check((r = await send({ tool: 'book-flight', riskLevel: 'low' }, { rewrite: (s) => ({ ...s, context: { riskLevel: 'low', tool: 'book-flight' } }) })) === 'RAN', 'the `context` alias equal to the signed itinerary → runs (the signed object is evaluated)', r);
  // What is hashed is what is evaluated: unsignedContextOf's object.
  const s = extractEnvelope(await buildA2AEnvelope(signing, { action: 'book', amount: 0, context: { tool: 'book-flight' } }));
  const evaluated = unsignedContextOf(s).itinerary;
  const hash = envelopeHashFor({ agentDid: s.agentDid, action: s.action, amount: s.amount, currency: s.currency, merchant: s.merchant, itinerary: evaluated, trace: s.trace, materiality: s.materiality, nonce: s.nonce, issuedAt: s.issuedAt, signature: '' });
  check(evaluated === s.itinerary && crypto.verify(null, Buffer.from(hash, 'utf8'), agent.publicKey, Buffer.from(s.envelopeSignature, 'hex')), 'the signature verifies over the very object unsignedContextOf hands the rules');
}

console.log('\n— the itinerary altered in transit (anything relaying the A2A message) —');
{
  let r;
  const before = evaluations;
  check((r = await send({ tool: 'wire-funds', riskLevel: 'low' }, { rewrite: (s) => ({ ...s, itinerary: { tool: 'book-flight', riskLevel: 'low' } }) })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'blocked tool rewritten to an allowed one → CONTEXT_SIGNATURE_INVALID (was RAN)', r);
  check((r = await send({ tool: 'book-flight', riskLevel: 'high' }, { rewrite: (s) => ({ ...s, itinerary: { tool: 'book-flight', riskLevel: 'low' } }) })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'riskLevel high rewritten to low → CONTEXT_SIGNATURE_INVALID (was RAN)', r);
  check((r = await send({ tool: 'wire-funds' }, { rewrite: (s) => { const { itinerary, ...rest } = s; return rest; } })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'the itinerary dropped entirely → CONTEXT_SIGNATURE_INVALID', r);
  check((r = await send({ tool: 'wire-funds' }, { rewrite: (s) => ({ ...s, itinerary: { tool: 'book-flight' }, context: { tool: 'book-flight' } }) })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'itinerary and alias both rewritten, equal → CONTEXT_SIGNATURE_INVALID', r);
  check((r = await send({ tool: 'book-flight' }, { rewrite: (s) => ({ ...s, materiality: { reversible: true } }) })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'materiality added → CONTEXT_SIGNATURE_INVALID', r);
  check(evaluations === before, 'no bundle was fetched (and so no rule evaluated) for any altered envelope', evaluations - before);
}

console.log('\n— a context signature that is not the caller\'s —');
{
  let r;
  const foreign = extractEnvelope(await buildA2AEnvelope(otherSigning, { action: 'book', amount: 0, context: { tool: 'book-flight' } }));
  check((r = await send({ tool: 'book-flight' }, { rewrite: (s) => ({ ...s, envelopeSignature: foreign.envelopeSignature }) })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'another key\'s context signature → CONTEXT_SIGNATURE_INVALID', r);
  check((r = await send({ tool: 'book-flight' }, { rewrite: (s) => ({ ...s, envelopeSignature: s.signature }) })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'the request signature passed off as the context signature → CONTEXT_SIGNATURE_INVALID', r);
  check((r = await send({ tool: 'book-flight' }, { rewrite: (s) => ({ ...s, envelopeSignature: '' }) })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'an empty context signature → CONTEXT_SIGNATURE_INVALID (never read as absent)', r);
  check((r = await send({ tool: 'book-flight' }, { rewrite: (s) => ({ ...s, envelopeSignature: { sig: 'x' } }) })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'a non-string context signature → CONTEXT_SIGNATURE_INVALID', r);
}

console.log('\n— no context signature (it is optional) —');
{
  let r;
  check((r = await send({ tool: 'book-flight', riskLevel: 'low' }, { g: plain })) === 'RAN', 'signContext off → judged as before', r);
  check((r = await send({ tool: 'wire-funds', riskLevel: 'low' }, { g: plain })) === `${TASK_STATE.REJECTED}/TOOL_BLOCKED`, 'signContext off, blocked tool → the rule judges it as before', r);
  check((r = await send({ tool: 'book-flight', riskLevel: 'low' }, { rewrite: (s) => ({ ...s, envelopeSignature: null }) })) === 'RAN', 'envelopeSignature: null reads as absent', r);
}

console.log('\n— requireContextSignature —');
{
  let r;
  const strip = (s) => { const { envelopeSignature, ...rest } = s; return rest; };
  check((r = await send({ tool: 'book-flight' }, { g: plain, guard: strict })) === `${AUTH}/CONTEXT_SIGNATURE_REQUIRED`, 'factory option: no context signature → CONTEXT_SIGNATURE_REQUIRED', r);
  check((r = await send({ tool: 'book-flight' }, { guard: strict, rewrite: strip })) === `${AUTH}/CONTEXT_SIGNATURE_REQUIRED`, 'factory option: a stripped context signature → CONTEXT_SIGNATURE_REQUIRED', r);
  check((r = await send({ tool: 'book-flight' }, { g: plain, guard: strict, rewrite: (s) => ({ ...s, context: s.itinerary, itinerary: undefined }) })) === `${AUTH}/CONTEXT_SIGNATURE_REQUIRED`, 'factory option: the deprecated alias alone (no signature possible) → CONTEXT_SIGNATURE_REQUIRED', r);
  check((r = await send({ tool: 'book-flight', riskLevel: 'low' }, { guard: strict })) === 'RAN', 'factory option: a valid context signature → runs', r);
  check((r = await send({ tool: 'wire-funds' }, { guard: strict, rewrite: (s) => ({ ...s, itinerary: { tool: 'book-flight' } }) })) === `${AUTH}/CONTEXT_SIGNATURE_INVALID`, 'factory option: an altered context → CONTEXT_SIGNATURE_INVALID', r);
  check((r = await send({ tool: 'book-flight' }, { g: plain, taskOpts: { requireContextSignature: true } })) === `${AUTH}/CONTEXT_SIGNATURE_REQUIRED`, 'per-skill option overrides the factory default (on)', r);
  check((r = await send({ tool: 'book-flight', riskLevel: 'low' }, { g: plain, guard: strict, taskOpts: { requireContextSignature: false } })) === 'RAN', 'per-skill option overrides the factory default (off)', r);
  check(CONTEXT_SIGNATURE_REASON_CODES.every((c) => mapDecisionToTaskState('block', c).taskState === AUTH), 'both codes map to TASK_STATE_AUTH_REQUIRED');
}

console.log('\n— the shared conformance vectors (docs/protocol/context-signature-vectors.json) —');
{
  // The vectors live in the monorepo's docs/protocol/; a copy of this package without them (the public mirror) skips this block.
  const vectorsUrl = new URL('../../docs/protocol/context-signature-vectors.json', import.meta.url);
  const doc = existsSync(vectorsUrl) ? JSON.parse(readFileSync(vectorsUrl, 'utf8')) : (console.log('SKIP  docs/protocol/context-signature-vectors.json not present'), { vectors: [] });
  for (const v of doc.vectors) {
    const hash = envelopeHashFor({ ...v.request, signature: '' });
    check(hash === v.envelopeHash, `${v.name}: this package's envelopeHashFor reproduces the backend's envelope hash`, hash);
    let r;
    // The vectors are fixed in time, so a request that passes BOTH signature checks stops at freshness.
    check((r = (await receiver.verifyRequest(v.request)).reasonCode) === 'REQUEST_EXPIRED', `${v.name}: both signatures verify (stops at freshness)`, r);
    const altered = { ...v.request, itinerary: { ...(v.request.itinerary ?? {}), riskLevel: 'critical' } };
    check((r = (await receiver.verifyRequest(altered)).reasonCode) === 'CONTEXT_SIGNATURE_INVALID', `${v.name}: the itinerary altered → CONTEXT_SIGNATURE_INVALID`, r);
  }
}

if (failed) {
  console.error(`\n${failed} check(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — the A2A receiver verifies the caller\'s context signature before it judges the context.');

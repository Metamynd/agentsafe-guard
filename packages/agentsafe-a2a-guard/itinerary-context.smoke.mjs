// itinerary-context.smoke.mjs — the agent's unsigned context reaches the A2A receiver under ONE name. The envelope is
// built by the real agentsafe-guard (`buildA2AEnvelope` over `buildSignedRequest`, cross-package, no hand-rolled
// signer), carried in a real A2A Message, and judged by the real `guardA2ATask`.
//
// Before a2a-guard 0.11.0 the receiver read `context` while the guard sends `itinerary`, so every context-dependent
// check saw nothing: rules that fire on a present value (tool-not-allowed, pii-present, …) let the task RUN, and an
// honest `riskLevel` / a mandate context operand was refused. The first block below fails on 0.10.0.
//
//   node itinerary-context.smoke.mjs
import crypto from 'node:crypto';
import { buildHederaDid } from './magp-did.mjs';
import { createA2aGuard, buildA2AEnvelope, extractEnvelope, unsignedContextOf, MAGP_A2A_EXTENSION_URI, TASK_STATE } from './agentsafe-a2a-guard.mjs';
import { createGuard } from '../agentsafe-guard/agentsafe-guard.mjs';
import { envelopeHashFor } from '../agentsafe-guard/governance-envelope.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.100');
const agentKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
const agent = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: did, agentKey, signContext: false }); // the unsigned-context cases (the context alias)
const agentSigningContext = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: did, agentKey }); // signs by default (guard >= 0.17.0)

const mol = (id, predicate, config, decision, reasonCode) => ({ id, combinator: 'any', atoms: [{ id: 'a', predicate, config }], decision, reasonCode });
const open = [{ action: 'book', document: { permission: [{ target: 'book', constraint: [] }] } }];
const bundles = {
  risk: { subject: did, standards: [{ key: 'risk', document: { molecules: [mol('r', 'risk-at-or-above', { level: 'high' }, 'escalate', 'RISK_REVIEW')] } }], sops: [], mandates: open },
  tool: { subject: did, standards: [], sops: [{ id: 't', document: { molecules: [mol('t', 'tool-not-allowed', { allowed: ['book-flight'] }, 'block', 'TOOL_BLOCKED')] } }], mandates: open },
  pii: { subject: did, standards: [], sops: [{ id: 'p', document: { molecules: [mol('p', 'pii-present', {}, 'block', 'PII_BLOCKED')] } }], mandates: open },
  purpose: { subject: did, standards: [], sops: [], mandates: [{ action: 'book', document: { permission: [{ target: 'book', constraint: [{ leftOperand: 'purpose', operator: 'isAnyOf', rightOperand: ['travel'] }] }] } }] },
};
let bundle;
const receiver = createA2aGuard({ fetchBundle: async () => bundle });
const task = receiver.guardA2ATask('book', async () => 'RAN');

let failed = 0;
const check = (ok, label, got) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `  (got ${got})`}`); if (!ok) failed++; };
const outcome = (out) => (out === 'RAN' ? 'RAN' : `${out.state}/${out.message.metadata[MAGP_A2A_EXTENSION_URI].reasonCode}`);
/** A real envelope from agentsafe-guard, optionally rewritten in transit, sent through the real receiver. */
async function send(b, context, { g = agent, rewrite } = {}) {
  bundle = bundles[b];
  const env = await buildA2AEnvelope(g, { action: 'book', amount: 0, context });
  if (rewrite) env.metadata[MAGP_A2A_EXTENSION_URI] = rewrite(env.metadata[MAGP_A2A_EXTENSION_URI]);
  return outcome(await task({ contextId: 'c', taskId: 't', parts: [{ kind: 'text', text: 'go' }], ...env }));
}

console.log('— a guard-built envelope carries its context as `itinerary`, and the receiver judges it —');
{
  const env = await buildA2AEnvelope(agent, { action: 'book', amount: 0, context: { riskLevel: 'low' } });
  const signed = extractEnvelope(env);
  check('itinerary' in signed && !('context' in signed), 'agentsafe-guard sends `itinerary` (never `context`)', Object.keys(signed));
  let r;
  check((r = await send('risk', { riskLevel: 'low' })) === 'RAN', 'honest riskLevel low → runs (was escalate CONTEXT_UNVERIFIABLE)', r);
  check((r = await send('risk', { riskLevel: 'high' })) === `${TASK_STATE.INPUT_REQUIRED}/RISK_REVIEW`, 'riskLevel high → RISK_REVIEW', r);
  check((r = await send('risk', {})) === `${TASK_STATE.INPUT_REQUIRED}/CONTEXT_UNVERIFIABLE`, 'no riskLevel → CONTEXT_UNVERIFIABLE', r);
  check((r = await send('tool', { tool: 'wire-funds' })) === `${TASK_STATE.REJECTED}/TOOL_BLOCKED`, 'tool off the allow-list → refused (was RUN: fail-open)', r);
  check((r = await send('tool', { tool: 'book-flight' })) === 'RAN', 'tool on the allow-list → runs', r);
  check((r = await send('pii', { piiPresent: true })) === `${TASK_STATE.REJECTED}/PII_BLOCKED`, 'piiPresent → refused (was RUN: fail-open)', r);
  check((r = await send('purpose', { purpose: 'travel' })) === 'RAN', 'a mandate context operand is read (was CONSTRAINT_FAILED)', r);
  check((r = await send('purpose', { purpose: 'gambling' })) === `${TASK_STATE.REJECTED}/CONSTRAINT_FAILED:purpose`, 'a mandate context operand out of range → refused', r);
}

console.log('\n— an older sender that puts the context under `context` (deprecated alias) —');
{
  const legacy = (s) => { const { itinerary, ...rest } = s; return { ...rest, context: itinerary }; };
  let r;
  check((r = await send('tool', { tool: 'wire-funds' }, { rewrite: legacy })) === `${TASK_STATE.REJECTED}/TOOL_BLOCKED`, '`context` alone is still judged (tool → refused)', r);
  check((r = await send('risk', { riskLevel: 'low' }, { rewrite: legacy })) === 'RAN', '`context` alone is still judged (low risk → runs)', r);
}

console.log('\n— both names present —');
{
  let r;
  check((r = await send('tool', { tool: 'book-flight' }, { rewrite: (s) => ({ ...s, context: { ...s.itinerary } }) })) === 'RAN', 'both present and equal → accepted', r);
  check((r = await send('tool', { tool: 'book-flight', riskLevel: 'low' }, { rewrite: (s) => ({ ...s, context: { riskLevel: 'low', tool: 'book-flight' } }) })) === 'RAN', 'both equal, keys in another order → accepted', r);
  check((r = await send('tool', { tool: 'wire-funds' }, { rewrite: (s) => ({ ...s, context: { tool: 'book-flight' } }) })) === `${TASK_STATE.AUTH_REQUIRED}/MALFORMED_REQUEST`, 'both present and DIFFERENT → MALFORMED_REQUEST (never pick one)', r);
  check((r = await send('tool', { tool: 'book-flight' }, { rewrite: (s) => ({ ...s, context: { tool: 'wire-funds' } }) })) === `${TASK_STATE.AUTH_REQUIRED}/MALFORMED_REQUEST`, 'a benign itinerary cannot hide a different context (or the reverse)', r);
  check((r = await send('tool', {}, { rewrite: (s) => ({ ...s, itinerary: 'x' }) })) === `${TASK_STATE.AUTH_REQUIRED}/MALFORMED_REQUEST`, 'a non-object itinerary → MALFORMED_REQUEST', r);
  check((r = await send('tool', {}, { rewrite: (s) => { const { itinerary, ...rest } = s; return { ...rest, context: ['x'] }; } })) === `${TASK_STATE.AUTH_REQUIRED}/MALFORMED_REQUEST`, 'a non-object context → MALFORMED_REQUEST', r);
  check(unsignedContextOf({ itinerary: null }).ok && Object.keys(unsignedContextOf({ itinerary: null }).itinerary).length === 0, 'a null itinerary reads as absent');
}

console.log('\n— the context signature (context-claim binding) covers the object the receiver evaluates —');
{
  const env = await buildA2AEnvelope(agentSigningContext, { action: 'book', amount: 0, context: { tool: 'wire-funds', riskLevel: 'low' } });
  const s = extractEnvelope(env);
  const hashOver = (itinerary) => envelopeHashFor({ agentDid: s.agentDid, action: s.action, amount: s.amount, currency: s.currency, merchant: s.merchant, itinerary, trace: s.trace, materiality: s.materiality, nonce: s.nonce, issuedAt: s.issuedAt, signature: '' });
  const verifies = (hash) => crypto.verify(null, Buffer.from(hash, 'utf8'), publicKey, Buffer.from(s.envelopeSignature, 'hex'));
  const evaluated = unsignedContextOf(s);
  check(evaluated.ok && verifies(hashOver(evaluated.itinerary)), 'envelopeSignature verifies over exactly the context the receiver evaluates');
  check(!verifies(hashOver({ tool: 'book-flight', riskLevel: 'low' })), 'and not over a swapped one');
  let r;
  check((r = await send('tool', { tool: 'wire-funds' }, { g: agentSigningContext })) === `${TASK_STATE.REJECTED}/TOOL_BLOCKED`, 'a context-signed envelope is judged on its signed itinerary', r);
  const legacy = (x) => { const { itinerary, ...rest } = x; return { ...rest, context: itinerary }; };
  check((r = await send('tool', { tool: 'book-flight' }, { g: agentSigningContext, rewrite: legacy })) === `${TASK_STATE.AUTH_REQUIRED}/MALFORMED_REQUEST`, 'the `context` alias beside an envelopeSignature → MALFORMED_REQUEST (the signature covers `itinerary`)', r);
}

if (failed) {
  console.error(`\n${failed} check(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — the A2A receiver reads the context agentsafe-guard sends (`itinerary`), `context` only as a non-conflicting alias.');

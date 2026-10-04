// a2a-guard.smoke.mjs — end-to-end proof that guardA2ATask independently re-verifies a signed
// MAGP envelope carried in an A2A Message's metadata, and that the decision->TaskState mapping
// (docs/design/a2a-compatibility-scope.md §5) is exactly what it claims: a REFUSAL IS A RETURNED
// TaskStatus, never a thrown error — the deliberate divergence from agentsafe-mcp-guard's
// throw-based guardIncomingTool, because A2A tasks have a formal state machine.
//
//   node a2a-guard.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import {
  createA2aGuard,
  buildA2AEnvelope,
  buildTaskStatus,
  extractEnvelope,
  mapDecisionToTaskState,
  MAGP_A2A_EXTENSION_URI,
  TASK_STATE,
} from './agentsafe-a2a-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const raw = spki.subarray(spki.length - 32);
  const did = buildHederaDid('testnet', raw, topic);
  const sign = (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex');
  return { did, sign };
}

const agent = mint('0.0.910');

// Two genuinely-permitted skills, a review-gated one, and NO mandate at all for a fourth — so
// this proves real discrimination between skills, not just "some rule fired somewhere".
const bundle = {
  subject: agent.did,
  mandates: [
    { action: 'summarize-report', document: { permission: [{ target: 'summarize-report', constraint: [] }] } },
    { action: 'wire-transfer', document: { permission: [{ target: 'wire-transfer', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 10 }] }] } },
  ],
  sops: [
    {
      id: 'high-risk-review',
      document: {
        molecules: [
          { id: 'risk', name: 'risk review', combinator: 'any', decision: 'escalate', reasonCode: 'RISK_REVIEW', atoms: [{ id: 'a', predicate: 'risk-at-or-above', config: { level: 'high' } }] },
        ],
      },
    },
  ],
};

const guard = createA2aGuard({ allowedAgents: 'any', fetchBundle: async () => bundle });

// An honest client states its risk: the bundle's SOP has a risk rule, and an envelope that leaves `riskLevel` out is
// escalated, not waved through (see the D-03 section below).
function signedEnvelope(action, amount = 0, context = { riskLevel: 'low' }) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const message = buildAuthMessage({ agentDid: agent.did, action, amount, currency: 'USD', merchant: '', nonce, issuedAt });
  const signature = agent.sign(message);
  // The unsigned context under its canonical wire name, `itinerary` (as agentsafe-guard's buildSignedRequest sends it).
  return { agentDid: agent.did, action, amount, currency: 'USD', merchant: '', itinerary: context, nonce, issuedAt, signature };
}

function messageWithEnvelope(envelope, { contextId = 'ctx-1', taskId = 'task-1' } = {}) {
  return { contextId, taskId, metadata: envelope ? { [MAGP_A2A_EXTENSION_URI]: envelope } : {} };
}

let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };

console.log('— D-03: the agent cannot skip a risk rule by hiding, garbling or understating its risk (spec §6.4.3) —');
{
  const verdict = async (envelope, opts, g = guard) => { const d = await g.verifyRequest(envelope, opts); return `${d.decision}/${d.reasonCode}`; };
  ok((await verdict(signedEnvelope('summarize-report', 0, {}))) === 'escalate/CONTEXT_UNVERIFIABLE', 'OMITTING riskLevel -> escalate (was allow)');
  ok((await verdict(signedEnvelope('summarize-report', 0, { riskLevel: 'HIGH' }))) === 'escalate/RISK_REVIEW', '"HIGH" upper-case is read as high -> escalate RISK_REVIEW (was allow)');
  ok((await verdict(signedEnvelope('summarize-report', 0, { riskLevel: 'banana' }))) === 'escalate/CONTEXT_UNVERIFIABLE', 'an unrecognised riskLevel -> escalate, never "not risky"');

  // the owner's tier rides in the signed mandate, so this guard applies the same floor as the issuer's gate
  const tiered = { ...bundle, mandates: [{ action: 'summarize-report', document: { permission: [{ target: 'summarize-report', riskTier: 'high', constraint: [] }] } }] };
  const tierGuard = createA2aGuard({ allowedAgents: 'any', fetchBundle: async () => tiered });
  ok((await verdict(signedEnvelope('summarize-report', 0, { riskLevel: 'low' }), undefined, tierGuard)) === 'escalate/RISK_REVIEW', 'owner tier=high: an agent claiming "low" is still judged high');
  ok((await verdict(signedEnvelope('summarize-report', 0, {}), undefined, tierGuard)) === 'escalate/RISK_REVIEW', 'owner tier=high: an agent that says nothing is judged high too');

  // what THIS skill derived from the real call beats the agent's claim; the agent can only raise it
  ok((await verdict(signedEnvelope('summarize-report', 0, { riskLevel: 'low' }), { trustedContext: { riskLevel: 'high' } })) === 'escalate/RISK_REVIEW', 'trustedContext riskLevel=high beats an agent claim of "low"');
  ok((await verdict(signedEnvelope('summarize-report', 0, {}), { trustedContext: { riskLevel: 'low' } })) === 'allow/AUTHORIZED', 'trustedContext riskLevel=low supplies the risk when the agent sent none');

  // A trustedContext the skill author CONFIGURED but that yields nothing usable means the deriver is broken: a
  // structured refusal (never an exception, never a quiet fallback to the agent's word).
  for (const [name, bad] of [['junk riskLevel', { riskLevel: 'severe' }], ['riskLevel undefined', { riskLevel: undefined }], ['null', null], ['an array', ['high']]]) {
    ok((await verdict(signedEnvelope('summarize-report', 0, { riskLevel: 'low' }), { trustedContext: bad })) === 'block/GUARD_ERROR', `broken trustedContext (${name}) on verifyRequest -> refused`);
  }
  {
    let ran2 = false;
    for (const [name, opt] of [['a function returning undefined', () => undefined], ['a function returning junk riskLevel', () => ({ riskLevel: 'nope' })], ['a function that throws', () => { throw new Error('classifier down'); }]]) {
      ran2 = false;
      const task = guard.guardA2ATask('summarize-report', async () => { ran2 = true; return 'done'; }, { trustedContext: opt });
      let out; let threw = false;
      try { out = await task(messageWithEnvelope(signedEnvelope('summarize-report', 0, { riskLevel: 'low' })), { id: 't' }); } catch { threw = true; }
      ok(!threw && !ran2 && out?.state !== undefined && out?.message?.metadata?.[MAGP_A2A_EXTENSION_URI]?.reasonCode === 'GUARD_ERROR', `guardA2ATask trustedContext ${name} -> a structured GUARD_ERROR refusal, handler never runs`, out?.state);
    }
  }

  // guardA2ATask: the skill author states the risk of THIS skill (object, or a function of the call)
  const run = async (opts) => { let ran = false; const task = guard.guardA2ATask('summarize-report', async () => { ran = true; return 'done'; }, opts); const r = await task(messageWithEnvelope(signedEnvelope('summarize-report', 0, { riskLevel: 'low' })), { id: 't' }); return { ran, r }; };
  const hi = await run({ trustedContext: { riskLevel: 'high' } });
  ok(hi.ran === false && hi.r?.state === TASK_STATE.INPUT_REQUIRED && hi.r?.message?.metadata?.[MAGP_A2A_EXTENSION_URI]?.reasonCode === 'RISK_REVIEW', 'guardA2ATask trustedContext (object) escalates a "low" claim without running the handler', hi.r?.state);
  const hiFn = await run({ trustedContext: () => ({ riskLevel: 'high' }) });
  ok(hiFn.ran === false, 'guardA2ATask trustedContext (function) too');
  const lo = await run({ trustedContext: { riskLevel: 'low' } });
  ok(lo.ran === true, 'a low trustedContext lets an honest request run');
}

console.log('\n— decision -> TaskState mapping (§5) —');
{
  ok(mapDecisionToTaskState('allow').taskState === TASK_STATE.WORKING, 'allow -> WORKING');
  ok(mapDecisionToTaskState('observe').taskState === TASK_STATE.WORKING, 'observe -> WORKING (permit-but-flag)');
  ok(mapDecisionToTaskState('escalate').taskState === TASK_STATE.INPUT_REQUIRED, 'escalate -> INPUT_REQUIRED, not AUTH_REQUIRED');
  ok(mapDecisionToTaskState('block', 'SIGNATURE_INVALID').taskState === TASK_STATE.AUTH_REQUIRED, 'a signature failure -> AUTH_REQUIRED specifically');
  ok(mapDecisionToTaskState('block', 'MAGP_ENVELOPE_MISSING').taskState === TASK_STATE.AUTH_REQUIRED, 'a missing envelope -> AUTH_REQUIRED, not a generic rejection');
  ok(mapDecisionToTaskState('block', 'NO_PERMISSION_FOR_ACTION').taskState === TASK_STATE.REJECTED, 'an ordinary policy refusal -> REJECTED');
  ok(mapDecisionToTaskState('suspend', 'AGENT_SUSPENDED').taskState === TASK_STATE.REJECTED, 'containment has no closer analog than REJECTED');
  ok(mapDecisionToTaskState('quarantine', 'AGENT_QUARANTINED').taskState === TASK_STATE.REJECTED, 'quarantine likewise');
}

let ran = false;
const summarize = guard.guardA2ATask('summarize-report', () => { ran = true; return { summary: 'ok' }; });
const wireTransfer = guard.guardA2ATask('wire-transfer', (message, task, amount) => { ran = true; return { moved: amount }; });

console.log('\n— permitted: the handler runs and its return value passes through untouched —');
{
  ran = false;
  const result = await summarize(messageWithEnvelope(signedEnvelope('summarize-report', 0)));
  ok(ran, 'the handler actually ran');
  ok(result?.summary === 'ok', 'the handler\'s own return value is returned, not wrapped');
}

console.log('\n— no envelope at all: refused as AUTH_REQUIRED, a returned TaskStatus, NOT a thrown error —');
{
  ran = false;
  let threw = null;
  let result;
  try { result = await summarize(messageWithEnvelope(null)); } catch (e) { threw = e; }
  ok(!ran, 'the handler never ran');
  ok(threw === null, 'guardA2ATask does not throw on a policy refusal — A2A refusals are protocol responses');
  ok(result?.state === TASK_STATE.AUTH_REQUIRED, 'the returned TaskStatus is AUTH_REQUIRED', result?.state);
  ok(result.message.metadata[MAGP_A2A_EXTENSION_URI].reasonCode === 'MAGP_ENVELOPE_MISSING', 'the reason code is carried in the attached message\'s metadata', result.message.metadata[MAGP_A2A_EXTENSION_URI].reasonCode);
}

console.log('\n— wrong skill: a signature valid for one skill must not run a DIFFERENT skill\'s handler —');
{
  ran = false;
  const onlyEverAuthorizedFor = signedEnvelope('summarize-report', 0);
  const result = await wireTransfer(messageWithEnvelope(onlyEverAuthorizedFor));
  ok(!ran, 'the wire-transfer handler never ran on a summarize-report-only signature');
  ok(result?.state === TASK_STATE.AUTH_REQUIRED, 'refused as AUTH_REQUIRED (the signature does not cover this skill)', result?.state);
  ok(result.message.metadata[MAGP_A2A_EXTENSION_URI].reasonCode === 'SIGNATURE_INVALID', 'reason is SIGNATURE_INVALID', result.message.metadata[MAGP_A2A_EXTENSION_URI].reasonCode);
}

console.log('\n— over the cap: REJECTED, not AUTH_REQUIRED — this is a real policy refusal, not an identity problem —');
{
  ran = false;
  const result = await wireTransfer(messageWithEnvelope(signedEnvelope('wire-transfer', 500)));
  ok(!ran, 'the handler never ran');
  ok(result?.state === TASK_STATE.REJECTED, 'refused as REJECTED', result?.state);
}

console.log('\n— high risk: INPUT_REQUIRED (a HOLD, not a denial) — the caller can poll for resolution —');
{
  ran = false;
  const result = await summarize(messageWithEnvelope(signedEnvelope('summarize-report', 0, { riskLevel: 'high' })));
  ok(!ran, 'the handler does not run while the task is held');
  ok(result?.state === TASK_STATE.INPUT_REQUIRED, 'the task is INPUT_REQUIRED, not terminal', result?.state);
  ok(result.message.metadata[MAGP_A2A_EXTENSION_URI].reasonCode === 'RISK_REVIEW', 'reason is RISK_REVIEW', result.message.metadata[MAGP_A2A_EXTENSION_URI].reasonCode);
}

console.log('\n— buildA2AEnvelope / extractEnvelope: the initiator-side adapter round-trips —');
{
  // A mock guard is enough here: buildA2AEnvelope is a pure serialization adapter over
  // buildSignedRequest, which agentsafe-guard's own suite already covers — this proves the
  // NEW code (the envelope shape), not the signing path underneath it.
  const mockGuard = { buildSignedRequest: async (params) => ({ ...params, agentDid: agent.did, nonce: 'n', issuedAt: 't', signature: 'sig' }) };
  const envelope = await buildA2AEnvelope(mockGuard, { action: 'summarize-report', amount: 0 });
  ok(Array.isArray(envelope.extensions) && envelope.extensions.includes(MAGP_A2A_EXTENSION_URI), 'the extension URI is declared in `extensions`');
  ok(envelope.metadata[MAGP_A2A_EXTENSION_URI]?.signature === 'sig', 'the signed request rides in `metadata` under the extension URI');

  const message = { metadata: envelope.metadata };
  const extracted = extractEnvelope(message);
  ok(extracted?.agentDid === agent.did, 'extractEnvelope reads back exactly what buildA2AEnvelope wrote');
  ok(extractEnvelope({ metadata: {} }) === null, 'extractEnvelope returns null, not undefined or a throw, when the extension was never used');
}

console.log('\n— buildTaskStatus carries contextId/taskId through so a client can correlate the refusal —');
{
  const status = buildTaskStatus({ decision: 'block', reasonCode: 'NO_MANDATE', contextId: 'ctx-42', taskId: 'task-99' });
  ok(status.message.contextId === 'ctx-42', 'contextId round-trips');
  ok(status.message.taskId === 'task-99', 'taskId round-trips');
}

if (failed) {
  console.error(`\n${failed} case(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — guardA2ATask independently re-verifies the envelope, pins each skill to its own action, and every refusal is a returned TaskStatus, never a thrown error.');

// a2a-payload-binding.smoke.mjs — payload binding at the A2A receiver (MAGP 8.3.9 / 8.7.11), the same contract as
// agentsafe-mcp-guard's payload-binding.smoke.mjs: the agent signs a digest of the COMPLETE task input; this receiver digests
// what it is about to EXECUTE, refuses a difference locally, and states the digest in the CLAIM it signs so the issuer compares
// it with the one it stored at authorize time.
//
//   node a2a-payload-binding.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { buildPayloadBindingMessage, payloadDigestOf, claimDigestField, PAYLOAD_DIGEST_HEADER } from './payload-binding.mjs';
import { createA2aGuard, buildA2AEnvelope, MAGP_A2A_EXTENSION_URI, a2aBindingValue } from './agentsafe-a2a-guard.mjs';

const kp = () => crypto.generateKeyPairSync('ed25519');
const rawOf = (publicKey) => { const spki = publicKey.export({ type: 'spki', format: 'der' }); return spki.subarray(spki.length - 32); };
const agentKeys = kp();
const agentDid = buildHederaDid('testnet', rawOf(agentKeys.publicKey), '0.0.910');
const sign = (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), agentKeys.privateKey).toString('hex');
const ISSUER = 'https://issuer.example/api/v1';
const ACTION = 'book-hotel';
const bundle = { subject: agentDid, standards: [], sops: [], mandates: [{ action: ACTION, document: { permission: [{ target: ACTION, constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] } }] };

const PARTS = [{ text: 'Book the Grand for 2 nights' }, { data: { payee: { iban: 'GB00AAAA', name: 'Grand Hotel' }, guests: ['A', 'B'] } }];
const SWAPPED = [PARTS[0], { data: { payee: { iban: 'XX99EVIL', name: 'Grand Hotel' }, guests: ['A', 'B'] } }];

/** The signed envelope, optionally binding `payload` exactly as agentsafe-guard's buildSignedRequest does. */
function envelope({ payload, amount = 250, tamper = {} } = {}) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const env = { agentDid, action: ACTION, amount, currency: 'USD', merchant: '', nonce, issuedAt, authorizationId: 'auth-1' };
  env.signature = sign(buildAuthMessage(env));
  if (payload !== undefined) {
    env.payloadDigest = payloadDigestOf(payload);
    env.payloadSignature = sign(buildPayloadBindingMessage({ agentDid, action: ACTION, nonce, issuedAt, payloadDigest: env.payloadDigest }));
  }
  return { ...env, ...tamper };
}
const messageOf = (env, parts = PARTS) => ({ contextId: 'c', taskId: 't', parts, metadata: { [MAGP_A2A_EXTENSION_URI]: env } });
const reasonOf = (status) => status?.message?.metadata?.[MAGP_A2A_EXTENSION_URI]?.reasonCode;

function withMockClaim(responder) {
  const real = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, opts) => {
    seen.push({ url: String(url), headers: opts?.headers ?? {} });
    const { status, body } = responder({ url: String(url), headers: opts?.headers ?? {} });
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  return { seen, restore: () => { globalThis.fetch = real; } };
}
// A compliant issuer echoes the digest the claim stated (null when it stated none): the hold is bound to exactly that.
const okClaim = (extra = {}) => ({ headers }) => ({ status: 200, body: { success: true, data: { ok: true, effectState: 'dispatching', agentDid, action: ACTION, amount: 250, currency: 'USD', payloadDigest: headers[PAYLOAD_DIGEST_HEADER] ?? null, ...extra } } });
const mk = (opts = {}) => createA2aGuard({ allowedAgents: 'any', issuerApi: ISSUER, fetchBundle: async () => bundle, requireAuthorization: true, ...opts });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('bindPayload:true — the task input matching the signed digest runs, and the claim states the digest in a header', async () => {
  const { seen, restore } = withMockClaim(okClaim());
  try {
    const ran = [];
    const skill = mk().guardA2ATask(ACTION, async (m) => { ran.push(m.parts); return 'done'; }, { bindPayload: true });
    assert.equal(await skill(messageOf(envelope({ payload: PARTS }))), 'done');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].headers[PAYLOAD_DIGEST_HEADER], payloadDigestOf(PARTS));
    assert.deepEqual(ran[0], PARTS);
  } finally { restore(); }
});

// bindScope (owner decision 2026-09-24): 'message' binds everything a handler can read from the message, not just `parts`.
const FULL = {
  contextId: 'c', taskId: 't', parts: PARTS,
  metadata: { 'x-app/routing': { account: 'GB00AAAA' } },
  referenceTaskIds: ['prev-1'],
  extensions: ['https://example.org/ext/travel'],
};
/** A message the way a sender builds it: the binding value is computed first, then the MAGP envelope is added to it. */
function fullMessage(env, over = {}) {
  const m = { ...FULL, ...over };
  return { ...m, metadata: { ...m.metadata, [MAGP_A2A_EXTENSION_URI]: env }, extensions: [...(m.extensions ?? []), MAGP_A2A_EXTENSION_URI] };
}

test("bindScope:'message' — parts, metadata, referenceTaskIds and extensions are all bound; the MAGP envelope itself is not part of the digest", async () => {
  const { seen, restore } = withMockClaim(okClaim());
  try {
    const bound = a2aBindingValue(FULL, 'message');
    assert.deepEqual(Object.keys(bound).sort(), ['extensions', 'metadata', 'parts', 'referenceTaskIds']);
    const seenByHandler = [];
    const skill = mk().guardA2ATask(ACTION, async (m) => { seenByHandler.push(m); return 'done'; }, { bindPayload: true, bindScope: 'message' });
    assert.equal(await skill(fullMessage(envelope({ payload: bound }))), 'done');
    assert.equal(seen[0].headers[PAYLOAD_DIGEST_HEADER], payloadDigestOf(bound));
    assert.deepEqual(seenByHandler[0].metadata['x-app/routing'], { account: 'GB00AAAA' });
    assert.ok(seenByHandler[0].metadata[MAGP_A2A_EXTENSION_URI], 'the envelope stays on the message the handler sees');
  } finally { restore(); }
});

test("bindScope:'message' — a changed metadata value, reference, or extension is refused (PAYLOAD_NOT_BOUND); with 'parts' metadata stays unbound", async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const bound = a2aBindingValue(FULL, 'message');
    const skill = mk().guardA2ATask(ACTION, async () => 'ran', { bindPayload: true, bindScope: 'message' });
    for (const over of [{ metadata: { 'x-app/routing': { account: 'XX99EVIL' } } }, { referenceTaskIds: ['someone-elses-task'] }, { extensions: ['https://evil.example/ext'] }]) {
      assert.equal(reasonOf(await skill(fullMessage(envelope({ payload: bound }), over))), 'PAYLOAD_NOT_BOUND', JSON.stringify(over));
    }
    // The 'parts' scope (the pre-0.7 default) does not see a metadata change — exactly the gap 'message' closes.
    const partsOnly = mk().guardA2ATask(ACTION, async () => 'ran', { bindPayload: true, bindScope: 'parts' });
    assert.equal(await partsOnly(fullMessage(envelope({ payload: PARTS }), { metadata: { 'x-app/routing': { account: 'XX99EVIL' } } })), 'ran');
  } finally { restore(); }
});

test('bindPayload:true without a bindScope warns once that metadata is unbound; an explicit scope does not, and a bad scope throws', async () => {
  const warns = [];
  const real = console.warn;
  console.warn = (...a) => warns.push(a.join(' '));
  try {
    mk().guardA2ATask(ACTION, async () => 'x', { bindPayload: true });
    assert.equal(warns.filter((w) => w.includes("bindScope: 'message'")).length, 1);
    warns.length = 0;
    mk().guardA2ATask(ACTION, async () => 'x', { bindPayload: true, bindScope: 'parts' });
    mk().guardA2ATask(ACTION, async () => 'x', { bindPayload: true, bindScope: 'message' });
    assert.equal(warns.filter((w) => w.includes('bindScope')).length, 0);
    assert.throws(() => mk().guardA2ATask(ACTION, async () => 'x', { bindPayload: true, bindScope: 'everything' }), /bindScope/);
  } finally { console.warn = real; }
});

test('a swapped payee is refused locally (PAYLOAD_NOT_BOUND), the handler never runs and no claim is made', async () => {
  const { seen, restore } = withMockClaim(okClaim());
  try {
    let ran = 0;
    const skill = mk().guardA2ATask(ACTION, async () => { ran++; }, { bindPayload: true });
    const status = await skill(messageOf(envelope({ payload: PARTS }), SWAPPED));
    assert.equal(reasonOf(status), 'PAYLOAD_NOT_BOUND');
    assert.equal(ran, 0); assert.equal(seen.length, 0, 'the hold must not be spent on a task that already fails the comparison');
  } finally { restore(); }
});

test('the issuer refusing the claim digest surfaces its reason (a receiver that skipped the local check is still stopped)', async () => {
  const { restore } = withMockClaim(() => ({ status: 403, body: { success: false, message: 'PAYLOAD_DIGEST_MISMATCH' } }));
  try {
    const status = await mk().guardA2ATask(ACTION, async () => 'x', { bindPayload: true })(messageOf(envelope({ payload: PARTS })));
    assert.equal(reasonOf(status), 'PAYLOAD_DIGEST_MISMATCH');
  } finally { restore(); }
});

test('a digest with a bad signature, or lifted from another authorization, binds nothing (PAYLOAD_BINDING_INVALID)', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const skill = mk().guardA2ATask(ACTION, async () => 'x', { bindPayload: true });
    assert.equal(reasonOf(await skill(messageOf(envelope({ payload: PARTS, tamper: { payloadSignature: 'ab'.repeat(64) } })))), 'PAYLOAD_BINDING_INVALID');
    const a = envelope({ payload: PARTS });
    const lifted = { ...envelope({ payload: PARTS }), payloadDigest: a.payloadDigest, payloadSignature: a.payloadSignature };
    assert.equal(reasonOf(await skill(messageOf(lifted))), 'PAYLOAD_BINDING_INVALID');
    const noSig = { ...a }; delete noSig.payloadSignature;
    assert.equal(reasonOf(await skill(messageOf(noSig))), 'PAYLOAD_BINDING_INVALID');
  } finally { restore(); }
});

test('an UNBOUND authorization is unchanged by default: permitted, and the claim carries no digest', async () => {
  const { seen, restore } = withMockClaim(okClaim());
  try {
    const skill = mk().guardA2ATask(ACTION, async () => 'ran', { bindPayload: true });
    assert.equal(await skill(messageOf(envelope())), 'ran');
    assert.equal(seen[0].headers[PAYLOAD_DIGEST_HEADER], undefined, 'no binding was made, so none is asserted');
  } finally { restore(); }
});

test('requirePayloadBinding refuses an unbound authorization; without bindPayload it is a configuration error', async () => {
  const { seen, restore } = withMockClaim(okClaim());
  try {
    const strict = mk().guardA2ATask(ACTION, async () => 'ran', { bindPayload: true, requirePayloadBinding: true });
    assert.equal(reasonOf(await strict(messageOf(envelope()))), 'PAYLOAD_BINDING_REQUIRED');
    assert.equal(seen.length, 0);
    assert.throws(() => mk().guardA2ATask(ACTION, async () => 'x', { requirePayloadBinding: true }), /requirePayloadBinding needs bindPayload/);
  } finally { restore(); }
});

test('an issuer that predates payload binding (its grant carries no digest) is REFUSED when the claim stated one', async () => {
  const { restore } = withMockClaim(() => ({ status: 200, body: { success: true, data: { ok: true, agentDid, action: ACTION, amount: 250, currency: 'USD' } } }));
  try {
    const skill = mk().guardA2ATask(ACTION, async () => 'ran', { bindPayload: true });
    assert.equal(reasonOf(await skill(messageOf(envelope({ payload: PARTS })))), 'PAYLOAD_DIGEST_MISMATCH');
    assert.equal(await skill(messageOf(envelope())), 'ran', '...while an UNBOUND task against the same old issuer is exactly what it always was');
  } finally { restore(); }
});

test('the handler receives the JSON snapshot that was digested (toJSON and later mutation cannot diverge)', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const seen = [];
    const skill = mk().guardA2ATask(ACTION, async (m) => { seen.push(m.parts); }, { bindPayload: true });
    const sneaky = [{ toJSON() { return PARTS[0]; }, text: 'EVIL' }, PARTS[1]];
    await skill(messageOf(envelope({ payload: PARTS }), sneaky));
    assert.deepEqual(seen[0], PARTS);
  } finally { restore(); }
});

test('bindPayload as a function chooses what is digested', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    const skill = mk().guardA2ATask(ACTION, async () => 'ran', { bindPayload: (_env, m) => m.parts[1].data.payee });
    assert.equal(await skill(messageOf(envelope({ payload: PARTS[1].data.payee }))), 'ran');
    assert.equal(reasonOf(await skill(messageOf(envelope({ payload: PARTS[1].data.payee }), SWAPPED))), 'PAYLOAD_NOT_BOUND');
  } finally { restore(); }
});

test('input JSON cannot carry is refused (PAYLOAD_NOT_CANONICALIZABLE), never skipped', async () => {
  const { restore } = withMockClaim(okClaim());
  try {
    let ran = 0;
    const skill = mk().guardA2ATask(ACTION, async () => { ran++; }, { bindPayload: () => () => 1 });
    assert.equal(reasonOf(await skill(messageOf(envelope({ payload: PARTS })))), 'PAYLOAD_NOT_CANONICALIZABLE');
    assert.equal(ran, 0);
  } finally { restore(); }
});

test('the digest is covered by the receiver\'s signature on the claim: it verifies WITH the payload field and not without it', async () => {
  const { publicKey, privateKey } = kp();
  const svcDid = buildHederaDid('testnet', rawOf(publicKey), '0.0.911');
  const serviceKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
  const { seen, restore } = withMockClaim(okClaim());
  try {
    const d = payloadDigestOf(PARTS);
    await mk({ serviceDid: svcDid, serviceKey }).guardA2ATask(ACTION, async () => 'x', { bindPayload: true })(messageOf(envelope({ payload: PARTS })));
    const h = seen[0].headers;
    const esc = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
    const message = (fields) => ['MAGP-SERVICE-v1', 'claim', 'auth-1', ...fields, h['x-magp-service-nonce'], h['x-magp-service-issued-at']].map(esc).join('|');
    const verifies = (m) => crypto.verify(null, Buffer.from(m, 'utf8'), publicKey, Buffer.from(h['x-magp-service-signature'], 'hex'));
    assert.equal(verifies(message([h['idempotency-key'], claimDigestField(d)])), true, 'signed with the digest field');
    assert.equal(verifies(message([h['idempotency-key']])), false, 'a header stripped of its signed field would not verify');
  } finally { restore(); }
});

test('the initiator side: buildA2AEnvelope carries the payload binding produced by the guard', async () => {
  const guard = { buildSignedRequest: async (params) => ({ ...envelope({ payload: params.payload }) }) };
  const built = await buildA2AEnvelope(guard, { action: ACTION, amount: 250, payload: PARTS });
  const carried = built.metadata[MAGP_A2A_EXTENSION_URI];
  assert.equal(carried.payloadDigest, payloadDigestOf(PARTS));
  assert.equal(typeof carried.payloadSignature, 'string');
});

let pass = 0, fail = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m ' + name); pass++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m ' + name + '\n       ' + (e.stack ?? e.message).split('\n').slice(0, 4).join('\n       ')); fail++; }
}
console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

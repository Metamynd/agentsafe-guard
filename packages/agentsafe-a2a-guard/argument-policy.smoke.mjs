// argument-policy.smoke.mjs — the owner's per-skill argument policy (MAGP §8.3.14) at the A2A receiver, the same contract as
// agentsafe-mcp-guard's argument-policy.smoke.mjs: a task's arguments are its one data part; a path outside `allow` is refused
// ARGUMENT_NOT_ALLOWED before any claim, and a `sensitive` value reaches the skill redacted or keyed-hashed, never as sent.
//
//   node argument-policy.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createA2aGuard, MAGP_A2A_EXTENSION_URI, a2aTaskArguments } from './agentsafe-a2a-guard.mjs';

const kp = () => crypto.generateKeyPairSync('ed25519');
const rawOf = (publicKey) => { const spki = publicKey.export({ type: 'spki', format: 'der' }); return spki.subarray(spki.length - 32); };
const agentKeys = kp();
const agentDid = buildHederaDid('testnet', rawOf(agentKeys.publicKey), '0.0.911');
const sign = (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), agentKeys.privateKey).toString('hex');
const ACTION = 'send-invoice';
const KEY = 'k'.repeat(32);
const POLICY = { allow: ['/to', '/lines/*/sku', '/lines/*/qty', '/note', '/iban'], sensitive: [{ path: '/iban', mode: 'hmac' }, { path: '/note', mode: 'redact' }] };
const bundleWith = (args) => ({ subject: agentDid, standards: [], sops: [], mandates: [{ action: ACTION, document: { permission: [{ target: ACTION, constraint: [], ...(args !== undefined ? { arguments: args } : {}) }] } }] });

function envelope() {
  const env = { agentDid, action: ACTION, amount: 0, currency: 'USD', merchant: '', nonce: crypto.randomUUID(), issuedAt: new Date().toISOString() };
  env.signature = sign(buildAuthMessage(env));
  return env;
}
const messageOf = (parts) => ({ contextId: 'c', taskId: 't', parts, metadata: { [MAGP_A2A_EXTENSION_URI]: envelope() } });
const meta = (status) => status?.message?.metadata?.[MAGP_A2A_EXTENSION_URI];
const mk = (args = POLICY, opts = {}) => createA2aGuard({ allowedAgents: 'any', fetchBundle: async () => bundleWith(args), argumentKey: KEY, ...opts });
const hmac = (v) => 'hmac-sha256:' + crypto.createHmac('sha256', KEY).update(JSON.stringify(v), 'utf8').digest('hex');

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('allowed arguments run; the skill gets the sensitive values redacted and keyed-hashed, never as sent', async () => {
  const ran = [];
  const skill = mk().guardA2ATask(ACTION, async (m) => { ran.push(m.parts[0]); return 'done'; });
  const out = await skill(messageOf([{ kind: 'data', data: { to: 'ap@acme', lines: [{ sku: 'X', qty: 2 }], note: 'card 4111', iban: 'GB00AAAA' }, metadata: { m: 1 } }]));
  assert.equal(out, 'done');
  assert.deepEqual(ran[0], { kind: 'data', data: { to: 'ap@acme', lines: [{ sku: 'X', qty: 2 }], note: '[REDACTED]', iban: hmac('GB00AAAA') }, metadata: { m: 1 } });
});

test('a path outside allow is refused before the skill runs and names the path', async () => {
  let ran = false;
  const skill = mk().guardA2ATask(ACTION, async () => { ran = true; });
  const status = await skill(messageOf([{ data: { to: 'ap@acme', bcc: 'x@evil' } }]));
  assert.deepEqual([meta(status).reasonCode, meta(status).path, ran], ['ARGUMENT_NOT_ALLOWED', '/bcc', false]);
  assert.equal(status.state, 'TASK_STATE_REJECTED');
});

test('a task whose parts are not exactly one data part is uncheckable under a policy, and unaffected without one', async () => {
  for (const parts of [[{ text: 'send it to ap@acme' }], [{ data: { to: 'a' } }, { text: 'and bcc x' }], [], [{ data: { to: 'a' }, text: 'x' }]]) {
    const status = await mk().guardA2ATask(ACTION, async () => 'ran')(messageOf(parts));
    assert.equal(meta(status)?.reasonCode, 'ARGUMENTS_UNCHECKABLE', JSON.stringify(parts));
    const noPolicy = createA2aGuard({ allowedAgents: 'any', fetchBundle: async () => bundleWith(undefined) });
    assert.equal(await noPolicy.guardA2ATask(ACTION, async () => 'ran')(messageOf(parts)), 'ran', JSON.stringify(parts));
  }
  assert.equal(a2aTaskArguments({ parts: [{ kind: 'file', data: {} }] }), undefined);
});

test('a policy that asks for a keyed hash refuses on an agent with no argumentKey', async () => {
  const status = await mk(POLICY, { argumentKey: undefined }).guardA2ATask(ACTION, async () => 'ran')(messageOf([{ data: { iban: 'GB00' } }]));
  assert.deepEqual([meta(status).reasonCode, meta(status).path], ['SENSITIVE_ARGUMENT_UNPROTECTED', '/iban']);
});

test('a refused task never claims a hold; verifyRequest without arguments is uncheckable', async () => {
  const real = globalThis.fetch;
  let claims = 0;
  globalThis.fetch = async () => { claims++; return { ok: true, status: 200, json: async () => ({}) }; };
  try {
    const guard = mk(POLICY, { requireAuthorization: true, issuerApi: 'https://issuer.example/api/v1' });
    const env = { ...envelope(), authorizationId: 'auth-1' };
    assert.equal((await guard.verifyRequest(env, { arguments: { bcc: 'x' } })).reasonCode, 'ARGUMENT_NOT_ALLOWED');
    assert.equal((await guard.verifyRequest(env)).reasonCode, 'ARGUMENTS_UNCHECKABLE');
    assert.equal(claims, 0);
  } finally { globalThis.fetch = real; }
});

test('an argumentKey shorter than 32 bytes is refused at construction; the guard says it checks arguments', () => {
  assert.throws(() => createA2aGuard({ allowedAgents: 'any', argumentKey: 'short' }), /argumentKey/);
  assert.equal(mk().checksArguments, true);
});

let failed = 0;
const quiet = console.warn; console.warn = () => {};
for (const [name, fn] of t) {
  try { await fn(); console.log(`PASS  ${name}`); } catch (e) { failed++; console.log(`FAIL  ${name}\n      ${e.message}`); }
}
console.warn = quiet;
console.log(failed === 0 ? '\nPASS' : `\nFAIL (${failed})`);
process.exit(failed === 0 ? 0 : 1);

// argument-policy.smoke.mjs — the owner's per-tool argument policy (policy-core argument-policy.ts), enforced by this guard.
//
// A mandate permission may carry `arguments: { allow, sensitive }`: the JSON Pointer paths a tool call's arguments may
// carry (anything else is refused, ARGUMENT_NOT_ALLOWED) and the values rewritten before the tool sees them (`redact`,
// or `hmac` with the Service's argumentKey). This proves the guard refuses a stray field before any handler runs, hands
// the handler the sanitized copy, refuses rather than send a value in the clear when it has no key, and refuses a call
// whose arguments it was not given.
//
//   node argument-policy.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), topic);
  return { did, sign: (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex') };
}

const agent = mint('0.0.910');
const service = mint('0.0.911');
const KEY = 'k'.repeat(32);

const bundle = {
  subject: agent.did,
  mandates: [
    {
      action: 'send-email',
      document: {
        permission: [{
          target: 'send-email',
          constraint: [],
          arguments: { allow: ['/to', '/subject', '/body'], sensitive: [{ path: '/to', mode: 'hmac' }, { path: '/body', mode: 'redact' }] },
        }],
      },
    },
    { action: 'read-report', document: { permission: [{ target: 'read-report', constraint: [] }] } },
  ],
};

function signedRequest(action) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const signature = agent.sign(buildAuthMessage({ agentDid: agent.did, action, amount: 0, currency: 'USD', merchant: '', nonce, issuedAt }));
  return { agentDid: agent.did, action, amount: 0, currency: 'USD', merchant: '', nonce, issuedAt, signature };
}

let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };
const refusal = async (fn) => { try { await fn(); return null; } catch (e) { return e?.governance ?? { reasonCode: String(e?.message ?? e) }; } };

const guard = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => bundle, argumentKey: KEY });
let seen = null;
const sendEmail = guard.guardIncomingTool('send-email', (_signed, args) => { seen = args; return { sent: true }; });

console.log('— arguments inside the policy run, sanitized —');
{
  seen = null;
  const args = { to: 'alice@example.com', subject: 'hi', body: 'secret' };
  await sendEmail(signedRequest('send-email'), args);
  const expectedTo = 'hmac-sha256:' + crypto.createHmac('sha256', KEY).update('"alice@example.com"').digest('hex');
  ok(seen?.to === expectedTo, 'the recipient reaches the tool as a keyed hash', seen?.to);
  ok(seen?.body === '[REDACTED]', 'the body reaches the tool redacted', seen?.body);
  ok(seen?.subject === 'hi', 'an allowed, non-sensitive value is unchanged');
  ok(args.to === 'alice@example.com', "the agent's own object is not modified");
}

console.log('\n— a stray argument is refused before the handler runs —');
{
  seen = null;
  const r = await refusal(() => sendEmail(signedRequest('send-email'), { to: 'a@b.c', bcc: 'x@evil.example' }));
  ok(seen === null, 'the handler never ran');
  ok(r?.reasonCode === 'ARGUMENT_NOT_ALLOWED' && r?.path === '/bcc', 'refused ARGUMENT_NOT_ALLOWED naming /bcc', `${r?.reasonCode} ${r?.path}`);
}

console.log('\n— a re-cased key is refused, not passed through —');
{
  const r = await refusal(() => sendEmail(signedRequest('send-email'), { To: 'a@b.c' }));
  ok(r?.reasonCode === 'ARGUMENT_NOT_ALLOWED', 'refused ARGUMENT_NOT_ALLOWED', r?.reasonCode);
}

console.log('\n— no key: a value the owner wants hashed is never sent in the clear —');
{
  const keyless = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => bundle });
  let ran = false;
  const tool = keyless.guardIncomingTool('send-email', () => { ran = true; });
  const r = await refusal(() => tool(signedRequest('send-email'), { to: 'a@b.c' }));
  ok(!ran && r?.reasonCode === 'SENSITIVE_ARGUMENT_UNPROTECTED', 'refused SENSITIVE_ARGUMENT_UNPROTECTED', r?.reasonCode);
}

console.log('\n— arguments the guard cannot see are refused —');
{
  const twoArgs = guard.guardIncomingTool('send-email', () => {});
  const r1 = await refusal(() => twoArgs(signedRequest('send-email'), { to: 'a@b.c' }, 'extra'));
  ok(r1?.reasonCode === 'ARGUMENTS_UNCHECKABLE', 'a tool called with two arguments: ARGUMENTS_UNCHECKABLE', r1?.reasonCode);
  const r2 = await guard.verifyRequest(signedRequest('send-email'));
  ok(r2?.decision === 'block' && r2?.reasonCode === 'ARGUMENTS_UNCHECKABLE', 'verifyRequest without { arguments }: ARGUMENTS_UNCHECKABLE', r2?.reasonCode);
  const r3 = await refusal(() => sendEmail(signedRequest('send-email'), ['a@b.c']));
  ok(r3?.reasonCode === 'ARGUMENTS_UNCHECKABLE', 'an array instead of an object: ARGUMENTS_UNCHECKABLE', r3?.reasonCode);
}

console.log('\n— the tool runs the snapshot that was checked, never the caller\'s object —');
{
  seen = null;
  let reads = 0;
  const shifty = { get to() { reads++; return reads === 1 ? 'a@b.c' : 'evil@x.example'; }, subject: 'hi' };
  await sendEmail(signedRequest('send-email'), shifty);
  const expected = 'hmac-sha256:' + crypto.createHmac('sha256', KEY).update('"a@b.c"').digest('hex');
  ok(seen?.to === expected && seen !== shifty, 'a getter is read once; the handler gets the checked value', seen?.to);
}

console.log('\n— a policy on any mandate the bundle holds for the action applies —');
{
  const twoMandates = { subject: agent.did, mandates: [
    { action: 'send-email', document: { permission: [{ target: 'send-email', constraint: [] }] } },
    { action: 'send-email', document: { permission: [{ target: 'send-email', constraint: [], arguments: { allow: ['/to'] } }] } },
  ] };
  const g = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => twoMandates });
  const r = await refusal(() => g.guardIncomingTool('send-email', () => {})(signedRequest('send-email'), { to: 'a@b.c', bcc: 'x' }));
  ok(r?.reasonCode === 'ARGUMENT_NOT_ALLOWED', 'the second mandate\'s policy refuses /bcc', r?.reasonCode);
}

console.log('\n— with requireAuthorization, a refused argument never claims the hold —');
{
  const realFetch = globalThis.fetch;
  let claims = 0;
  globalThis.fetch = async () => { claims++; return { ok: true, status: 200, json: async () => ({ success: true, data: { ok: true, effectState: 'dispatching', agentDid: agent.did, action: 'send-email', amount: 0, currency: 'USD', merchant: '', claimToken: 'tok-1' } }) }; };
  try {
    const claiming = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true, argumentKey: KEY });
    const r = await claiming.verifyRequest({ ...signedRequest('send-email'), authorizationId: 'auth-1' }, { arguments: { to: 'a@b.c', bcc: 'x' } });
    ok(r?.reasonCode === 'ARGUMENT_NOT_ALLOWED' && claims === 0, 'refused ARGUMENT_NOT_ALLOWED with no claim made', `${r?.reasonCode}, ${claims} claim(s)`);
    const good = await claiming.verifyRequest({ ...signedRequest('send-email'), authorizationId: 'auth-2' }, { arguments: { to: 'a@b.c' } });
    ok(good?.decision === 'allow' && claims === 1 && good.authorizationId === 'auth-2' && good.claimToken === 'tok-1' && good.arguments?.to?.startsWith('hmac-sha256:'), 'an allowed call claims once and carries both the claim and the sanitized arguments', `${good?.decision}, ${claims} claim(s)`);
  } finally { globalThis.fetch = realFetch; }
}

console.log('\n— a tool with no policy is unchanged —');
{
  let got;
  const read = guard.guardIncomingTool('read-report', (_s, a) => { got = a; });
  const arg = { anything: { goes: true } };
  await read(signedRequest('read-report'), arg);
  ok(got === arg, 'the handler receives the very object it was called with');
  const v = await guard.verifyRequest(signedRequest('read-report'));
  ok(v?.decision === 'allow', 'verifyRequest without arguments still allows', v?.decision);
}

console.log('\n— configuration —');
{
  let threw = null;
  try { createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => bundle, argumentKey: 'short' }); } catch (e) { threw = e; }
  ok(/argumentKey/.test(String(threw?.message)), 'a key shorter than 32 bytes is refused at construction');
}

console.log(failed === 0 ? '\nPASS' : `\nFAIL (${failed})`);
process.exit(failed === 0 ? 0 : 1);

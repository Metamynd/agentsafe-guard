// access-context.smoke.mjs — guardIncomingTool's `access` option: a tool's answer reaches the agent only when every tenant
// and user field in it names the principal the call is served for. The principal comes from the operator, after the request
// is verified; the check fails closed on anything it cannot read, and a refusal never echoes a value.
//
//   node access-context.smoke.mjs   → PASS when every case matches.
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

const agent = mint('0.0.920');
const service = mint('0.0.921');
const bundle = { subject: agent.did, mandates: [{ action: 'read-records', document: { permission: [{ target: 'read-records', constraint: [] }] } }] };

function signedRequest(extra = {}) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const signature = agent.sign(buildAuthMessage({ agentDid: agent.did, action: 'read-records', amount: 0, currency: 'USD', merchant: '', nonce, issuedAt }));
  return { agentDid: agent.did, action: 'read-records', amount: 0, currency: 'USD', merchant: '', nonce, issuedAt, signature, ...extra };
}

let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };
const refusal = async (fn) => { try { await fn(); return null; } catch (e) { return e?.name === 'GovernanceBlocked' ? e.governance : { reasonCode: `THREW ${e?.message}` }; } };
const warn = console.warn; console.warn = () => {};

const ACCESS = { tenant: ['/items/*/tenantId'], user: ['/items/*/owner'], principal: { tenantId: 'acme', userId: 'alice' } };
const row = (tenantId, owner) => ({ id: 'r', tenantId, owner });
const guard = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => bundle });
let answer;
let ran = 0;
const tool = (access) => guard.guardIncomingTool('read-records', () => { ran++; return answer; }, { access });

console.log('— an answer that belongs to the principal is released —');
{
  answer = { items: [row('acme', 'alice'), row('acme', 'alice')] };
  const out = await tool(ACCESS)(signedRequest(), {});
  ok(JSON.stringify(out) === JSON.stringify(answer), 'the records come back unchanged');
  answer = { items: [] };
  ok((await tool(ACCESS)(signedRequest(), {}))?.items?.length === 0, 'no records: nothing to withhold');
  answer = undefined;
  ok((await tool(ACCESS)(signedRequest(), {})) === undefined, 'a tool that returns nothing returns nothing');
}

console.log('\n— another tenant\'s or user\'s record withholds the whole answer, after the tool ran —');
{
  ran = 0;
  answer = { items: [row('acme', 'alice'), row('globex', 'alice')] };
  const r = await refusal(() => tool(ACCESS)(signedRequest(), {}));
  ok(ran === 1, 'the tool ran');
  ok(r?.reasonCode === 'ACCESS_CONTEXT_MISMATCH' && r?.path === '/items/1/tenantId' && r?.executed === true && r?.decision === 'block', 'refused ACCESS_CONTEXT_MISMATCH at /items/1/tenantId, executed', JSON.stringify(r));
  ok(!JSON.stringify(r).includes('globex'), 'the other tenant\'s id is not in the refusal');
  answer = { items: [row('acme', 'bob')] };
  ok((await refusal(() => tool(ACCESS)(signedRequest(), {})))?.reasonCode === 'ACCESS_CONTEXT_MISMATCH', 'the right tenant, another user: withheld');
  answer = { byTenant: { 'globex-corp': { id: 'globex-corp' } } };
  const keyed = await refusal(() => tool({ tenant: ['/byTenant/*/id'], principal: { tenantId: 'acme' } })(signedRequest(), {}));
  ok(keyed?.path === '/byTenant/*/id' && !JSON.stringify(keyed).includes('globex'), 'a map keyed by tenant name keeps `*` in the path', keyed?.path);
}

console.log('\n— what cannot be checked is withheld —');
{
  answer = { items: [{ id: 'r', owner: 'alice' }] };
  const missing = await refusal(() => tool(ACCESS)(signedRequest(), {}));
  ok(missing?.reasonCode === 'ACCESS_CONTEXT_UNCHECKABLE' && missing?.path === '/items/0/tenantId', 'a record without the field', JSON.stringify(missing));
  answer = { items: [row({ id: 'acme' }, 'alice')] };
  ok((await refusal(() => tool(ACCESS)(signedRequest(), {})))?.reasonCode === 'ACCESS_CONTEXT_UNCHECKABLE', 'a value that is not a string or number');
  answer = { items: [row('acme', 'alice')], n: 1n };
  const big = await refusal(() => tool(ACCESS)(signedRequest(), {}));
  ok(big?.reasonCode === 'ACCESS_CONTEXT_UNCHECKABLE' && big?.detail === 'the answer cannot be written as JSON', 'a BigInt: the answer is not JSON', JSON.stringify(big));
}

console.log('\n— the agent gets the snapshot that was checked, never a live object —');
{
  let reads = 0;
  answer = { items: [{ get tenantId() { reads++; return reads === 1 ? 'acme' : 'globex'; }, owner: 'alice' }] };
  const out = await tool(ACCESS)(signedRequest(), {});
  ok(out.items[0].tenantId === 'acme' && reads === 1, 'a getter is read once; what is returned is what was checked', `${out.items[0].tenantId}, ${reads} read(s)`);
}

console.log('\n— the principal comes from the operator\'s resolver, after verification —');
{
  answer = { items: [row('t-7', 'u-9')] };
  let seen = null;
  const resolved = tool({ ...ACCESS, principal: (signed, args) => { seen = [signed.agentDid, args]; return { tenantId: 't-7', userId: 'u-9' }; } });
  const out = await resolved(signedRequest(), { q: 1 });
  ok(out?.items?.length === 1 && seen?.[0] === agent.did && seen?.[1]?.q === 1, 'the resolver gets the verified request and the arguments');
  ran = 0;
  const r = await refusal(() => tool({ ...ACCESS, principal: async () => { throw new Error('directory down'); } })(signedRequest(), {}));
  ok(ran === 0 && r?.reasonCode === 'ACCESS_PRINCIPAL_UNAVAILABLE' && r?.executed === false, 'a failing resolver: ACCESS_PRINCIPAL_UNAVAILABLE, the tool never ran', JSON.stringify(r));
  const partial = await refusal(() => tool({ ...ACCESS, principal: () => ({ tenantId: 'acme' }) })(signedRequest(), {}));
  ok(partial?.reasonCode === 'ACCESS_PRINCIPAL_UNAVAILABLE', 'a resolver that names no userId for a user check');
  ran = 0;
  const unverified = await refusal(() => tool({ ...ACCESS, principal: () => { throw new Error('must not be called'); } })({ ...signedRequest(), signature: '00' }, {}));
  ok(ran === 0 && unverified?.reasonCode !== 'ACCESS_PRINCIPAL_UNAVAILABLE', 'a request that fails verification never reaches the resolver', unverified?.reasonCode);
}

console.log('\n— a hold this guard settles: released when nothing ran, captured when the answer is withheld —');
{
  const realFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url).replace(/^.*\/authorize\/[^/]+\//, ''));
    return { ok: true, status: 200, json: async () => ({ success: true, data: { ok: true, effectState: 'dispatching', agentDid: agent.did, action: 'read-records', amount: 0, currency: 'USD', merchant: '', claimToken: 'tok-1' } }) };
  };
  try {
    const claiming = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true });
    const settled = (access) => claiming.guardIncomingTool('read-records', () => answer, { settle: true, access });
    calls.length = 0;
    await refusal(() => settled({ ...ACCESS, principal: () => null })({ ...signedRequest(), authorizationId: 'auth-1' }, {}));
    ok(calls.includes('void') && !calls.includes('capture'), 'no principal: the hold is released (void), never captured', calls.join(','));
    calls.length = 0;
    answer = { items: [row('globex', 'alice')] };
    const r = await refusal(() => settled(ACCESS)({ ...signedRequest(), authorizationId: 'auth-2' }, {}));
    ok(r?.reasonCode === 'ACCESS_CONTEXT_MISMATCH' && calls.includes('capture') && !calls.includes('void'), 'withheld: the hold is captured (the tool ran), the answer refused', calls.join(','));
  } finally { globalThis.fetch = realFetch; }
}

console.log('\n— a misconfigured tool fails when it is wrapped; a tool without `access` is unchanged —');
{
  for (const bad of [null, { tenant: ['/t'] }, { tenant: ['t'], principal: { tenantId: 'a' } }, { principal: { tenantId: 'a' } }, { tenant: ['/t'], principal: {} }, { tenant: ['/t'], principal: { tenantId: 'a' }, extra: 1 }]) {
    let threw = false;
    try { guard.guardIncomingTool('read-records', () => {}, { access: bad }); } catch { threw = true; }
    ok(threw, `refused at wrap time: ${JSON.stringify(bad)}`);
  }
  const live = { items: [row('globex', 'x')] };
  const plain = guard.guardIncomingTool('read-records', () => live);
  ok((await plain(signedRequest(), {})) === live, 'no `access`: the handler\'s own object comes back, unchecked');
}

console.warn = warn;
console.log(failed === 0 ? '\nPASS' : `\nFAIL (${failed})`);
process.exit(failed === 0 ? 0 : 1);

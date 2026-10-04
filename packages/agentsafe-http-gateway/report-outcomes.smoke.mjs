// report-outcomes.smoke.mjs — A-1 of the 2026-10-03 pre-beta rerun, at the gateway: with `reportOutcomes`, every governed
// request the gateway answers is reported through the guard (MAGP §16.4) — what it ran WITHOUT a claim, and what it refused
// itself — in the background, without changing a response. A claimed execution is not reported (the claim already put it
// on the effect chain), and a request that named no agent has nobody to attribute it to.
//
//   node report-outcomes.smoke.mjs
import assert from 'node:assert/strict';
import { createHttpGateway } from './gateway.mjs';

const reports = [];
const verdicts = new Map(); // agentDid -> verdict
const guard = {
  async verifyRequest(signed) { return verdicts.get(signed.agentDid) ?? { decision: 'block', reasonCode: 'AGENT_NOT_SERVED' }; },
  async reportOutcome(r) { reports.push(r); return { ok: true, reasonCode: 'RECORDED' }; },
};
const route = { method: 'POST', path: '/perform', action: 'records-update', valueFields: [], allowedFields: [] };
let forwarded = 0;
const gatewayWith = (opts = {}) => createHttpGateway({ guard, routes: [route], denyByDefault: true, settle: false, forward: async () => { forwarded++; return { status: 200, body: { done: true } }; }, ...opts });
const signedBy = (agentDid, extra = {}) => ({ agentDid, action: 'records-update', amount: 0, currency: 'USD', merchant: '', nonce: `n-${Math.random()}`, issuedAt: new Date().toISOString(), signature: 'ab', ...extra });
const call = (gw, signed, path = '/perform') => gw({ method: 'POST', path, headers: signed ? { 'x-magp-request': JSON.stringify(signed) } : {}, rawBody: Buffer.from('{}') });
const settled = (gw) => gw.drainSettlements(2000);

let failed = 0;
async function check(label, fn) {
  reports.length = 0; forwarded = 0;
  try { await fn(); console.log(`PASS  ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}

verdicts.set('did:key:zMine', { decision: 'allow', reasonCode: 'AUTHORIZED' });
verdicts.set('did:key:zClaimed', { decision: 'allow', reasonCode: 'AUTHORIZED', authorizationId: 'auth-1', counterpartyAuthenticated: true });

await check('an unclaimed execution is reported as executed, with the agent\'s signed request', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  const res = await call(gw, signedBy('did:key:zMine'));
  await settled(gw);
  assert.equal(res.status, 200);
  assert.equal(reports.length, 1);
  assert.deepEqual([reports[0].outcome, reports[0].reasonCode, reports[0].httpStatus, reports[0].signed.agentDid], ['executed', 'EXECUTED', 200, 'did:key:zMine']);
});

await check('a refusal the gateway decided (another agent: AGENT_NOT_SERVED) is reported as refused', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  const res = await call(gw, signedBy('did:key:zTheirs'));
  await settled(gw);
  assert.equal(res.status, 403);
  assert.equal(forwarded, 0);
  assert.deepEqual([reports[0].outcome, reports[0].reasonCode, reports[0].httpStatus], ['refused', 'AGENT_NOT_SERVED', 403]);
});

await check('a binding refusal before the guard runs is reported too (it named an agent)', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  const res = await gw({ method: 'POST', path: '/perform', headers: { 'x-magp-request': JSON.stringify(signedBy('did:key:zMine')) }, rawBody: Buffer.from('{"surcharge":5}') });
  await settled(gw);
  assert.equal(res.body.reasonCode, 'PAYLOAD_UNBINDABLE');
  assert.deepEqual([reports[0].outcome, reports[0].reasonCode], ['refused', 'PAYLOAD_UNBINDABLE']);
});

await check('repeated refusals of one caller for one reason are coalesced (a flood must not bury the owner\'s log)', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  for (let i = 0; i < 5; i++) await call(gw, signedBy('did:key:zTheirs'));
  await call(gw, signedBy('did:key:zOther'));
  await call(gw, signedBy('did:key:zMine'));
  await call(gw, signedBy('did:key:zMine'));
  await settled(gw);
  const refused = reports.filter((r) => r.outcome === 'refused');
  assert.deepEqual(refused.map((r) => r.signed.agentDid), ['did:key:zTheirs', 'did:key:zOther'], 'one per (caller, reason) per minute');
  assert.equal(reports.filter((r) => r.outcome === 'executed').length, 2, 'executions are never coalesced');
});

await check('a claimed execution is not reported (the claim already put it on the effect chain)', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  await call(gw, signedBy('did:key:zClaimed'));
  await settled(gw);
  assert.equal(forwarded, 1);
  assert.equal(reports.length, 0);
});

await check('a request that named no agent, or an unrouted path, has nobody to attribute it to: not reported', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  assert.equal((await call(gw, null)).body.reasonCode, 'MISSING_GOVERNANCE');
  assert.equal((await call(gw, signedBy('did:key:zMine'), '/elsewhere')).body.reasonCode, 'ROUTE_NOT_ALLOWED');
  await settled(gw);
  assert.equal(reports.length, 0);
});

await check('off by default: nothing is reported', async () => {
  const gw = gatewayWith();
  await call(gw, signedBy('did:key:zMine'));
  await call(gw, signedBy('did:key:zTheirs'));
  await settled(gw);
  assert.equal(reports.length, 0);
});

await check('a report that fails never changes the response', async () => {
  const failing = { ...guard, async reportOutcome() { throw new Error('issuer down'); } };
  const quiet = console.warn; console.warn = () => {};
  try {
    const gw = createHttpGateway({ guard: failing, routes: [route], denyByDefault: true, settle: false, reportOutcomes: true, forward: async () => ({ status: 200, body: { done: true } }) });
    const res = await call(gw, signedBy('did:key:zMine'));
    assert.equal(await gw.drainSettlements(2000), 0);
    assert.equal(res.status, 200);
  } finally { console.warn = quiet; }
});

if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log('\nPASS — the gateway reports what it ran without a claim and what it refused, and nothing else.');

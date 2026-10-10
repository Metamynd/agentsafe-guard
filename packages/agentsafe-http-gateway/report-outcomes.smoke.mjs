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
  async verifyRequest(signed) { return verdicts.get(signed.agentDid) ?? { decision: 'block', reasonCode: 'AGENT_NOT_ADMITTED' }; },
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

// Pre-beta rerun 6 FW6-3: a low-risk request allowed on its own merits, naming an approved escalation's authorization it
// never claimed, must not be reported as having run under that authorization.
await check('an unclaimed execution that NAMES an authorization is reported without claiming it ran under it', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  const res = await call(gw, signedBy('did:key:zMine', { authorizationId: 'auth-approved' }));
  await settled(gw);
  assert.equal(res.status, 200);
  assert.equal(reports.length, 1);
  assert.equal(reports[0].signed.authorizationId, 'auth-approved', 'the request is passed on as received (the guard reports it as presented)');
  assert.equal(reports[0].claimedAuthorizationId, undefined, 'never reported as claimed');
});

await check('a refusal after a CLAIM names the claimed authorization', async () => {
  const gw = gatewayWith({ reportOutcomes: true, resolveCredential: async () => null });
  const res = await call(gw, signedBy('did:key:zClaimed', { authorizationId: 'auth-1' }));
  await settled(gw);
  assert.equal(res.body.reasonCode, 'CREDENTIAL_UNAVAILABLE');
  assert.deepEqual([reports[0].outcome, reports[0].claimedAuthorizationId], ['refused', 'auth-1']);
});

await check('a refusal the gateway decided (another agent: AGENT_NOT_ADMITTED) is reported as refused', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  const res = await call(gw, signedBy('did:key:zTheirs'));
  await settled(gw);
  assert.equal(res.status, 403);
  assert.equal(forwarded, 0);
  assert.deepEqual([reports[0].outcome, reports[0].reasonCode, reports[0].httpStatus], ['refused', 'AGENT_NOT_ADMITTED', 403]);
});

await check('a binding refusal before the guard runs is reported too (it named an agent)', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  const res = await gw({ method: 'POST', path: '/perform', headers: { 'x-magp-request': JSON.stringify(signedBy('did:key:zMine')) }, rawBody: Buffer.from('{"surcharge":5}') });
  await settled(gw);
  assert.equal(res.body.reasonCode, 'PAYLOAD_UNBINDABLE');
  assert.deepEqual([reports[0].outcome, reports[0].reasonCode], ['refused', 'PAYLOAD_UNBINDABLE']);
});

// Pre-beta 2026-10-09, L1: a query-string refusal returned before the request was read, so it never reached the owner's
// Activity Log. It names an agent like any other signed request; one with no signed request still names nobody.
await check('a query-string refusal of a signed request is reported (QUERY_NOT_BOUND)', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  const res = await call(gw, signedBy('did:key:zMine'), '/perform?amount=9999');
  await settled(gw);
  assert.equal(res.body.reasonCode, 'QUERY_NOT_BOUND');
  assert.equal(forwarded, 0);
  assert.deepEqual([reports[0]?.outcome, reports[0]?.reasonCode, reports[0]?.httpStatus, reports[0]?.signed.agentDid], ['refused', 'QUERY_NOT_BOUND', 403, 'did:key:zMine']);
});

await check('a query-string refusal with no signed request names nobody, so nothing is reported', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  const res = await call(gw, null, '/perform?amount=9999');
  await settled(gw);
  assert.equal(res.body.reasonCode, 'QUERY_NOT_BOUND');
  assert.equal(reports.length, 0);
});
await check('repeated refusals of one caller for one reason are aggregated: the first at once, the rest as ONE report with their count', async () => {
  const gw = gatewayWith({ reportOutcomes: true });
  for (let i = 0; i < 5; i++) await call(gw, signedBy('did:key:zTheirs'));
  await call(gw, signedBy('did:key:zOther'));
  await call(gw, signedBy('did:key:zMine'));
  await call(gw, signedBy('did:key:zMine'));
  await settled(gw); // closes the open windows
  const refused = reports.filter((r) => r.outcome === 'refused');
  assert.deepEqual(refused.map((r) => [r.signed.agentDid, r.occurrences ?? 1]), [['did:key:zTheirs', 1], ['did:key:zOther', 1], ['did:key:zTheirs', 4]], 'nothing dropped: 1 + 4 = 5');
  assert.equal(reports.filter((r) => r.outcome === 'executed').length, 2, 'executions are never aggregated');
  // The aggregate is carried by the latest repeat, not a copy of the first refusal (already reported on its own).
  const theirs = refused.filter((r) => r.signed.agentDid === 'did:key:zTheirs');
  assert.notEqual(theirs[1].signed.nonce, theirs[0].signed.nonce, 'the aggregate is a different signed request');
});

await check('a refusal window closes on its own timer, and the next refusal opens a fresh one', async () => {
  const gw = gatewayWith({ reportOutcomes: true, refusalWindowMs: 40 });
  await call(gw, signedBy('did:key:zTheirs'));
  await call(gw, signedBy('did:key:zTheirs'));
  await call(gw, signedBy('did:key:zTheirs'));
  await new Promise((r) => setTimeout(r, 120));
  await call(gw, signedBy('did:key:zTheirs'));
  await settled(gw);
  assert.deepEqual(reports.map((r) => r.occurrences ?? 1), [1, 2, 1]);
});

await check('a report the issuer could not take is spooled and re-sent with the SAME reportId; a refused one is not', async () => {
  const fsp = await import('node:fs/promises'); const os = await import('node:os'); const path = await import('node:path');
  const spool = path.join(await fsp.mkdtemp(path.join(os.tmpdir(), 'gw-spool-')), 'reports.jsonl');
  let down = true; const seen = [];
  const flaky = { ...guard, async reportOutcome(r) {
    const reportId = r.reportId ?? `rpt_${seen.length}_abcdefgh`; seen.push({ ...r, reportId });
    if (r.signed.agentDid === 'did:key:zRefusedByIssuer') return { ok: false, status: 403, reasonCode: 'COUNTERPARTY_NOT_REGISTERED', reportId };
    return down ? { ok: false, reasonCode: 'REPORT_UNREACHABLE', reportId } : { ok: true, reasonCode: 'RECORDED', reportId };
  } };
  verdicts.set('did:key:zRefusedByIssuer', { decision: 'allow', reasonCode: 'AUTHORIZED' });
  const quiet = console.warn; console.warn = () => {};
  try {
    const gw = createHttpGateway({ guard: flaky, routes: [route], denyByDefault: true, settle: false, reportOutcomes: true, reportSpool: spool, forward: async () => ({ status: 200, body: { done: true } }) });
    await call(gw, signedBy('did:key:zMine'));
    await call(gw, signedBy('did:key:zRefusedByIssuer'));
    await gw.drainSettlements(2000);
    const spooled = (await fsp.readFile(spool, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l));
    assert.deepEqual(spooled.map((p) => p.signed.agentDid), ['did:key:zMine'], 'only the transient failure is kept');
    const firstId = spooled[0].reportId;
    assert.equal(await gw.flushReports(), 0, 'still down: nothing recorded, kept for later');
    assert.equal((await fsp.readFile(spool, 'utf8')).split('\n').filter(Boolean).length, 1);
    down = false;
    assert.equal(await gw.flushReports(), 1);
    assert.equal(seen.at(-1).reportId, firstId, 'the issuer sees the same reportId, so a report that did land is recorded once');
    await assert.rejects(() => fsp.readFile(spool, 'utf8'), 'the spool is empty once everything landed');
  } finally { console.warn = quiet; verdicts.delete('did:key:zRefusedByIssuer'); }
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

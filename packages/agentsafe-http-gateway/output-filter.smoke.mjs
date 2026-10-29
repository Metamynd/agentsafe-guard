// output-filter.smoke.mjs — route.output: a request is forwarded only when what would leave (the body after any argument
// rewrite, and the query string) has none of the operator's forbidden words. A refusal names where, never the word;
// nothing is sent and a claimed hold is released.
//
//   node output-filter.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import { createHttpGateway } from './gateway.mjs';

const quiet = console.warn; console.warn = () => {};
let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`PASS  ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}

const OUTPUT = { forbidden: ['ssn', 'Falcon'] };
let forwarded = [];
let released = [];
let verdict = { decision: 'allow', authorizationId: 'auth-1', claimToken: 't' };
const forward = async (req) => { forwarded.push(req); return { status: 200, body: { ok: true } }; };
const guard = {
  verifyRequest: async () => verdict,
  releaseAuthorization: async (a) => { released.push(a.reason); return { ok: true }; },
  captureAuthorization: async () => ({ ok: true }),
};
const gatewayWith = (output, extra = {}) => createHttpGateway({
  guard, forward, settle: true, settleInBackground: false, reportOutcomes: false, denyByDefault: true,
  routes: [{ method: 'POST', path: '/messages', action: 'send-message', bind: false, extract: () => ({ agentDid: 'did:x', action: 'send-message' }), output, ...extra }],
});
const send = (gw, body, path = '/messages') => gw({ method: 'POST', path, headers: {}, rawBody: typeof body === 'string' ? new TextEncoder().encode(body) : body });
const reset = () => { forwarded = []; released = []; verdict = { decision: 'allow', authorizationId: 'auth-1', claimToken: 't' }; };

await check('clean text is forwarded as it is', async () => {
  reset();
  const res = await send(gatewayWith(OUTPUT), JSON.stringify({ to: 'x', text: 'lessons on falconry' }));
  assert.equal(res.status, 200);
  assert.equal(forwarded.length, 1);
});

await check('a forbidden word refuses the request: 403, the path, never the word; nothing sent, the hold released', async () => {
  reset();
  const res = await send(gatewayWith(OUTPUT), JSON.stringify({ to: 'x', text: ['hi', 'Customer SSN: 123'] }));
  assert.deepEqual(res.body, { decision: 'block', reasonCode: 'OUTPUT_FORBIDDEN_WORD', path: '/text/1', action: 'send-message', executed: false });
  assert.equal(res.status, 403);
  assert.equal(forwarded.length, 0);
  assert.deepEqual(released, ['OUTPUT_FORBIDDEN_WORD']);
});

await check('a fullwidth or differently-cased spelling, an object key, and a non-JSON body are all checked', async () => {
  for (const body of [JSON.stringify({ text: 'ＦＡＬＣＯＮ' }), JSON.stringify({ meta: { ssn: 1 } }), 'plain text with an SSN in it', '{"t":"\u0073sn"}']) {
    reset();
    assert.equal((await send(gatewayWith(OUTPUT), body)).body.reasonCode, 'OUTPUT_FORBIDDEN_WORD', body);
    assert.equal(forwarded.length, 0, body);
  }
});

await check('JSON that is not strict is uncheckable, never read as plain text; a form body is decoded', async () => {
  reset();
  const dup = await send(gatewayWith(OUTPUT), '{"a":1,"a":2,"t":"\u0073sn"}');
  assert.deepEqual([dup.body.reasonCode, dup.body.detail], ['OUTPUT_UNCHECKABLE', 'the body is not strict JSON']);
  const form = (body) => gatewayWith(OUTPUT)({ method: 'POST', path: '/messages', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, rawBody: new TextEncoder().encode(body) });
  assert.equal((await form('note=%73sn')).body.reasonCode, 'OUTPUT_FORBIDDEN_WORD');
  assert.equal((await form('note=%E0%A4%A')).body.reasonCode, 'OUTPUT_UNCHECKABLE');
  assert.equal((await form('note=hello')).status, 200);
  assert.equal(forwarded.length, 1);
});

await check('both body fields are checked when both are set; a non-JSON value in a parsed body is uncheckable', async () => {
  reset();
  const gw = gatewayWith(OUTPUT);
  const both = await gw({ method: 'POST', path: '/messages', headers: {}, rawBody: new TextEncoder().encode('{"t":"fine"}'), body: { t: 'the ssn' } });
  assert.equal(both.body.reasonCode, 'OUTPUT_FORBIDDEN_WORD');
  assert.equal((await gw({ method: 'POST', path: '/messages', headers: {}, body: { n: 4111n } })).status, 200);
  assert.equal((await gw({ method: 'POST', path: '/messages', headers: {}, body: { m: new Map([['ssn', 1]]) } })).body.reasonCode, 'OUTPUT_UNCHECKABLE');
  assert.equal(forwarded.length, 1);
});

await check('the query string is checked too, and one that does not decode is uncheckable', async () => {
  reset();
  const gw = gatewayWith(OUTPUT, { allowedQuery: ['q'] });
  assert.deepEqual([(await send(gw, '', '/messages?q=my+ssn')).body.reasonCode, (await send(gw, '', '/messages?q=my+ssn')).body.path], ['OUTPUT_FORBIDDEN_WORD', '?']);
  assert.equal((await send(gw, '', '/messages?q=%E0%A4%A')).body.reasonCode, 'OUTPUT_UNCHECKABLE');
  assert.equal((await send(gw, '', '/messages?q=hello')).status, 200);
});

await check('a body that is not UTF-8 is uncheckable; an empty body passes', async () => {
  reset();
  assert.equal((await send(gatewayWith(OUTPUT), new Uint8Array([0xff, 0xfe, 0x00]))).body.reasonCode, 'OUTPUT_UNCHECKABLE');
  assert.equal((await send(gatewayWith(OUTPUT), new Uint8Array(0))).status, 200);
});

await check('what is checked is what would leave: the body after the owner\'s argument rewrite', async () => {
  reset();
  verdict = { decision: 'allow', authorizationId: 'auth-1', claimToken: 't', arguments: { to: 'x', text: '[redacted]' } };
  const gw = createHttpGateway({ guard: { ...guard, checksArguments: true }, forward, settle: true, settleInBackground: false, reportOutcomes: false,
    routes: [{ method: 'POST', path: '/messages', action: 'send-message', bind: false, extract: () => ({ agentDid: 'did:x' }), output: OUTPUT }] });
  const res = await send(gw, JSON.stringify({ to: 'x', text: 'the ssn' }));
  assert.equal(res.status, 200);
  assert.equal(JSON.parse(new TextDecoder().decode(forwarded[0].rawBody)).text, '[redacted]');
});

await check('a request the guard refuses is refused for that, not for its text', async () => {
  reset();
  verdict = { decision: 'block', reasonCode: 'SIGNATURE_INVALID' };
  assert.equal((await send(gatewayWith(OUTPUT), JSON.stringify({ text: 'ssn' }))).body.reasonCode, 'SIGNATURE_INVALID');
});

await check('a refused request is reported refused under its output code', async () => {
  reset();
  const reports = [];
  const signed = { agentDid: 'did:x', action: 'send-message', nonce: 'n', issuedAt: '2026-10-29T00:00:00Z', signature: 's' };
  const gw = createHttpGateway({ guard: { ...guard, reportOutcome: async (p) => { reports.push(p); return { ok: true }; } }, forward, settle: true, settleInBackground: false, reportOutcomes: true, refusalWindowMs: 1,
    routes: [{ method: 'POST', path: '/messages', action: 'send-message', bind: false, extract: () => signed, output: OUTPUT }] });
  await send(gw, JSON.stringify({ text: 'ssn' }));
  await gw.drainSettlements(1000);
  await new Promise((r) => setTimeout(r, 20));
  await gw.flushReports?.();
  assert.deepEqual(reports.map((p) => [p.outcome, p.reasonCode, p.httpStatus]), [['refused', 'OUTPUT_FORBIDDEN_WORD', 403]]);
});

await check('a misconfigured route fails startup; a route without output is unchanged', async () => {
  for (const bad of [null, {}, { forbidden: [] }, { forbidden: ['credit card'] }, { forbidden: ['ssn'], extra: 1 }]) {
    assert.throws(() => gatewayWith(bad), undefined, JSON.stringify(bad));
  }
  reset();
  assert.equal((await send(gatewayWith(undefined), JSON.stringify({ text: 'ssn' }))).status, 200);
});

await check('the gateway and the MCP guard ship the same output-filter.mjs', async () => {
  const { readFile } = await import('node:fs/promises');
  for (const name of ['output-filter.mjs', 'output-filter.d.mts']) {
    const mine = await readFile(new URL(`./${name}`, import.meta.url), 'utf8');
    const guards = await readFile(new URL(`../agentsafe-mcp-guard/${name}`, import.meta.url), 'utf8').catch(() => null);
    if (guards === null) return; // a published copy of this package alone: nothing to compare
    assert.equal(mine.replace(/\r\n/g, '\n'), guards.replace(/\r\n/g, '\n'), `edit both copies of ${name} together`);
  }
});

console.warn = quiet;
console.log(failed === 0 ? '\nPASS' : `\nFAIL (${failed})`);
process.exit(failed === 0 ? 0 : 1);

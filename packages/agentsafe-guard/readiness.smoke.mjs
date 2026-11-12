// readiness.smoke.mjs — the readiness CLI against a fake API: status, gate, --issue, --min, staleness, the token rule.
import assert from 'node:assert/strict';
import { readinessGate, readinessStatus, ReadinessError } from './readiness.mjs';

const API = 'https://api.example.test/api/v1';
const REPORT = '11111111-1111-4111-8111-111111111111';

function fakeApi({ status = 'conditional', validity = 'current', reports = [{ reportId: REPORT, target: 'autonomous-payments' }], authentic = true } = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, method: init.method ?? 'GET', auth: init.headers?.authorization ?? null, body: init.body ?? null });
    const u = new URL(url);
    const ok = (data) => ({ ok: true, status: 200, json: async () => ({ success: true, data }), text: async () => '<html>report</html>' });
    if (u.pathname.endsWith('/status')) {
      return ok({ reportId: REPORT, authentic, status: validity, reasons: validity === 'current' ? [] : [{ code: 'MANDATE_CHANGED', description: "The agent's mandate changed." }], reassessBy: '2027-02-10', supersededBy: null, ...(u.searchParams.has('hash') ? { hashMatches: u.searchParams.get('hash') === 'sha256:good' } : {}) });
    }
    if (u.pathname.endsWith('/readiness-reports') && (init.method ?? 'GET') === 'POST') return ok({ reportId: 'issued-now' });
    if (u.pathname.endsWith('/readiness-reports')) return ok(reports);
    if (u.pathname.includes('/readiness-reports/')) {
      return ok({ reportId: REPORT, targetLabel: 'autonomous production payments', status: { status, reasons: ['Gate G1 not evidenced.'] }, risk: { grade: 'C', index: 30, band: { low: 25, high: 35 } }, gates: [{ id: 'G1', result: 'not-evidenced' }], verification: { reportHash: 'sha256:abc' }, validity: { status: validity, triggers: validity === 'current' ? [] : ['MANDATE_CHANGED'] } });
    }
    return { ok: false, status: 404, json: async () => ({ message: 'not found' }) };
  };
  return { fetchImpl, calls };
}

const env = { METAMYND_TOKEN: 'mm_pat_' + 'x'.repeat(43) };

// status: public, no token sent; current + authentic passes; a changed mandate fails with the reason; a wrong copy fails.
{
  const { fetchImpl, calls } = fakeApi();
  const r = await readinessStatus({ reportId: REPORT, flags: { api: API }, env: {}, fetchImpl });
  assert.equal(r.ok, true);
  assert.equal(calls[0].auth, null, 'status sends no token');
  const stale = await readinessStatus({ reportId: REPORT, flags: { api: API }, env: {}, fetchImpl: fakeApi({ validity: 'reassessment-required' }).fetchImpl });
  assert.equal(stale.ok, false);
  assert.match(stale.lines.join('\n'), /mandate changed/);
  const wrong = await readinessStatus({ reportId: REPORT, hash: 'sha256:bad', flags: { api: API }, env: {}, fetchImpl });
  assert.equal(wrong.ok, false);
  assert.equal((await readinessStatus({ reportId: REPORT, flags: { api: API }, env: {}, fetchImpl: fakeApi({ authentic: false }).fetchImpl })).ok, false);
}

// gate: needs the token from the environment, sends it as a bearer, and judges status against --min.
{
  await assert.rejects(readinessGate({ flags: { api: API, programme: 'p' }, env: {}, fetchImpl: fakeApi().fetchImpl }), ReadinessError);
  const { fetchImpl, calls } = fakeApi({ status: 'conditional' });
  const strict = await readinessGate({ flags: { api: API, programme: 'p' }, env, fetchImpl });
  assert.equal(strict.ok, false, 'conditional does not meet the default min of ready');
  assert.ok(calls.every((c) => c.auth === `Bearer ${env.METAMYND_TOKEN}`));
  const lenient = await readinessGate({ flags: { api: API, programme: 'p', min: 'conditional' }, env, fetchImpl });
  assert.equal(lenient.ok, true);
}

// gate: a report needing reassessment fails unless --allow-stale; --issue issues first; no report is an error, not a pass.
{
  const stale = fakeApi({ status: 'ready', validity: 'reassessment-required' });
  assert.equal((await readinessGate({ flags: { api: API, programme: 'p' }, env, fetchImpl: stale.fetchImpl })).ok, false);
  assert.equal((await readinessGate({ flags: { api: API, programme: 'p', 'allow-stale': true }, env, fetchImpl: stale.fetchImpl })).ok, true);
  const { fetchImpl, calls } = fakeApi({ status: 'ready' });
  const issued = await readinessGate({ flags: { api: API, programme: 'p', issue: true, target: 'supervised-payments' }, env, fetchImpl });
  assert.equal(issued.reportId, 'issued-now');
  assert.deepEqual(JSON.parse(calls[0].body), { target: 'supervised-payments' });
  await assert.rejects(readinessGate({ flags: { api: API, programme: 'p' }, env, fetchImpl: fakeApi({ reports: [] }).fetchImpl }), /no issued report/);
}

// --out writes the printable report; a token is never sent to a plain-HTTP remote host.
{
  let written = null;
  await readinessGate({ flags: { api: API, programme: 'p', out: 'r.html' }, env, fetchImpl: fakeApi({ status: 'ready' }).fetchImpl, writeFile: async (p, s) => (written = [p, s]) });
  assert.deepEqual(written, ['r.html', '<html>report</html>']);
  await assert.rejects(readinessGate({ flags: { api: 'http://api.example.test/api/v1', programme: 'p' }, env, fetchImpl: fakeApi().fetchImpl }), /must be https/);
  await readinessStatus({ reportId: REPORT, flags: { api: 'http://localhost:9926/api/v1' }, env: {}, fetchImpl: fakeApi().fetchImpl });
}

console.log('readiness.smoke: ok');

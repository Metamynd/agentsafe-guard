// verify.smoke.mjs — the CI governance check, checked.
//
// The property under test is not "does it pass an agent that is fine". It is that it
// refuses to report a control as holding when the control does not exist. That distinction
// is the whole reason this command was written: the public sandbox mandate carried
// `merchants: []`, an unapproved supplier was paid $250, and every surface that could have
// noticed reported nothing wrong.
//
// Zero dependencies, no network: `loadBundle` and `createGuardFromConfig` are stubbed with
// a fake fetch, so this runs anywhere `node` runs.

import crypto from 'node:crypto';
import assert from 'node:assert/strict';

import { verify } from './verify.mjs';

let failures = 0;
const ok = (label, cond, extra = '') => {
  console.log(`${cond ? 'ok   ' : 'NOT OK'} ${label}${extra ? '  →  ' + extra : ''}`);
  if (!cond) failures++;
};

/** A throwaway Ed25519 key in the DER PKCS#8 hex the guard expects. */
const { privateKey } = crypto.generateKeyPairSync('ed25519');
const AGENT_KEY = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const AGENT_DID = 'did:hedera:testnet:zVerify_0.0.1';

const mandate = (constraints) => ({
  uid: 'urn:metamynd:mandate:verify-smoke',
  validFrom: '2020-01-01T00:00:00Z',
  permission: [{ target: 'flight-purchase', action: 'execute', constraint: constraints }],
});

const CAP = { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 500, unit: 'USD' };
const TOTAL = { leftOperand: 'mm:cumulativeSpend', operator: 'lteq', rightOperand: 5000, unit: 'USD' };
const MERCHANTS = { leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: ['skyward-air'] };

/** Serve a policy bundle carrying exactly the constraints under test. */
function stubFetch(constraints) {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      data: {
        subject: AGENT_DID,
        issuedAt: new Date().toISOString(),
        maxStaleness: 'PT5M',
        standards: [],
        sops: [],
        mandates: [{ action: 'flight-purchase', hash: null, ref: null, document: mandate(constraints) }],
        issuer: null,
        proof: { type: 'none', note: 'test' },
      },
    }),
  });
}

const run = async (constraints, opts = {}) => {
  stubFetch(constraints);
  const lines = [];
  const result = await verify({
    configPath: { apiBase: 'https://example.invalid/api/v1', agentDid: AGENT_DID, agentKey: AGENT_KEY, bundleUrl: 'https://example.invalid/bundle' },
    log: (l) => lines.push(l),
    ...opts,
  });
  return { ...result, output: lines.join('\n') };
};

const status = (r, control) => r.checks.find((c) => c.control === control)?.status;

console.log('\n  verify — a fully governed agent\n');
{
  const r = await run([CAP, TOTAL, MERCHANTS]);
  ok('passes overall', r.ok === true);
  ok('ordinary work still runs', status(r, 'baseline') === 'held');
  ok('refuses an ungranted action', status(r, 'scope') === 'held');
  ok('per-transaction cap holds', status(r, 'perTxn') === 'held');
  ok('cumulative cap holds', status(r, 'cumulative') === 'held');
  ok('merchant allow-list holds', status(r, 'merchants') === 'held',
    r.checks.find((c) => c.control === 'merchants')?.reasonCode ?? '');
}

console.log('\n  verify — the sandbox bug: an omitted merchant constraint\n');
{
  // The exact shape that shipped. `issueMandate` OMITS the constraint when the merchant
  // list is empty, so the mandate says nothing about merchants and every merchant is
  // permitted. It must be reported, and it must never read as a pass.
  const r = await run([CAP, TOTAL]);
  ok('reported NOT CONFIGURED, not passed', status(r, 'merchants') === 'not-configured');
  ok('says every merchant is permitted', /EVERY merchant is permitted/.test(r.output));
  ok('still exits 0 without --require', r.ok === true);
}

console.log('\n  verify — a PRESENT but empty allow-list is the opposite problem\n');
{
  // Worth its own case because the intuition runs backwards, and this suite is what
  // corrected it: `[].includes(x)` is always false, so an `isAnyOf` over an empty list
  // grants nothing at all. The agent can pay nobody. That is a BROKEN agent rather than an
  // ungoverned one, and verify has to tell the two apart — they need opposite fixes.
  const r = await run([CAP, TOTAL, { ...MERCHANTS, rightOperand: [] }]);
  ok('fails the build', r.ok === false);
  ok('flagged as failed, not as absent', status(r, 'merchants') === 'failed');
  ok('baseline catches that ordinary work is impossible', status(r, 'baseline') === 'failed');
  ok('says it permits no merchant at all', /permits no merchant at all/.test(r.output));
}

console.log('\n  verify — --require turns an absent control into a build failure\n');
{
  const r = await run([CAP, TOTAL], { require: ['merchants'] });
  ok('fails the build', r.ok === false);
  ok('names the missing control', r.requiredMissing.map((c) => c.control).includes('merchants'));
  ok('does not claim it failed to hold', status(r, 'merchants') === 'not-configured');
}

console.log('\n  verify — an agent that CAN exceed its mandate\n');
{
  // A mandate with no limits at all: scope still holds (nothing grants
  // `permissions.update`), but every spend control is absent rather than passing.
  const r = await run([]);
  ok('scope containment still holds', status(r, 'scope') === 'held');
  ok('per-transaction cap reported absent', status(r, 'perTxn') === 'not-configured');
  ok('cumulative cap reported absent', status(r, 'cumulative') === 'not-configured');
  ok('nothing is reported as held that is not configured',
    r.checks.filter((c) => c.status === 'held').every((c) => ['scope', 'baseline'].includes(c.control)));
  const req = await run([], { require: ['perTxn', 'cumulative', 'merchants'] });
  ok('--require fails it', req.ok === false, `${req.requiredMissing.length} missing`);
}

console.log('\n  verify — json output\n');
{
  const r = await run([CAP, TOTAL, MERCHANTS], { json: true });
  const parsed = JSON.parse(r.output);
  ok('emits parseable json', parsed.ok === true && Array.isArray(parsed.checks));
  ok('names the agent', parsed.agent === AGENT_DID);
}

console.log('');
if (failures) {
  console.error(`FAIL — ${failures} assertion(s) did not hold.`);
  process.exit(1);
}
console.log('PASS — verify reports absent controls as absent, and never as held.\n');

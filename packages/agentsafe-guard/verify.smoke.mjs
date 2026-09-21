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

console.log('\n  verify — a policy that REQUIRES request inputs (--context)\n');
{
  // A non-financial agent: no spend constraint at all, but a rule that fires when the required
  // evidence is ABSENT. A bare baseline request carries no evidence, so it is blocked and a
  // healthy agent reads as broken. --context supplies the inputs a compliant request carries.
  const evidenceSop = [{
    id: 'sop',
    document: { molecules: [{ id: 'kyc', name: 'KYC evidence required', combinator: 'all', atoms: [{ id: 'a', predicate: 'evidence-requirement', config: { required: ['kyc'] } }], decision: 'block', reasonCode: 'NO_KYC' }] },
  }];
  const withSops = async (constraints, opts = {}) => {
    stubFetch(constraints);
    const inner = globalThis.fetch;
    globalThis.fetch = async (...a) => {
      const res = await inner(...a);
      const body = await res.json();
      body.data.sops = evidenceSop;
      return { ...res, json: async () => body };
    };
    const lines = [];
    const result = await verify({ configPath: { apiBase: 'https://example.invalid/api/v1', agentDid: AGENT_DID, agentKey: AGENT_KEY, bundleUrl: 'https://example.invalid/bundle' }, log: (l) => lines.push(l), ...opts });
    return { ...result, output: lines.join('\n') };
  };
  const without = await withSops([]);
  ok('without --context the baseline is blocked by the evidence rule', status(without, 'baseline') === 'failed');
  ok('...and says the agent cannot do its job', /cannot perform the action it was issued for/.test(without.output));
  const withCtx = await withSops([], { context: { evidenceTypes: ['kyc'] } });
  ok('with --context the baseline passes', status(withCtx, 'baseline') === 'held');
  ok('the overall result is ok (no spend cap is only "not configured")', withCtx.ok === true);
  ok('scope is still refused whatever the context says', status(withCtx, 'scope') === 'held');
  // A cap must hold for the RIGHT reason: with the inputs supplied, the refusal is the cap's.
  const capped = await withSops([CAP], { context: { evidenceTypes: ['kyc'] } });
  ok('a cap holds when the request is otherwise compliant', status(capped, 'perTxn') === 'held' && capped.checks.find((c) => c.control === 'perTxn').reasonCode !== 'NO_KYC');
}

console.log('\n  verify — a risk rule at the "low" threshold vs the hard-coded baseline riskLevel\n');
{
  // verify's baseline sends riskLevel "low". A rule whose threshold IS "low" ("escalate on ANY risk") fires on
  // that, so a healthy agent reads as failing — which is the truth: that rule sends every action to a human.
  // There used to be a way out: --context riskLevel=null meant "no risk level", which never fired a risk rule.
  // That was D-03 by another name (hiding the field skipped the rule), so it is gone: a missing or null risk is
  // now UNVERIFIABLE and escalates too (spec §6.4.3).
  const lowRisk = [{ id: 'sop', document: { molecules: [{ id: 'r', name: 'Any risk', combinator: 'all', atoms: [{ id: 'a', predicate: 'risk-at-or-above', config: { level: 'low' } }], decision: 'escalate', reasonCode: 'ANY_RISK' }] } }];
  const withRiskSops = async (opts = {}) => {
    stubFetch([]);
    const inner = globalThis.fetch;
    globalThis.fetch = async (...a) => {
      const res = await inner(...a);
      const body = await res.json();
      body.data.sops = lowRisk;
      return { ...res, json: async () => body };
    };
    return verify({ configPath: { apiBase: 'https://example.invalid/api/v1', agentDid: AGENT_DID, agentKey: AGENT_KEY, bundleUrl: 'https://example.invalid/bundle' }, log: () => {}, ...opts });
  };
  ok('bare baseline is escalated by the low-threshold rule', status(await withRiskSops(), 'baseline') === 'failed');
  const hidden = await withRiskSops({ context: { riskLevel: null } });
  ok('hiding the risk (context { riskLevel: null }) no longer clears it — it escalates as unverifiable', status(hidden, 'baseline') === 'failed');
  ok('...and a risk that is actually above the rule\'s threshold still fires with the rule\'s own reason', /ANY_RISK/.test(JSON.stringify((await withRiskSops()).checks)));
}

console.log('\n  verify — the CLI refuses a --context with no value\n');
{
  const { spawnSync } = await import('node:child_process');
  const cli = new URL('./cli.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const r = spawnSync(process.execPath, [cli, 'verify', '--context'], { encoding: 'utf8' });
  ok('exits 2 (could not run), not a silent bare run', r.status === 2, `status ${r.status}`);
  ok('says it needs a file path', /--context needs a file path/.test(r.stderr));
}

console.log('\n  verify — an agent whose caps are NOT in USD\n');
{
  // Found running a delegated GBP request end to end: the probes assumed USD, so a healthy GBP agent failed its own
  // baseline ("cannot perform the action it was issued for") and every non-USD team saw a red build for nothing.
  // The mandate's caps AND the SOP's currency-scoped cap are both GBP, as the hosted provisioning writes them.
  const GBP_CAP = { ...CAP, unit: 'GBP' };
  const GBP_TOTAL = { ...TOTAL, unit: 'GBP' };
  const gbpSop = [{
    id: 'sop',
    document: { molecules: [{ id: 'cap', name: 'Per-transaction cap', combinator: 'any', atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 500, currency: ['GBP'] } }], decision: 'block', reasonCode: 'SOP_SPEND_CAP' }] },
  }];
  const runGbp = async (constraints) => {
    stubFetch(constraints);
    const inner = globalThis.fetch;
    globalThis.fetch = async (...a) => {
      const res = await inner(...a);
      const body = await res.json();
      body.data.sops = gbpSop;
      return { ok: true, status: 200, json: async () => body };
    };
    return run(constraints);
  };
  const r = await runGbp([GBP_CAP, GBP_TOTAL, MERCHANTS]);
  ok('a healthy GBP agent passes overall', r.ok === true, r.checks.filter((c) => c.status === 'failed').map((c) => c.control + ':' + c.reasonCode).join(','));
  ok('ordinary work still runs', status(r, 'baseline') === 'held');
  ok('per-transaction cap still refuses over the cap', status(r, 'perTxn') === 'held');
  ok('cumulative cap still refuses', status(r, 'cumulative') === 'held');
  ok('merchant allow-list still refuses', status(r, 'merchants') === 'held');
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

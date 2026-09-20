// hosted-nonfinancial.smoke.mjs — the HOSTED non-financial scaffold, run for real (BR-006).
//
// The hosted flow needs a live login, so this stands in for the platform with the smallest thing
// the generated project actually talks to: an issuer that serves the agent's policy bundle. It then
// scaffolds the project exactly as `main()` does after provisioning, links the real
// agentsafe-guard / agentsafe-mcp-guard / agentsafe-http-gateway from source, starts the generated
// gateway process, and runs the generated agent against it.
//
// What this proves: the generated files are valid, nothing in them is financial, every derived step
// behaves as labelled through the REAL guard (and, in the two-process shape, through the real
// gateway), `npm test`'s `verify --context` passes, and the provisioning body omits spend fields.
// What it does NOT prove: the live platform's own enforced Standards (they are not modelled here) —
// the generated demo prints "NOT AS EXPECTED" itself if a live gate ever disagrees.
//
//   node hosted-nonfinancial.smoke.mjs   → PASS when every case matches.
process.env.CREATE_METAMYND_AGENT_NO_MAIN = '1';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, existsSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGuardFromConfig } from '../agentsafe-guard/agentsafe-guard.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const INTEGRATIONS = resolve(HERE, '..');
const {
  scaffoldProject, buildPolicyCases, ruleToMolecule, generateAgentKeypair, harnessAgentDid,
  harnessMandate, harnessDefaultSopNeutral,
} = await import('./index.mjs');

let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log(`ok    ${name}`); }
  catch (e) { failed++; console.log(`FAIL  ${name}\n      ${e.message}`); }
}
const strip = (t) => t.replace(/\x1b\[[0-9;]*m/g, '');
const FINANCIAL_LEAK = /flight|bookflight|book-flight|pnr|\busd\b|per-transaction|spend cap|payAmount|cumulativeSpend|amount-unknown|AIRLINE/i;

const SCOPE = 'send-customer-notice';
const rule = (name, predicate, config, then, reasonCode) => ({ name, when: { predicate, config }, then, reasonCode });
const RULES = [
  rule('Personal data needs review', 'pii-present', {}, 'escalate', 'PII_REVIEW'),
  rule('Consent required', 'consent-missing', {}, 'block', 'NO_CONSENT'),
  rule('No investment promises', 'text-matches', { terms: ['guaranteed returns'] }, 'block', 'PROHIBITED_CLAIM'),
  // An input-REQUIRING rule: a request without the evidence is blocked, so the passing request (and
  // `npm test`'s baseline) must carry it — exactly what verify-context.json exists for.
  rule('KYC evidence required', 'evidence-requirement', { required: ['kyc'] }, 'block', 'NO_KYC'),
];

// ---- a stand-in issuer: serves the policy bundle, swallows decision reports ----
const { publicKeyHex, privateKeyHex } = generateAgentKeypair();
const AGENT_DID = harnessAgentDid(publicKeyHex);
const molecules = RULES.map(ruleToMolecule);
const bundle = {
  subject: AGENT_DID,
  issuedAt: new Date().toISOString(),
  maxStaleness: 'PT5M',
  standards: [],
  sops: [{ id: 'sop', document: { molecules } }],
  mandates: [{ action: SCOPE, hash: null, ref: null, document: harnessMandate({ scope: SCOPE, financial: false, merchants: [] }) }],
  issuer: null,
  proof: { type: 'none', note: 'stand-in issuer' },
};
const provisionBodies = []; // what the hosted CLI actually POSTed to /onboarding/agent
let ISSUER = '';
const issuer = http.createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  if (req.method === 'GET' && req.url.startsWith('/api/v1/policy/bundle/')) return res.end(JSON.stringify({ data: bundle }));
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let body = {};
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { /* not JSON */ }
    // The two endpoints the hosted CLI calls before scaffolding (login, then one-call provisioning).
    if (req.method === 'POST' && req.url === '/api/v1/auth/login') return res.end(JSON.stringify({ success: true, data: { accessToken: 'stand-in-token' } }));
    if (req.method === 'POST' && req.url === '/api/v1/onboarding/agent') {
      provisionBodies.push(body);
      return res.end(JSON.stringify({ success: true, data: { apiBase: ISSUER, agentDid: AGENT_DID, agentKey: privateKeyHex, identityId: 'stand-in', keyVerified: true, mandate: { scope: body.scope }, standards: [], bundleUrl: `${ISSUER}/policy/bundle/${AGENT_DID}` } }));
    }
    res.end('{}'); // decision reports and anything else the guard fires and forgets
  });
});
await new Promise((r) => issuer.listen(0, '127.0.0.1', r));
ISSUER = `http://127.0.0.1:${issuer.address().port}/api/v1`;

const workdir = mkdtempSync(join(tmpdir(), 'metamynd-hosted-nf-'));
const config = { apiBase: ISSUER, agentDid: AGENT_DID, agentKey: privateKeyHex, identityId: 'stand-in', keyVerified: true, mandate: { scope: SCOPE } };

/** node_modules/<pkg> -> the real package source, so generated code resolves it as a user's would. */
function link(dir, pkg, target) {
  const nm = join(dir, 'node_modules', '@metamynd');
  mkdirSync(nm, { recursive: true });
  if (!existsSync(join(nm, pkg))) symlinkSync(target, join(nm, pkg), 'junction');
}

function scaffold(name, opts) {
  const outDir = join(workdir, name);
  const demo = buildPolicyCases(molecules);
  const realLog = console.log;
  console.log = () => {}; // scaffoldProject narrates; keep the test output readable
  try { scaffoldProject({ outDir, config, slug: name, scope: SCOPE, demo, sandbox: false, ...opts }); }
  finally { console.log = realLog; }
  link(outDir, 'agentsafe-guard', join(INTEGRATIONS, 'agentsafe-guard'));
  if (opts.withGateway) {
    link(join(outDir, 'gateway'), 'agentsafe-mcp-guard', join(INTEGRATIONS, 'agentsafe-mcp-guard'));
    link(join(outDir, 'gateway'), 'agentsafe-http-gateway', join(INTEGRATIONS, 'agentsafe-http-gateway'));
  }
  return { outDir, demo, read: (f) => readFileSync(join(outDir, f), 'utf8') };
}

/** Run node as a child WITHOUT blocking the event loop: the stand-in issuer is served from this process. */
function runNode(args, { cwd, env = {}, timeout = 60000 } = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, args, { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const timer = setTimeout(() => { child.kill(); stderr += '\n[test] timed out'; }, timeout);
    child.on('close', (status) => { clearTimeout(timer); resolvePromise({ status, stdout: strip(stdout), stderr: strip(stderr) }); });
  });
}
const runAgent = async (outDir, env = {}) => {
  const r = await runNode(['index.mjs'], { cwd: outDir, env });
  assert.equal(r.status, 0, 'agent exited ' + r.status + ':\n' + r.stdout + r.stderr);
  return r.stdout;
};

function stepResults(out) {
  const blocks = out.split(/\n\s*Step \d+ of \d+ - /).slice(1);
  return blocks.map((b) => ({
    intent: b.split('\n')[0],
    outcome: /ALLOWED/.test(b) ? 'allow' : /ESCALATED/.test(b) ? 'escalate' : /BLOCKED/.test(b) ? 'block' : '?',
    asExpected: /as expected\./.test(b) && !/NOT AS EXPECTED/.test(b),
  }));
}

try {
  await check('single process (--no-gateway): valid, non-financial, and every step behaves as labelled through the real guard', async () => {
    const p = scaffold('single', { withGateway: false });
    execFileSync(process.execPath, ['--check', join(p.outDir, 'index.mjs')], { stdio: 'pipe' });
    for (const f of ['index.mjs', 'package.json']) assert.doesNotMatch(p.read(f), FINANCIAL_LEAK, `${f} mentions something financial`);
    // The README says the agent has NO spend cap — that is the point — so it gets the narrower check.
    assert.doesNotMatch(p.read('README.md'), /flight|bookflight|pnr|\busd\b|per-transaction|payAmount|cumulativeSpend/i, 'README describes a payment demo');
    assert.ok(!existsSync(join(p.outDir, 'gateway')), 'no gateway directory');
    const out = await runAgent(p.outDir);
    const steps = stepResults(out);
    assert.equal(steps.length, p.demo.cases.length + 1, 'one step per case plus the ungranted action');
    assert.deepEqual(steps.map((s) => s.outcome), ['allow', 'escalate', 'block', 'block', 'block', 'block']);
    assert.ok(steps.every((s) => s.asExpected), 'every step matched its own expectation:\n' + out);
    assert.doesNotMatch(out, /NOT AS EXPECTED/);
  });

  await check('two processes: the generated gateway independently verifies the allowed step; every step still matches', async () => {
    const p = scaffold('gateway', { withGateway: true, gatewayPort: 0 });
    // a free port for the gateway, chosen now so the agent can be told where it is
    const probe = http.createServer();
    await new Promise((r) => probe.listen(0, '127.0.0.1', r));
    const port = probe.address().port;
    await new Promise((r) => probe.close(r));
    for (const f of ['server.mjs', 'README.md', '.env.example']) {
      assert.doesNotMatch(readFileSync(join(p.outDir, 'gateway', f), 'utf8'), FINANCIAL_LEAK, `gateway/${f} mentions something financial`);
    }
    const gw = spawn(process.execPath, ['server.mjs'], { cwd: join(p.outDir, 'gateway'), env: { ...process.env, PORT: String(port), MAGP_API: ISSUER }, stdio: ['ignore', 'pipe', 'pipe'] });
    let gwLog = '';
    gw.stdout.on('data', (d) => { gwLog += d; });
    gw.stderr.on('data', (d) => { gwLog += d; });
    try {
      const deadline = Date.now() + 15000;
      while (!/listening on/.test(gwLog) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
      assert.match(gwLog, /listening on/, 'gateway did not start:\n' + gwLog);
      const out = await runAgent(p.outDir, { GATEWAY_URL: `http://127.0.0.1:${port}` });
      const steps = stepResults(out);
      assert.deepEqual(steps.map((s) => s.outcome), ['allow', 'escalate', 'block', 'block', 'block', 'block']);
      assert.ok(steps.every((s) => s.asExpected), 'every step matched its own expectation:\n' + out);
      assert.match(out, /your tool ran \(in \.\/gateway\)/, 'the allowed step ran in the gateway process');
    } finally {
      gw.kill(); // this child's own PID only
    }
  });

  await check('a request that skips the agent and hits the gateway with no signature is refused', async () => {
    const p = scaffold('gateway-direct', { withGateway: true, gatewayPort: 0 });
    const probe = http.createServer();
    await new Promise((r) => probe.listen(0, '127.0.0.1', r));
    const port = probe.address().port;
    await new Promise((r) => probe.close(r));
    const gw = spawn(process.execPath, ['server.mjs'], { cwd: join(p.outDir, 'gateway'), env: { ...process.env, PORT: String(port), MAGP_API: ISSUER }, stdio: ['ignore', 'pipe', 'pipe'] });
    let gwLog = '';
    gw.stdout.on('data', (d) => { gwLog += d; });
    try {
      const deadline = Date.now() + 15000;
      while (!/listening on/.test(gwLog) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
      const res = await fetch(`http://127.0.0.1:${port}/perform`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"consent":true}' });
      assert.notEqual(res.status, 200, 'an unsigned call must not run the tool');
      const other = await fetch(`http://127.0.0.1:${port}/not-a-route`, { method: 'POST', body: '{}' });
      assert.notEqual(other.status, 200, 'an unmatched path must not fall through to the tool');

      // What the README says the gateway does and does NOT close, demonstrated against the real thing
      // so the documentation cannot drift from behaviour. A properly SIGNED request:
      const guard = await createGuardFromConfig(join(p.outDir, 'agent.metamynd.json'));
      const send = async (context, action = SCOPE) => {
        const signed = await guard.buildSignedRequest({ action, context });
        return fetch(`http://127.0.0.1:${port}/perform`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-magp-request': JSON.stringify(signed) }, body: JSON.stringify(context) });
      };
      const compliant = { consent: true, piiPresent: false, prompt: 'hello', evidenceTypes: ['kyc'] };
      assert.equal((await send(compliant)).status, 200, 'a signed, compliant request runs the tool');
      assert.equal((await send({ ...compliant, consent: false })).status, 403, 'a signed request that DECLARES no consent is refused');
      // ...but the inputs are unsigned, so a signing agent can simply not send the field (README: "Rule
      // inputs are not signed"). If this ever starts failing, the gateway began enforcing something the
      // README does not yet say — update the README, do not delete the test.
      const { consent, ...omitted } = compliant;
      assert.equal((await send(omitted)).status, 200, 'omitting the consent field is NOT caught — documented limit');
      assert.notEqual((await send(compliant, 'permissions.update')).status, 200, 'an action outside the mandate is refused whatever the context says');
    } finally {
      gw.kill();
    }
  });

  await check('npm test (verify --context) passes, reports the missing spend cap as "not configured", and needs the context', async () => {
    const p = scaffold('verify', { withGateway: false });
    assert.equal(JSON.parse(p.read('package.json')).scripts.test, 'agentsafe-guard verify --context ./verify-context.json');
    const ctx = JSON.parse(p.read('verify-context.json'));
    assert.deepEqual(ctx.evidenceTypes, ['kyc'], 'the compliant request carries the required evidence');
    const cli = join(INTEGRATIONS, 'agentsafe-guard', 'cli.mjs');
    const ok = await runNode([cli, 'verify', '--context', './verify-context.json'], { cwd: p.outDir });
    assert.equal(ok.status, 0, 'verify exited ' + ok.status + ':\n' + ok.stdout + ok.stderr);
    const withCtx = ok.stdout;
    assert.match(withCtx, /permits ordinary in-scope work/);
    assert.match(withCtx, /no per-transaction cap in this mandate/, 'an absent cap is reported, not passed');
    assert.match(withCtx, /Every configured control held/);
    const bare = await runNode([cli, 'verify'], { cwd: p.outDir });
    assert.equal(bare.status, 1, 'without the context the evidence rule blocks the baseline, so verify fails');
    assert.match(bare.stdout, /cannot perform the action it was issued for/);
  });

  await check('the neutral README/gateway README say what the gateway does NOT close, and list the rule inputs', () => {
    const p = scaffold('docs', { withGateway: true, gatewayPort: 0 });
    const gwReadme = readFileSync(join(p.outDir, 'gateway', 'README.md'), 'utf8');
    assert.match(gwReadme, /Rule inputs are not signed/, 'says the rule inputs are outside the signature');
    assert.match(gwReadme, /omit a field or send a different one/, 'says a signing agent can omit or forge an input');
    assert.match(gwReadme, /Replay/);
    assert.match(gwReadme, /5 minutes/, 'bounds replay by the freshness window');
    assert.match(gwReadme, /requireAuthorization: false/);
    assert.doesNotMatch(gwReadme, /skipping its own guard, or calling the tool\s+directly\. There is nothing to call/, 'the old over-claim is gone');
    assert.match(p.read('README.md'), /not covered by its\s+signature/, 'the top-level README says inputs are unsigned too');
    assert.match(readFileSync(join(p.outDir, 'gateway', 'server.mjs'), 'utf8'), /requireAuthorization: false/);
    assert.match(readFileSync(join(p.outDir, 'gateway', 'server.mjs'), 'utf8'), /valueFields: \[\]/);
    const readme = p.read('README.md');
    for (const field of ['piiPresent', 'consent', 'evidenceTypes', 'prompt / output']) assert.ok(readme.includes(field), `README lists ${field}`);
    assert.match(readme, /Cloned this project fresh\?/);
  });

  await check('the default (no rules supplied) non-financial project demos the amount-free review rule', () => {
    const demo = buildPolicyCases(harnessDefaultSopNeutral().molecules);
    assert.equal(demo.cases.length, 2);
    assert.equal(demo.cases[1].reasonCode, 'RISK_REVIEW');
  });

  await check('verify-context.json clears riskLevel when a risk rule sits at the "low" threshold (verify hard-codes "low")', async () => {
    const lowRisk = [ruleToMolecule(rule('Any risk', 'risk-at-or-above', { level: 'low' }, 'escalate', 'ANY_RISK'))];
    const outDir = join(workdir, 'low-risk');
    const realLog = console.log;
    console.log = () => {};
    try { scaffoldProject({ outDir, config, slug: 'low-risk', scope: SCOPE, demo: buildPolicyCases(lowRisk), sandbox: false, withGateway: false }); }
    finally { console.log = realLog; }
    assert.equal(JSON.parse(readFileSync(join(outDir, 'verify-context.json'), 'utf8')).riskLevel, null);
    // ...and it is NOT added when the rules never read riskLevel
    const outDir2 = join(workdir, 'no-risk');
    console.log = () => {};
    try { scaffoldProject({ outDir: outDir2, config, slug: 'no-risk', scope: SCOPE, demo: buildPolicyCases([ruleToMolecule(rule('PII', 'pii-present', {}, 'escalate', 'PII'))]), sandbox: false, withGateway: false }); }
    finally { console.log = realLog; }
    assert.ok(!('riskLevel' in JSON.parse(readFileSync(join(outDir2, 'verify-context.json'), 'utf8'))));
  });

  await check('the financial hosted scaffold keeps its payment shape when no demo is given', () => {
    const outDir = join(workdir, 'financial');
    const realLog = console.log;
    console.log = () => {};
    try { scaffoldProject({ outDir, config, slug: 'financial', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false, withGateway: true, gatewayPort: 4401 }); }
    finally { console.log = realLog; }
    const index = readFileSync(join(outDir, 'index.mjs'), 'utf8');
    assert.match(index, /bookFlightViaGateway/);
    assert.match(index, /USD 500/);
    assert.equal(JSON.parse(readFileSync(join(outDir, 'package.json'), 'utf8')).scripts.test, 'agentsafe-guard verify');
    assert.ok(!existsSync(join(outDir, 'verify-context.json')));
    assert.match(readFileSync(join(outDir, 'gateway', 'server.mjs'), 'utf8'), /requireAuthorization: true/);
  });
  // ---- The REAL hosted CLI (main()), against the stand-in login + provisioning endpoints. ----
  const cli = (extra) => runNode(
    [join(HERE, 'index.mjs'), '--yes', '--api', ISSUER, '--email', 'owner@example.test', '--password', 'pw', ...extra],
    { cwd: workdir, env: { CREATE_METAMYND_AGENT_NO_MAIN: '' } }, // '' = falsy: let the child run main()
  );
  const policyFile = join(workdir, 'comms.policy.json');
  writeFileSync(policyFile, JSON.stringify({ name: 'Support Comms Agent', scope: SCOPE, rules: RULES }));

  await check('hosted CLI: a policy file with no money provisions WITHOUT spend fields and scaffolds the neutral project', async () => {
    provisionBodies.length = 0;
    const out = join(workdir, 'cli-neutral');
    const r = await cli(['--config', policyFile, '--out', out]);
    assert.equal(r.status, 0, 'exited ' + r.status + ':\n' + r.stdout + r.stderr);
    assert.match(r.stdout, /non-financial agent/);
    assert.equal(provisionBodies.length, 1);
    const body = provisionBodies[0];
    for (const k of ['currency', 'maxAmount', 'perTxnMax']) assert.ok(!(k in body), `the provisioning body must not carry ${k}: ${JSON.stringify(body)}`);
    assert.equal(body.scope, SCOPE, 'the supplied scope, not flight-purchase');
    assert.deepEqual(body.merchants, []);
    assert.deepEqual(body.sop.documentJson.molecules.map((m) => m.reasonCode), ['PII_REVIEW', 'NO_CONSENT', 'PROHIBITED_CLAIM', 'NO_KYC'], 'exactly the supplied rules');
    assert.doesNotMatch(r.stdout, /no spend limits supplied/);
    const index = readFileSync(join(out, 'index.mjs'), 'utf8');
    assert.doesNotMatch(index, FINANCIAL_LEAK);
    assert.ok(existsSync(join(out, 'gateway', 'server.mjs')), 'the default two-process shape');
    assert.deepEqual(JSON.parse(readFileSync(join(out, 'verify-context.json'), 'utf8')).evidenceTypes, ['kyc']);
  });

  await check('hosted CLI: flags only keeps the payment provisioning body, and says which defaults it used', async () => {
    provisionBodies.length = 0;
    const r = await cli(['--scope', 'flight-purchase', '--out', join(workdir, 'cli-financial'), '--no-gateway']);
    assert.equal(r.status, 0, 'exited ' + r.status + ':\n' + r.stdout + r.stderr);
    assert.deepEqual([provisionBodies[0].currency, provisionBodies[0].maxAmount, provisionBodies[0].perTxnMax], ['USD', 10000, 500]);
    assert.match(r.stdout, /no spend limits supplied — using the defaults USD 500/);
    assert.match(readFileSync(join(workdir, 'cli-financial', 'index.mjs'), 'utf8'), /bookFlight/);
  });

  await check('hosted CLI: explicit spend flags are sent and no defaults notice is printed', async () => {
    provisionBodies.length = 0;
    const r = await cli(['--scope', 'pay-invoice', '--per-txn-max', '250', '--max-amount', '900', '--currency', 'GBP', '--out', join(workdir, 'cli-explicit'), '--no-gateway']);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual([provisionBodies[0].currency, provisionBodies[0].maxAmount, provisionBodies[0].perTxnMax], ['GBP', 900, 250]);
    assert.doesNotMatch(r.stdout, /no spend limits supplied/);
  });

  await check('hosted CLI: --non-financial with a rulePack-only file drops the pack and says so (accurately)', async () => {
    provisionBodies.length = 0;
    const packFile = join(workdir, 'pack.json');
    writeFileSync(packFile, JSON.stringify({ name: 'Pack Agent', scope: SCOPE, rulePack: 'payments-baseline' }));
    const r = await cli(['--non-financial', '--config', packFile, '--out', join(workdir, 'cli-pack'), '--no-gateway']);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /rule pack "payments-baseline" cannot be applied to a non-financial hosted agent/);
    assert.ok(!('rulePack' in provisionBodies[0]) && !('perTxnMax' in provisionBodies[0]));
    assert.match(r.stdout, /derived 2 demo case\(s\)/, 'the default amount-free review is what gets demonstrated');
  });

  await check('hosted CLI: a rulePack-only file WITHOUT --non-financial is never assumed money-free', async () => {
    provisionBodies.length = 0;
    const r = await cli(['--config', join(workdir, 'pack.json'), '--out', join(workdir, 'cli-pack-fin'), '--no-gateway']);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(provisionBodies[0].rulePack, 'payments-baseline');
    assert.equal(provisionBodies[0].perTxnMax, 500);
  });

  // --sandbox / --request / --claim honour --non-financial too: see modes-nonfinancial.smoke.mjs.
} finally {
  issuer.close();
  rmSync(workdir, { recursive: true, force: true });
}

if (failed) { console.error(`\n${failed} case(s) FAILED`); process.exit(1); }
console.log('\nPASS — the hosted non-financial scaffold runs, and behaves as labelled, through the real guard and gateway.');

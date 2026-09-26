// policy-demo.smoke.mjs — proves the NON-financial scaffold's demo is derived from the caller's own
// policy and that every case it generates behaves as labelled against the REAL evaluator
// (BR-006, beta regression 2026-09-20: a customer-communications policy used to produce a flight
// demo with spend limits nobody asked for and no case for its own privacy/content rules).
//
// No network, no npm install: it drives the real agentsafe-guard's guardToolLocal from source.
//
//   node policy-demo.smoke.mjs   → PASS when every case matches.
process.env.CREATE_METAMYND_AGENT_NO_MAIN = '1';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createGuard } from '../agentsafe-guard/agentsafe-guard.mjs';
// Dynamic, not static: ES imports are hoisted above the env assignment, which would start the CLI.
const {
  buildPolicyCases, resolveFinancial, generateAgentKeypair, harnessAgentDid,
  harnessMandate, harnessRulesFile, harnessDefaultSopNeutral, ruleToMolecule,
} = await import('./index.mjs');

let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log(`ok    ${name}`); }
  catch (e) { failed++; console.log(`FAIL  ${name}\n      ${e.message}`); }
}

const SCOPE = 'send-notice';
const { publicKeyHex, privateKeyHex } = generateAgentKeypair();
const guard = createGuard({ api: 'local', agentDid: harnessAgentDid(publicKeyHex), agentKey: privateKeyHex });

/** Run every generated case through guardToolLocal exactly as the generated index.mjs does. */
async function runCases(sopDocument, cases) {
  const mandate = harnessMandate({ scope: SCOPE, financial: false, merchants: [] });
  const rules = JSON.parse(harnessRulesFile(mandate, sopDocument));
  let ran = 0;
  // The generated index.mjs's mapping: `jurisdiction` is the SIGNED top-level field (MAGP 8.3.12), everything else is context.
  const tool = guard.guardToolLocal(SCOPE, async () => { ran++; return { ok: true }; }, ({ jurisdiction, ...context }) => ({ jurisdiction, context }), () => rules);
  const out = [];
  for (const c of cases) {
    const before = ran;
    let got, reasonCode;
    try { await tool(c.context); got = 'allow'; }
    catch (e) { got = e.governance?.decision; reasonCode = e.governance?.reasonCode; }
    out.push({ c, got, reasonCode, toolRan: ran > before });
  }
  return out;
}

const rule = (name, predicate, config, then, reasonCode) => ({ name, when: { predicate, config }, then, reasonCode });

const POLICIES = {
  'customer communications (PII, consent, content, risk)': [
    rule('Personal data needs review', 'pii-present', {}, 'escalate', 'PII_REVIEW'),
    rule('Consent required', 'consent-missing', {}, 'block', 'NO_CONSENT'),
    rule('No investment promises', 'text-matches', { terms: ['guaranteed returns', 'free money'] }, 'block', 'PROHIBITED_CLAIM'),
    rule('High risk goes to a human', 'risk-at-or-above', { level: 'high' }, 'escalate', 'RISK_REVIEW'),
  ],
  'healthcare referral (jurisdiction, residency, model, evidence)': [
    rule('UK/IE only', 'jurisdiction-not-allowed', { allowed: ['GB', 'IE'] }, 'block', 'BAD_JURISDICTION'),
    rule('Data stays in region', 'data-residency-violation', { allowedRegions: ['uk-south'] }, 'block', 'BAD_RESIDENCY'),
    rule('Approved model only', 'model-not-allowed', { allowed: ['approved-model-1'] }, 'block', 'BAD_MODEL'),
    rule('Referral letter required', 'evidence-requirement', { required: ['referral-letter'] }, 'escalate', 'NO_EVIDENCE'),
  ],
  'tooling and quotas (tool, rate, source, confidence)': [
    rule('Allowed tools', 'tool-not-allowed', { allowed: ['send-notice'] }, 'block', 'BAD_TOOL'),
    rule('Rate limit', 'rate-limit-exceeded', { max: 3 }, 'block', 'RATE'),
    rule('Approved sources', 'data-source-not-approved', { approved: ['crm'] }, 'block', 'BAD_SOURCE'),
    rule('Evidence confidence', 'evidence-confidence-below', { min: 0.8 }, 'escalate', 'LOW_CONFIDENCE'),
  ],
};

for (const [label, rules] of Object.entries(POLICIES)) {
  const molecules = rules.map(ruleToMolecule);
  const { cases, notDemonstrated } = buildPolicyCases(molecules);

  await check(`${label}: one passing case plus one per rule`, async () => {
    assert.equal(cases[0].expect, 'allow');
    assert.equal(cases.length, 1 + rules.length, `expected ${1 + rules.length} cases, got ${cases.length}`);
    assert.deepEqual(notDemonstrated, []);
  });

  await check(`${label}: every case behaves as labelled against the real evaluator`, async () => {
    const results = await runCases({ molecules }, cases);
    for (const { c, got, reasonCode, toolRan } of results) {
      assert.equal(got, c.expect, `"${c.rule ?? 'passing case'}": expected ${c.expect}, evaluator said ${got} (${reasonCode})`);
      if (c.reasonCode) assert.equal(reasonCode, c.reasonCode, `"${c.rule}": wrong reason code`);
      assert.equal(toolRan, c.expect === 'allow', `"${c.rule ?? 'passing case'}": tool ${toolRan ? 'ran' : 'did not run'} but decision was ${got}`);
    }
  });
}

/** Every generated case must agree with the real evaluator; returns the cases for further checks. */
async function assertAllCasesHold(molecules) {
  const { cases, notDemonstrated } = buildPolicyCases(molecules);
  for (const { c, got, reasonCode, toolRan } of await runCases({ molecules }, cases)) {
    assert.equal(got, c.expect, `"${c.rule ?? 'passing case'}": expected ${c.expect}, evaluator said ${got} (${reasonCode})`);
    if (c.reasonCode) assert.equal(reasonCode, c.reasonCode, `"${c.rule}": wrong reason code`);
    assert.equal(toolRan, c.expect === 'allow', `"${c.rule ?? 'passing case'}": tool ${toolRan ? 'ran' : 'did not run'} but decision was ${got}`);
  }
  return { cases, notDemonstrated };
}
const mol = (id, name, combinator, atoms, decision, reasonCode) => ({ id, name, combinator, atoms: atoms.map((a, i) => ({ id: 'a' + i, ...a })), decision, reasonCode });

await check('a multi-atom "all" molecule is tripped only when EVERY atom fires; an "any" molecule on one', async () => {
  const { cases, notDemonstrated } = await assertAllCasesHold([
    mol('m1', 'Consent and PII together', 'all', [{ predicate: 'consent-missing' }, { predicate: 'pii-present' }], 'block', 'BOTH'),
    mol('m2', 'Either jurisdiction or rate', 'any', [{ predicate: 'jurisdiction-not-allowed', config: { allowed: ['GB'] } }, { predicate: 'rate-limit-exceeded', config: { max: 2 } }], 'escalate', 'EITHER'),
  ]);
  assert.equal(cases.length, 3);
  assert.deepEqual(notDemonstrated, []);
});

// ---- Review findings (BR-006 code review): each of these produced a demo that contradicted the
// ---- evaluator. The generator must now either stage them truthfully or say it cannot.

await check('tiered rules on ONE atom (0.9 escalate + 0.5 block): the passing request passes, the tiers are reported not mislabelled', async () => {
  const { cases, notDemonstrated } = await assertAllCasesHold([
    mol('r1', 'Strong evidence', 'all', [{ predicate: 'evidence-confidence-below', config: { min: 0.9 } }], 'escalate', 'STRONG'),
    mol('r2', 'Any evidence', 'all', [{ predicate: 'evidence-confidence-below', config: { min: 0.5 } }], 'block', 'ANY'),
  ]);
  assert.equal(cases.length, 1, 'only the passing case; the tiers cannot be staged independently');
  assert.equal(cases[0].context.evidenceConfidence, 0.9, 'the passing request clears the HIGHEST bar');
  assert.deepEqual(notDemonstrated.map((n) => n.rule).sort(), ['Any evidence', 'Strong evidence']);
  assert.match(notDemonstrated[0].why, /same input/);
});

await check('two evidence-requirement rules: the passing request carries the UNION of what they require', async () => {
  const { cases } = await assertAllCasesHold([
    mol('r1', 'KYC', 'all', [{ predicate: 'evidence-requirement', config: { required: ['kyc'] } }], 'block', 'KYC'),
    mol('r2', 'Audit', 'all', [{ predicate: 'evidence-requirement', config: { required: ['audit'] } }], 'escalate', 'AUD'),
  ]);
  assert.deepEqual([...cases[0].context.evidenceTypes].sort(), ['audit', 'kyc']);
});

await check('two allow-lists on one field: the passing request uses a value on BOTH; for the SIGNED jurisdiction, none on both stages nothing', async () => {
  const both = await assertAllCasesHold([
    mol('a', 'SG only', 'all', [{ predicate: 'jurisdiction-not-allowed', config: { allowed: ['SG'] } }], 'escalate', 'A'),
    mol('b', 'US or SG', 'all', [{ predicate: 'jurisdiction-not-allowed', config: { allowed: ['US', 'SG'] } }], 'block', 'B'),
  ]);
  assert.equal(both.cases[0].context.jurisdiction, 'SG', 'the value on both lists');
  const disjoint = await assertAllCasesHold([
    mol('a', 'GB only', 'all', [{ predicate: 'jurisdiction-not-allowed', config: { allowed: ['GB'] } }], 'escalate', 'A'),
    mol('b', 'US only', 'all', [{ predicate: 'jurisdiction-not-allowed', config: { allowed: ['US'] } }], 'block', 'B'),
  ]);
  // A jurisdiction rule makes the field required (JURISDICTION_REQUIRED when none is signed), so with no code on both
  // lists no request can pass: nothing is staged, and each rule says why.
  assert.equal(disjoint.cases.length, 0, 'no passing request exists');
  assert.equal(disjoint.notDemonstrated.length, 2);
  assert.match(disjoint.notDemonstrated[0].why, /JURISDICTION_REQUIRED/);
  // Another allow-list field keeps the old behaviour: absent never trips it.
  const models = await assertAllCasesHold([
    mol('a', 'M1 only', 'all', [{ predicate: 'model-not-allowed', config: { allowed: ['m1'] } }], 'escalate', 'A'),
    mol('b', 'M2 only', 'all', [{ predicate: 'model-not-allowed', config: { allowed: ['m2'] } }], 'block', 'B'),
  ]);
  assert.equal(models.cases[0].context.model, undefined, 'no value satisfies both, so none is supplied (absent never trips an allow-list)');
  // A jurisdiction list whose only entries are not two-letter codes cannot be satisfied by a signed value either.
  assert.equal(buildPolicyCases([mol('a', 'Named region', 'all', [{ predicate: 'jurisdiction-not-allowed', config: { allowed: ['Singapore'] } }], 'block', 'A')]).cases.length, 0);
});

await check('the fired jurisdiction is a real two-letter code off the list (a signed value must be one)', async () => {
  const { cases } = await assertAllCasesHold([
    mol('a', 'ZZ and SG', 'all', [{ predicate: 'jurisdiction-not-allowed', config: { allowed: ['ZZ', 'SG'] } }], 'block', 'A'),
  ]);
  assert.equal(cases[0].context.jurisdiction, 'ZZ');
  assert.equal(cases[1].context.jurisdiction, 'XX', 'ZZ is on the list, so the next user-assigned code is used');
});

await check('overlapping risk tiers (high -> escalate, medium -> block) are reported, never mislabelled', async () => {
  const { cases, notDemonstrated } = await assertAllCasesHold([
    mol('r1', 'High', 'all', [{ predicate: 'risk-at-or-above', config: { level: 'high' } }], 'escalate', 'HIGH'),
    mol('r2', 'Medium', 'all', [{ predicate: 'risk-at-or-above', config: { level: 'medium' } }], 'block', 'MED'),
  ]);
  assert.equal(cases.length, 1);
  assert.equal(notDemonstrated.length, 2);
});

await check('a text rule whose example text contains ANOTHER text rule\'s term is not staged; an unrelated pair still is', async () => {
  const clash = await assertAllCasesHold([
    mol('t1', 'Bans "in"', 'all', [{ predicate: 'text-matches', config: { terms: ['in'] } }], 'block', 'T1'),
    mol('t2', 'Bans refund', 'all', [{ predicate: 'text-matches', config: { terms: ['refund'] } }], 'block', 'T2'),
  ]);
  assert.ok(clash.notDemonstrated.some((n) => n.rule === 'Bans refund' && /another text rule/.test(n.why)));
  const fine = await assertAllCasesHold([
    mol('t1', 'No medical advice', 'all', [{ predicate: 'text-matches', config: { terms: ['diagnosis'] } }], 'block', 'T1'),
    mol('t2', 'No investment promises', 'all', [{ predicate: 'text-matches', config: { terms: ['guaranteed returns'] } }], 'block', 'T2'),
  ]);
  assert.equal(fine.cases.length, 3, 'two independent text rules are both staged');
});

await check('identical atoms with different decisions are reported, not silently dropped', async () => {
  const { notDemonstrated } = await assertAllCasesHold([
    mol('r1', 'Review PII', 'all', [{ predicate: 'pii-present' }], 'escalate', 'REVIEW'),
    mol('r2', 'Block PII', 'all', [{ predicate: 'pii-present' }], 'block', 'BLOCK'),
  ]);
  assert.deepEqual(notDemonstrated.map((n) => n.rule).sort(), ['Block PII', 'Review PII']);
});

await check('a "none" combinator fires when NO atom fires: the demo stages nothing rather than a false "allow"', async () => {
  const molecules = [
    mol('n1', 'Must have consent', 'none', [{ predicate: 'consent-missing' }], 'block', 'N'),
    mol('r1', 'PII review', 'all', [{ predicate: 'pii-present' }], 'escalate', 'PII'),
  ];
  const { cases, notDemonstrated } = buildPolicyCases(molecules);
  assert.deepEqual(cases, []);
  assert.equal(notDemonstrated.length, 2);
  assert.match(notDemonstrated[0].why, /none/);
  // ...and the evaluator confirms why: a request satisfying "everything" is BLOCKED by that rule.
  const [ok] = await runCases({ molecules }, [{ context: { consent: true, piiPresent: false } }]);
  assert.equal(ok.got, 'block', 'the evaluator agrees the naive passing request would not pass');
});

await check('a molecule with no/unknown combinator never fires in the evaluator, so it is reported and does not disturb the rest', async () => {
  const { cases, notDemonstrated } = await assertAllCasesHold([
    { id: 'd1', name: 'Dead rule', atoms: [{ id: 'a', predicate: 'consent-missing' }], decision: 'block', reasonCode: 'DEAD' },
    { id: 'd2', name: 'Empty rule', combinator: 'all', atoms: [], decision: 'block', reasonCode: 'EMPTY' },
    mol('r1', 'PII review', 'all', [{ predicate: 'pii-present' }], 'escalate', 'PII'),
  ]);
  assert.equal(cases.length, 2, 'the passing case and the one live rule');
  assert.deepEqual(notDemonstrated.map((n) => n.rule).sort(), ['Dead rule', 'Empty rule']);
  assert.ok(!('consent' in cases[0].context), 'a dead rule contributes nothing to the passing request');
});

await check('an empty first term is skipped: the case uses the first term the evaluator actually honours', async () => {
  const { cases } = await assertAllCasesHold([
    mol('t1', 'Terms', 'all', [{ predicate: 'text-matches', config: { terms: ['', '   ', 'refund'] } }], 'block', 'T'),
  ]);
  assert.equal(cases.length, 2);
  assert.match(cases[1].context.prompt, /refund/);
});

await check('rules the demo cannot drive are reported, not silently dropped or faked', () => {
  const molecules = [
    { id: 'm1', name: 'Spend cap', combinator: 'all', atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 100 } }], decision: 'block', reasonCode: 'CAP' },
    { id: 'm2', name: 'Trust review', combinator: 'all', atoms: [{ id: 'a', predicate: 'hol-trust-below-review', config: { reviewBelow: 60 } }], decision: 'escalate', reasonCode: 'TRUST' },
    { id: 'm3', name: 'Just watch', combinator: 'all', atoms: [{ id: 'a', predicate: 'pii-present' }], decision: 'observe', reasonCode: 'WATCH' },
    { id: 'm4', name: 'Unknown thing', combinator: 'all', atoms: [{ id: 'a', predicate: 'made-up-predicate' }], decision: 'block', reasonCode: 'X' },
  ];
  const { cases, notDemonstrated } = buildPolicyCases(molecules);
  assert.equal(cases.length, 1, 'only the passing case is generated');
  assert.deepEqual(notDemonstrated.map((n) => n.rule), ['Spend cap', 'Trust review', 'Just watch', 'Unknown thing']);
  assert.match(notDemonstrated[0].why, /non-financial/);
  assert.match(notDemonstrated[1].why, /platform/);
  assert.match(notDemonstrated[2].why, /observe/);
});

await check('the runtime inputs each rule reads are listed (BR-008: a rule needs its field supplied)', () => {
  const { inputs } = buildPolicyCases(POLICIES['customer communications (PII, consent, content, risk)'].map(ruleToMolecule));
  const fields = Object.fromEntries(inputs.map((i) => [i.field, i.rules]));
  assert.deepEqual(Object.keys(fields).sort(), ['consent', 'piiPresent', 'prompt / output', 'riskLevel']);
  assert.deepEqual(fields.consent, ['Consent required']);
});

await check('the non-financial default SOP passes an ordinary request and reviews a high-risk one — no amount rule', async () => {
  const doc = harnessDefaultSopNeutral();
  assert.ok(!JSON.stringify(doc).includes('amount'), 'no amount atom in the default');
  // D-03: an ordinary request STATES its risk. One that leaves it out is no longer waved through — a missing
  // riskLevel is unverifiable and escalates (spec §6.4.3), exactly like a high one, so an agent cannot skip the
  // review by staying silent.
  const results = await runCases(doc, [
    { context: { riskLevel: 'low' }, expect: 'allow' },
    { context: { riskLevel: 'high' }, expect: 'escalate' },
    { context: {}, expect: 'escalate' },
    { context: { riskLevel: 'HIGH' }, expect: 'escalate' },
  ]);
  assert.deepEqual(results.map((r) => r.got), ['allow', 'escalate', 'escalate', 'escalate']);
});

await check('a non-financial mandate carries no spend constraint', () => {
  const m = harnessMandate({ scope: SCOPE, financial: false, merchants: [] });
  assert.deepEqual(m.permission[0].constraint, []);
  const money = harnessMandate({ scope: SCOPE, currency: 'USD', maxAmount: 10000, perTxnMax: 500, merchants: [] });
  assert.equal(money.permission[0].constraint.length, 2, 'the financial mandate is unchanged');
});

await check('resolveFinancial: explicit wins; a policy file with no money in it is non-financial; flags-only keep their defaults', () => {
  const comms = { name: 'Comms', scope: SCOPE, rules: [rule('PII', 'pii-present', {}, 'escalate')] };
  assert.equal(resolveFinancial({}, null).financial, true, 'flags only: historical (visible) defaults');
  assert.equal(resolveFinancial({ 'non-financial': true }, null).financial, false);
  assert.equal(resolveFinancial({ config: 'c.json' }, comms).financial, false);
  assert.match(resolveFinancial({ config: 'c.json' }, comms).why, /no spend limit/);
  assert.equal(resolveFinancial({ config: 'c.json' }, { ...comms, perTxnMax: 500 }).financial, true, 'a spend limit in the file');
  assert.equal(resolveFinancial({ config: 'c.json' }, { ...comms, currency: 'GBP' }).financial, true, 'a currency in the file');
  assert.equal(resolveFinancial({ config: 'c.json', 'per-txn-max': '250' }, comms).financial, true, 'a spend flag');
  assert.equal(resolveFinancial({ config: 'c.json' }, { ...comms, rules: [rule('Cap', 'amount-over', { limit: 5 }, 'block')] }).financial, true, 'a monetary rule');
  assert.equal(resolveFinancial({ config: 'c.json' }, { ...comms, financial: true }).financial, true, '"financial": true forces it');
  assert.equal(resolveFinancial({ config: 'c.json' }, { ...comms, perTxnMax: 500, financial: false }).financial, false, '"financial": false wins over a stray limit');
  assert.equal(resolveFinancial({ config: 'c.json', financial: true }, comms).financial, true, '--financial forces it');
});

// Review finding: a key that LOOKS like a spend limit but is not one we read must never be read as "no money".
await check('unrecognised money-like keys block the non-financial inference and say why', () => {
  for (const key of ['per_txn_max', 'budget', 'spendCap', 'monthlyLimit', 'maxPayment', 'invoiceTotal']) {
    const r = resolveFinancial({ config: 'c.json' }, { name: 'Pay Bot', scope: 'pay-invoice', [key]: 250, rules: [rule('Review', 'risk-at-or-above', { level: 'high' }, 'escalate')] });
    assert.equal(r.financial, true, `${key} must not be inferred non-financial`);
    assert.match(r.warn, new RegExp(key));
    assert.match(r.warn, /perTxnMax \/ maxAmount \/ currency/);
  }
  // ...but unknown, non-money keys are harmless, and explicit choices still win
  assert.equal(resolveFinancial({ config: 'c.json' }, { name: 'x', description: 'a comms bot', owner: 'me', rules: [rule('PII', 'pii-present', {}, 'escalate')] }).financial, false);
  assert.equal(resolveFinancial({ config: 'c.json', 'non-financial': true }, { budget: 5 }).financial, false, '--non-financial wins');
  assert.equal(resolveFinancial({ config: 'c.json' }, { budget: 5, financial: false }).financial, false, '"financial": false wins');
});

// The highest-risk direction (review finding): silently DROPPING money from a policy that has some.
await check('a policy component the scaffolder cannot inspect is never assumed to be money-free', () => {
  const rulePackOnly = { name: 'Pay Bot', scope: 'pay-invoice', rulePack: 'payments-baseline' };
  assert.equal(resolveFinancial({ config: 'c.json' }, rulePackOnly).financial, true, 'a rulePack-only file keeps its financial scaffold');
  assert.equal(resolveFinancial({ config: 'c.json' }, { ...rulePackOnly, rules: [] }).financial, true, 'an EMPTY rules list does not make a pack inspectable');
  assert.equal(resolveFinancial({ config: 'c.json' }, { ...rulePackOnly, rules: [rule('PII', 'pii-present', {}, 'escalate')] }).financial, false, 'rules present: the pack is ignored by the harness, the rules are the policy');
  assert.equal(resolveFinancial({ config: 'c.json' }, { ...rulePackOnly, financial: false }).financial, false, 'an explicit "financial": false still wins');
  const withMerchants = { name: 'Procurement', scope: 'purchase-order', merchants: ['acme'], rules: [rule('Review', 'risk-at-or-above', { level: 'high' }, 'escalate')] };
  assert.equal(resolveFinancial({ config: 'c.json' }, withMerchants).financial, true, 'named merchants are payees');
  assert.equal(resolveFinancial({ config: 'c.json' }, { ...withMerchants, merchants: [] }).financial, false, 'an empty list is not');
  assert.equal(resolveFinancial({ config: 'c.json', merchants: 'acme' }, { name: 'x', rules: [rule('PII', 'pii-present', {}, 'escalate')] }).financial, true, 'a --merchants flag');
});

// ---- The real CLI, end to end: what actually lands on disk for the tester's kind of policy. ----
const workdir = mkdtempSync(join(tmpdir(), 'metamynd-policy-demo-'));
const cliEnv = { ...process.env, CREATE_METAMYND_AGENT_NO_MAIN: '' }; // '' = falsy: let the child run main()
function scaffold(name, args) {
  const out = join(workdir, name);
  let stdout = '';
  try {
    stdout = execFileSync(process.execPath, [join(process.cwd(), 'index.mjs'), '--harness', '--yes', '--out', out, ...args], { env: cliEnv, stdio: 'pipe' }).toString();
  } catch (e) { throw new Error(`scaffold failed: ${e.stderr?.toString().slice(0, 300) ?? e.message}`); }
  const read = (f) => readFileSync(join(out, f), 'utf8');
  return { out, stdout: stdout.replace(/\x1b\[[0-9;]*m/g, ''), read };
}
function mjsFiles(dir) {
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory() ? mjsFiles(p) : p.endsWith('.mjs') ? [p] : [];
  });
}
const FINANCIAL_LEAK = /flight|bookflight|book-flight|pnr|\busd\b|per-transaction|spend cap|payAmount|cumulativeSpend|amount-unknown/i;

const commsFile = join(workdir, 'comms.policy.json');
writeFileSync(commsFile, JSON.stringify({
  name: 'Support Comms Agent', scope: 'send-customer-notice',
  rules: [
    { name: 'Personal data needs review', when: { predicate: 'pii-present' }, then: 'escalate', reasonCode: 'PII_REVIEW' },
    { name: 'Consent required', when: { predicate: 'consent-missing' }, then: 'block', reasonCode: 'NO_CONSENT' },
    { name: 'No investment promises', when: { predicate: 'text-matches', config: { terms: ['guaranteed returns'] } }, then: 'block', reasonCode: 'PROHIBITED_CLAIM' },
  ],
}));

for (const [shape, extra] of [['single process', []], ['--gateway', ['--gateway']]]) {
  await check(`comms policy (${shape}): nothing financial is generated or injected`, () => {
    const r = scaffold('comms-' + shape.replace(/\W+/g, ''), ['--config', commsFile, ...extra]);
    assert.match(r.stdout, /non-financial agent/);
    assert.match(r.stdout, /derived 4 demo case\(s\)/);
    for (const f of mjsFiles(r.out)) execFileSync(process.execPath, ['--check', f], { stdio: 'pipe' });
    for (const f of ['index.mjs', 'README.md', 'metamynd-rules.json']) {
      assert.doesNotMatch(r.read(f), FINANCIAL_LEAK, `${f} mentions something financial`);
    }
    const rules = JSON.parse(r.read('metamynd-rules.json'));
    assert.deepEqual(rules.mandate.permission[0].constraint, [], 'no spend constraint in the mandate');
    assert.equal(rules.mandate.permission[0].target, 'send-customer-notice', 'the supplied scope, not flight-purchase');
    assert.deepEqual(rules.sops[0].document.molecules.map((m) => m.reasonCode), ['PII_REVIEW', 'NO_CONSENT', 'PROHIBITED_CLAIM'], 'exactly the supplied rules');
    const index = r.read('index.mjs');
    for (const code of ['PII_REVIEW', 'NO_CONSENT', 'PROHIBITED_CLAIM']) assert.ok(index.includes(code), `a demo step exists for ${code}`);
    assert.match(r.read('README.md'), /What your rules read/);
    if (extra.length) {
      const gw = readFileSync(join(r.out, 'harness-gateway', 'harness-gateway.mjs'), 'utf8');
      assert.match(gw, /'\/perform'/);
      assert.doesNotMatch(gw, FINANCIAL_LEAK);
    }
  });
}

await check('flags only (no policy file): the historical payment scaffold is unchanged, and its defaults are now SAID', () => {
  const r = scaffold('flags-only', []);
  assert.match(r.stdout, /no spend limits supplied — using the defaults USD 500/);
  assert.match(r.read('index.mjs'), /bookFlight/);
  assert.equal(JSON.parse(r.read('metamynd-rules.json')).mandate.permission[0].constraint.length, 2);
});

await check('explicit spend flags: no defaults notice, still a financial scaffold', () => {
  const r = scaffold('explicit-money', ['--per-txn-max', '250', '--max-amount', '900', '--currency', 'GBP']);
  assert.doesNotMatch(r.stdout, /no spend limits supplied/);
  assert.match(r.read('index.mjs'), /GBP 250/);
});

await check('a policy file WITH a spend limit stays financial; "financial": true forces it; --non-financial forces the other way', () => {
  const withLimit = join(workdir, 'with-limit.json');
  writeFileSync(withLimit, JSON.stringify({ name: 'Pay Bot', scope: 'pay-invoice', perTxnMax: 250, currency: 'GBP', rules: [{ when: { predicate: 'risk-at-or-above', config: { level: 'high' } }, then: 'escalate' }] }));
  assert.doesNotMatch(scaffold('limit', ['--config', withLimit]).stdout, /non-financial agent/);
  const forced = join(workdir, 'forced.json');
  writeFileSync(forced, JSON.stringify({ ...JSON.parse(readFileSync(commsFile, 'utf8')), financial: true }));
  assert.doesNotMatch(scaffold('forced', ['--config', forced]).stdout, /non-financial agent/);
  const flagged = scaffold('flagged', ['--non-financial', '--scope', 'triage-ticket']);
  assert.match(flagged.stdout, /non-financial agent \(--non-financial\)/);
  assert.doesNotMatch(flagged.read('index.mjs'), FINANCIAL_LEAK);
  assert.match(flagged.read('index.mjs'), /RISK_REVIEW/, 'the amount-free default review rule is what gets demonstrated');
});

await check('hosted scaffolding ACCEPTS --non-financial (it now proceeds to ask for login); the full flow is in hosted-nonfinancial.smoke.mjs', () => {
  let err;
  // No email (blank env) stops it before any request; --api names a closed port anyway, so a stray METAMYND_EMAIL in a
  // developer's shell can never turn this into a call to the real default server.
  try { execFileSync(process.execPath, [join(process.cwd(), 'index.mjs'), '--non-financial', '--yes', '--api', 'http://127.0.0.1:9'], { env: { ...cliEnv, METAMYND_EMAIL: '', METAMYND_PASSWORD: '' }, stdio: 'pipe' }); }
  catch (e) { err = e; }
  assert.ok(err, 'exited non-zero (no --email supplied)');
  const text = err.stderr.toString() + err.stdout.toString();
  assert.match(text, /owner email is required/, 'got as far as the login step');
  assert.doesNotMatch(text, /not yet with --sandbox/, 'was not refused');
});

// NOTE: --non-financial with --sandbox / --request / --claim is now HONOURED (it used to be refused here). Those modes
// need a server, so they are covered by modes-nonfinancial.smoke.mjs against a stand-in - never in this file, which
// runs the CLI with no --api and would reach the real default server.

await check('spend flags/fields given to a NON-financial agent are reported as ignored, not silently dropped', () => {
  const flagged = scaffold('ignored-flags', ['--non-financial', '--per-txn-max', '250', '--currency', 'GBP', '--scope', 'triage-ticket']);
  assert.match(flagged.stdout, /ignoring --per-txn-max, --currency/);
  assert.match(flagged.stdout, /pass --financial/);
  const misspelled = join(workdir, 'misspelled.json');
  writeFileSync(misspelled, JSON.stringify({ name: 'Pay Bot', scope: 'pay-invoice', per_txn_max: 250, rules: [{ when: { predicate: 'risk-at-or-above', config: { level: 'high' } }, then: 'escalate' }] }));
  const r = scaffold('misspelled', ['--config', misspelled]);
  assert.match(r.stdout, /"per_txn_max" in the config file look like spend limits but are not recognised/);
  assert.doesNotMatch(r.stdout, /✓ non-financial agent/, 'and it is NOT inferred non-financial');
  assert.match(r.read('index.mjs'), /bookFlight/, 'the historical (visible-default) payment scaffold');
});

await check('when NO rule can be staged the summary says so, never "(-1)" or a promised ALLOW', () => {
  const noneFile = join(workdir, 'none.json');
  writeFileSync(noneFile, JSON.stringify({
    name: 'Ticket Bot', scope: 'route-ticket',
    molecules: [{ id: 'n1', name: 'Must mention a ticket', combinator: 'none', atoms: [{ id: 'a', predicate: 'text-matches', config: { terms: ['ticket #'] } }], decision: 'escalate', reasonCode: 'NO_TICKET' }],
  }));
  const r = scaffold('none-policy', ['--config', noneFile]);
  assert.match(r.stdout, /derived 0 demo case\(s\)/);
  assert.match(r.stdout, /BLOCK \(ungranted action\) only/);
  assert.doesNotMatch(r.stdout, /\(-1\)/);
  assert.match(r.read('README.md'), /None of your rules could be staged/);
});

await check('a scope that would break or inject into generated code is refused up front', () => {
  for (const bad of ["customer's-notice", 'a"b', 'a`b', 'a$b', 'a\\b']) {
    let err;
    try { execFileSync(process.execPath, [join(process.cwd(), 'index.mjs'), '--harness', '--yes', '--scope', bad, '--out', join(workdir, 'bad-scope')], { env: cliEnv, stdio: 'pipe' }); }
    catch (e) { err = e; }
    assert.ok(err, `${JSON.stringify(bad)} was accepted`);
    assert.match(err.stderr.toString() + err.stdout.toString(), /scope must not contain/);
  }
  const ok = scaffold('good-scope', ['--scope', 'send-customer.notice:v2']);
  assert.match(ok.read('index.mjs'), /send-customer\.notice:v2/);
});

rmSync(workdir, { recursive: true, force: true });

if (failed) { console.error(`\n${failed} case(s) FAILED`); process.exit(1); }
console.log('\nPASS — the non-financial demo is derived from the policy, and every case behaves as labelled.');

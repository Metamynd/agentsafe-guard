// local-eval.smoke.mjs — proves the guard evaluates a policy bundle LOCALLY
// (no network) via policy-core, and that its verdicts match the gate's logic.
//
//   node local-eval.smoke.mjs
//
// Exits 0 and prints PASS when every case matches; exits 1 on the first mismatch.
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';

// createGuard builds the signing key eagerly; a local-eval demo doesn't sign, so
// mint an ephemeral Ed25519 key (exported as Hedera-style pkcs8 DER hex).
const { privateKey } = crypto.generateKeyPairSync('ed25519');
const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const agentDid = 'did:hedera:testnet:z6MkSmoke_0.0.1';

const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });

// A simple policy bundle: one enforced Standard (risk → escalate), one SOP
// (per-transaction cap → block), and an ODRL mandate (budget + merchant).
const bundle = {
  standards: [
    {
      standardKey: 'eu-ai-act',
      document: {
        molecules: [
          {
            id: 'risk',
            combinator: 'any',
            atoms: [{ id: 'r', predicate: 'risk-at-or-above', config: { level: 'high' } }],
            decision: 'escalate',
            reasonCode: 'RISK_REVIEW',
          },
        ],
      },
    },
  ],
  sops: [
    {
      standardKey: 'sop:travel',
      document: {
        molecules: [
          {
            id: 'cap',
            combinator: 'any',
            atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 500 } }],
            decision: 'block',
            reasonCode: 'SOP_SPEND_CAP',
          },
          {
            // OBSERVE (SAFR §11): a mid-value spend is PERMITTED but flagged for
            // monitoring — outranks allow, but the cap block/quarantine still wins.
            id: 'watch',
            combinator: 'any',
            atoms: [{ id: 'w', predicate: 'amount-over', config: { limit: 200 } }],
            decision: 'observe',
            reasonCode: 'WATCH_LARGE',
          },
          {
            // Containment (1C): a gross overspend doesn't just block the action,
            // it quarantines the agent. Outranks the plain block above.
            id: 'contain',
            combinator: 'any',
            atoms: [{ id: 'q', predicate: 'amount-over', config: { limit: 5000 } }],
            decision: 'quarantine',
            reasonCode: 'GROSS_OVERSPEND',
          },
        ],
      },
    },
  ],
  mandate: {
    permission: [
      {
        target: 'flight-purchase',
        constraint: [
          { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 },
          { leftOperand: 'mm:cumulativeSpend', operator: 'lteq', rightOperand: 1000 },
          { leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: ['amadeus'] },
        ],
      },
    ],
  },
};

const cases = [
  { name: 'within cap, allowed merchant, low risk → allow', request: { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['allow', 'AUTHORIZED'] },
  // SAFR §11: a mid-value spend is permitted-but-flagged (observe outranks allow).
  { name: 'mid-value spend → observe (permit-but-flag, outranks allow)', request: { action: 'flight-purchase', amount: 300, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['observe', 'WATCH_LARGE'] },
  // observe loses to the SOP cap block at higher amounts (block > observe).
  { name: 'SOP per-transaction cap → block', request: { action: 'flight-purchase', amount: 600, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['block', 'SOP_SPEND_CAP'] },
  { name: 'Standard risk threshold → escalate', request: { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'high' } }, expect: ['escalate', 'RISK_REVIEW'] },
  { name: 'mandate merchant not allowed → block', request: { action: 'flight-purchase', amount: 100, merchant: 'sabre', context: { riskLevel: 'low' } }, expect: ['block', 'MERCHANT_NOT_ALLOWED'] },
  // §11.5: a forged unsigned context cannot shadow the signed amount/merchant.
  { name: 'forged context cannot shadow signed $600 → block', request: { action: 'flight-purchase', amount: 600, merchant: 'amadeus', context: { 'mm:payAmount': 1, riskLevel: 'low' } }, expect: ['block', 'SOP_SPEND_CAP'] },
  // 1C: gross overspend fires a quarantine that outranks the plain block/cap.
  { name: 'gross overspend → quarantine (contains agent, outranks block)', request: { action: 'flight-purchase', amount: 6000, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['quarantine', 'GROSS_OVERSPEND'] },
];

let failed = 0;
for (const c of cases) {
  const v = guard.evaluateLocally({ ...bundle, request: c.request });
  const ok = v.decision === c.expect[0] && v.reasonCode === c.expect[1];
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${c.name}  →  ${v.decision}/${v.reasonCode}`);
}

// Phase 2.3: a server-CONTAINED agent is denied at the edge, before ANY rule eval —
// the `contained` flag rides alongside the bundle (a sibling of the signed payload).
{
  const cv = guard.evaluateLocally({
    ...bundle,
    contained: { status: 'quarantined', reason: 'GROSS_OVERSPEND' },
    request: { action: 'flight-purchase', amount: 1, merchant: 'amadeus', context: { riskLevel: 'low' } },
  });
  const ok = cv.decision === 'quarantine' && cv.reasonCode === 'AGENT_QUARANTINED';
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  contained agent → denied at the edge (before rule eval)  →  ${cv.decision}/${cv.reasonCode}`);
}

// A mandate constraint issued with a `unit` (currency) — evaluateLocally must supply
// 'mm:currency' (defaulting to 'USD') to the values map, or a unit-bearing cap fails
// EVERY request regardless of amount, since undefined never equals a real unit.
{
  const unitBundle = {
    mandate: {
      permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 500, unit: 'USD' }] }],
    },
  };
  const withinCapUsd = guard.evaluateLocally({ ...unitBundle, request: { action: 'flight-purchase', amount: 100 } });
  const ok1 = withinCapUsd.decision === 'allow';
  if (!ok1) failed++;
  console.log(`${ok1 ? 'ok  ' : 'FAIL'}  a unit-bearing cap still allows a within-cap request (implicit USD default)  →  ${withinCapUsd.decision}/${withinCapUsd.reasonCode}`);

  const explicitUsd = guard.evaluateLocally({ ...unitBundle, request: { action: 'flight-purchase', amount: 100, currency: 'USD' } });
  const ok2 = explicitUsd.decision === 'allow';
  if (!ok2) failed++;
  console.log(`${ok2 ? 'ok  ' : 'FAIL'}  a unit-bearing cap allows the same request with currency explicitly matching  →  ${explicitUsd.decision}/${explicitUsd.reasonCode}`);

  const wrongCurrency = guard.evaluateLocally({ ...unitBundle, request: { action: 'flight-purchase', amount: 100, currency: 'JPY' } });
  const ok3 = wrongCurrency.decision === 'block';
  if (!ok3) failed++;
  console.log(`${ok3 ? 'ok  ' : 'FAIL'}  a unit-bearing cap blocks the same numeric amount in a DIFFERENT currency  →  ${wrongCurrency.decision}/${wrongCurrency.reasonCode}`);
}

// Phase 2.5b: the operating-mode autonomy ladder rides as a sibling and biases the
// EDGE verdict identically to the backend gate (READ_ONLY blocks value-bearing,
// RESTRICTED/SUPERVISED escalate, reads always pass, a rule block still outranks).
const modeCases = [
  { name: 'READ_ONLY blocks a value-bearing action at the edge', operatingMode: { mode: 'read_only' }, request: { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['block', 'MODE_READ_ONLY'] },
  { name: 'READ_ONLY still allows a zero-amount read', operatingMode: { mode: 'read_only' }, request: { action: 'flight-purchase', amount: 0, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['allow', 'AUTHORIZED'] },
  { name: 'RESTRICTED escalates an otherwise-allowed value action', operatingMode: { mode: 'restricted' }, request: { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['escalate', 'MODE_RESTRICTED_REVIEW'] },
  // Spend AT/ABOVE the SUPERVISED cap (100) with LOW risk isolates the mode path (the
  // Standard's high-risk escalate would otherwise fire first with its own reasonCode).
  { name: 'SUPERVISED escalates a spend at/above the cap', operatingMode: { mode: 'supervised' }, request: { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['escalate', 'MODE_SUPERVISED_REVIEW'] },
  { name: 'SUPERVISED allows a small low-risk spend below the cap', operatingMode: { mode: 'supervised' }, request: { action: 'flight-purchase', amount: 10, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['allow', 'AUTHORIZED'] },
  { name: 'a mode escalate NEVER downgrades a rule block (precedence holds)', operatingMode: { mode: 'restricted' }, request: { action: 'flight-purchase', amount: 600, merchant: 'amadeus', context: { riskLevel: 'low' } }, expect: ['block', 'SOP_SPEND_CAP'] },
];
for (const c of modeCases) {
  const v = guard.evaluateLocally({ ...bundle, operatingMode: c.operatingMode, request: c.request });
  const ok = v.decision === c.expect[0] && v.reasonCode === c.expect[1];
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${c.name}  →  ${v.decision}/${v.reasonCode}`);
}

// SAFR §11: guardToolLocal EXECUTES the wrapped handler on an OBSERVE (permit-but-
// flag) exactly like an allow — unlike block/escalate, which throw GovernanceBlocked.
{
  let ran = false;
  const wrapped = guard.guardToolLocal('flight-purchase', async () => { ran = true; return 'booked'; }, (a) => a, bundle);
  const out = await wrapped({ amount: 300, merchant: 'amadeus', context: { riskLevel: 'low' } });
  const ok = ran === true && out === 'booked';
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  guardToolLocal EXECUTES the handler on observe (permit-but-flag)  →  ran=${ran}`);
}

// And it still THROWS on a block (the cap), never executing the handler.
{
  let ran = false;
  const wrapped = guard.guardToolLocal('flight-purchase', async () => { ran = true; return 'booked'; }, (a) => a, bundle);
  let threw = false;
  try { await wrapped({ amount: 600, merchant: 'amadeus', context: { riskLevel: 'low' } }); } catch (e) { threw = e?.name === 'GovernanceBlocked'; }
  const ok = threw === true && ran === false;
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  guardToolLocal THROWS on block, handler never runs  →  threw=${threw} ran=${ran}`);
}

if (failed) {
  console.error(`\n${failed} case(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — guard evaluates the policy bundle locally, verdicts match the gate.');

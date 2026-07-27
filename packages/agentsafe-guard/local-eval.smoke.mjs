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

if (failed) {
  console.error(`\n${failed} case(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — guard evaluates the policy bundle locally, verdicts match the gate.');

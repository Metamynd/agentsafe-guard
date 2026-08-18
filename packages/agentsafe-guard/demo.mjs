// demo.mjs — the no-account, no-network tour of the guard.
//
//   npx @metamynd/agentsafe-guard demo
//
// Everything here runs locally: an ephemeral Ed25519 key, an inline policy bundle,
// and `policy-core` — the same evaluator bytes the hosted gate runs. No MetaMynd
// account, no API key, no Hedera, no outbound request (the `api` URL below is
// deliberately unroutable, and nothing ever calls it).
//
// Exits 0 when every verdict matches what the policy says it should be, 1 otherwise —
// so this doubles as a smoke test of the shipped package.
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';

const c = (code, s) => (process.stdout.isTTY ? `\u001b[${code}m${s}\u001b[0m` : s);
const bold = (s) => c('1', s);
const dim = (s) => c('2', s);
const head = (s) => console.log(`\n${bold(s)}\n${dim('─'.repeat(s.length))}`);

// Colour per decision — but never colour ALONE: the verdict is always spelled out.
const paint = { allow: '32', observe: '36', escalate: '33', block: '31', quarantine: '35' };
const verdict = (d) => c(paint[d] ?? '0', d.toUpperCase().padEnd(10));

const { privateKey } = crypto.generateKeyPairSync('ed25519');
const guard = createGuard({
  api: 'http://unused.local/api/v1', // never contacted — this demo is entirely local
  agentDid: 'did:hedera:testnet:z6MkDemo_0.0.1',
  agentKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex'),
});

// The policy an owner would author in the dashboard, as the agent receives it:
// one enforced Standard, one SOP, and an ODRL mandate.
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
            id: 'watch',
            combinator: 'any',
            atoms: [{ id: 'w', predicate: 'amount-over', config: { limit: 200 } }],
            decision: 'observe',
            reasonCode: 'WATCH_LARGE',
          },
          {
            id: 'cap',
            combinator: 'any',
            atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 500 } }],
            decision: 'block',
            reasonCode: 'SOP_SPEND_CAP',
          },
          {
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

let failed = 0;
const check = (ok) => { if (!ok) failed++; return ok ? dim('ok') : c('31', 'FAIL'); };

const run = (label, request, expect, extra = {}) => {
  const v = guard.evaluateLocally({ ...bundle, ...extra, request });
  const ok = v.decision === expect[0] && v.reasonCode === expect[1];
  console.log(`  ${verdict(v.decision)} ${String(v.reasonCode).padEnd(22)} ${label}  ${check(ok)}`);
};

console.log(bold('\nAgentSafe Guard — local policy evaluation'));
console.log(dim('No account, no API key, no network. Same policy-core the hosted gate runs.'));

head('The policy this agent is under');
console.log(`  Standard ${dim('eu-ai-act')}    risk ≥ high                 → escalate`);
console.log(`  SOP      ${dim('sop:travel')}   amount > 200                → observe   ${dim('(permit, but flag)')}`);
console.log(`                        amount > 500                → block`);
console.log(`                        amount > 5000               → quarantine ${dim('(contain the agent)')}`);
console.log(`  Mandate  ${dim('ODRL')}         merchant ∈ [amadeus], ≤ 1000 per action and in total`);

head('A tool call, evaluated against it');
run('$100 to amadeus, low risk', { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } }, ['allow', 'AUTHORIZED']);
run('$300 — over the watch line', { action: 'flight-purchase', amount: 300, merchant: 'amadeus', context: { riskLevel: 'low' } }, ['observe', 'WATCH_LARGE']);
run('$600 — over the SOP cap', { action: 'flight-purchase', amount: 600, merchant: 'amadeus', context: { riskLevel: 'low' } }, ['block', 'SOP_SPEND_CAP']);
run('$100 but flagged high risk', { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'high' } }, ['escalate', 'RISK_REVIEW']);
run('$100 to a merchant off the mandate', { action: 'flight-purchase', amount: 100, merchant: 'sabre', context: { riskLevel: 'low' } }, ['block', 'MERCHANT_NOT_ALLOWED']);
run('$6000 — gross overspend', { action: 'flight-purchase', amount: 6000, merchant: 'amadeus', context: { riskLevel: 'low' } }, ['quarantine', 'GROSS_OVERSPEND']);

head('The agent cannot argue its way out');
console.log(dim('  Unsigned context is untrusted input — it never shadows the signed amount.'));
run('$600 claiming "payAmount: 1"', { action: 'flight-purchase', amount: 600, merchant: 'amadeus', context: { 'mm:payAmount': 1, riskLevel: 'low' } }, ['block', 'SOP_SPEND_CAP']);
console.log(dim('  A quarantined agent is refused at the edge, before any rule is read.'));
run('$1 while quarantined', { action: 'flight-purchase', amount: 1, merchant: 'amadeus', context: { riskLevel: 'low' } }, ['quarantine', 'AGENT_QUARANTINED'], { contained: { status: 'quarantined', reason: 'GROSS_OVERSPEND' } });

head('Operating mode narrows the ladder further');
const mode = (m) => ({ operatingMode: { mode: m } });
run('read_only — value action refused', { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } }, ['block', 'MODE_READ_ONLY'], mode('read_only'));
run('read_only — a $0 read still passes', { action: 'flight-purchase', amount: 0, merchant: 'amadeus', context: { riskLevel: 'low' } }, ['allow', 'AUTHORIZED'], mode('read_only'));
run('restricted — spend needs a human', { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } }, ['escalate', 'MODE_RESTRICTED_REVIEW'], mode('restricted'));
run('restricted — but a block stays a block', { action: 'flight-purchase', amount: 600, merchant: 'amadeus', context: { riskLevel: 'low' } }, ['block', 'SOP_SPEND_CAP'], mode('restricted'));

head('What that means for your tool');
{
  let ran = false;
  const book = guard.guardToolLocal('flight-purchase', async () => { ran = true; return 'booked'; }, (a) => a, bundle);
  const out = await book({ amount: 300, merchant: 'amadeus', context: { riskLevel: 'low' } });
  console.log(`  observe   → handler RAN, returned ${JSON.stringify(out)}  ${check(ran === true && out === 'booked')}`);
}
{
  let ran = false;
  const book = guard.guardToolLocal('flight-purchase', async () => { ran = true; return 'booked'; }, (a) => a, bundle);
  let name = null;
  try { await book({ amount: 600, merchant: 'amadeus', context: { riskLevel: 'low' } }); } catch (e) { name = e?.name; }
  console.log(`  block     → threw ${name}, handler never ran  ${check(name === 'GovernanceBlocked' && ran === false)}`);
}

if (failed) {
  console.error(c('31', `\n${failed} case(s) FAILED — that is a bug, please report it.`));
  console.error(dim('Please report it — https://metamynd.ai\n'));
  process.exit(1);
}

console.log(bold('\nPASS') + dim(' — every verdict matched the policy, decided locally in-process.\n'));
console.log('Wire it into your own agent:');
console.log(dim("  import { createGuard } from '@metamynd/agentsafe-guard';"));
console.log(dim('  const safeBooking = guard.guardToolLocal(\'flight-purchase\', bookFlight, mapArgs, bundle);'));
console.log(`\n${dim('Local evaluation needs nothing from us. The hosted platform adds live policy')}`);
console.log(`${dim('editing, cumulative spend caps, human escalation, and anchored evidence:')}`);
console.log(`${dim('https://metamynd.ai')}\n`);

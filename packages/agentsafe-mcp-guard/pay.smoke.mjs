// pay.smoke.mjs — proves the x402 payment binding (MAGP §7a): a settlement is
// bound to exactly one authorization, can't exceed the authorized amount, can't be
// reused, and fails closed. Runs the §7a.1 ordering in-process, no chain/network.
//
//   node pay.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';
import { createGuard } from '../agentsafe-guard/agentsafe-guard.mjs';

function mint(t) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const raw = spki.subarray(spki.length - 32);
  return { did: buildHederaDid('testnet', raw, t), key: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex') };
}

const agentId = mint('0.0.100');
const service = mint('0.0.200');
const agent = createGuard({ api: 'http://x/api/v1', agentDid: agentId.did, agentKey: agentId.key });
const mcp = createMcpGuard({ serviceDid: service.did });

let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };

// Step 1 (authorize): the gate returned this authorizationId + amount for the hold.
const authorizationId = crypto.randomUUID();
const AMOUNT = 150;

// Step 3 (402): the Service, having verified the authorization, demands payment
// bound to it (§7a.2).
const requirements = mcp.requirePayment({
  authorizationId, agentDid: agentId.did, amount: AMOUNT,
  payTo: '0.0.5005', asset: 'USDC', resource: '/book-flight',
});
ok(requirements.accepts[0].extra.magpAuthorizationId === authorizationId, '402 is bound to the authorizationId');
ok(requirements.accepts[0].maxAmountRequired === '150000000', 'maxAmountRequired equals the authorized amount');

// Step 5 (pay): the agent reads the 402, confirms the binding matches its own
// authorization, and prepares to pay exactly the authorized amount.
const payment = agent.preparePayment(requirements, authorizationId);
ok(payment.authorizationId === authorizationId && payment.amountMinor === '150000000', 'agent prepares an exact, bound payment');

// A stub facilitator that "settles" and returns an on-chain tx hash.
const facilitator = async () => ({ settled: true, txHash: '0xdeadbeefcafe' });

// Happy path: verify binding → settle → tx hash.
const settled = await mcp.settle({ requirements, authorizationId, paidAmountMinor: payment.amountMinor, settleFn: facilitator });
ok(settled.settled && settled.txHash === '0xdeadbeefcafe', 'settles and returns the tx hash', `${settled.reasonCode}/${settled.txHash}`);

// Step 7 (capture): the agent reconciles the hold with the settled amount + tx hash.
// (Here we just assert the values the agent would send to /capture.)
ok(Number(payment.amountMinor) / 1e6 === AMOUNT, 'capture amount reconciles to the authorized amount');

// --- Adversarial cases ---

// Overpay: a payment above the authorized amount is rejected (§7a.2.2).
const over = await mcp.settle({ requirements, authorizationId, paidAmountMinor: '150000001', settleFn: facilitator });
ok(!over.settled && over.reasonCode === 'AMOUNT_MISMATCH', 'overpayment rejected (AMOUNT_MISMATCH)');

// Reuse: the same authorization cannot settle twice (anti-reuse).
const reuse = await mcp.settle({ requirements, authorizationId, paidAmountMinor: payment.amountMinor, settleFn: facilitator });
ok(!reuse.settled && reuse.reasonCode === 'SETTLEMENT_REUSED', 'reused authorization rejected (SETTLEMENT_REUSED)');

// Facilitator failure fails closed.
const auth2 = crypto.randomUUID();
const req2 = mcp.requirePayment({ authorizationId: auth2, agentDid: agentId.did, amount: 50, payTo: '0.0.5005', asset: 'USDC', resource: '/book-flight' });
const failSettle = await mcp.settle({ requirements: req2, authorizationId: auth2, paidAmountMinor: '50000000', settleFn: async () => ({ settled: false }) });
ok(!failSettle.settled && failSettle.reasonCode === 'SETTLEMENT_FAILED', 'facilitator failure fails closed (SETTLEMENT_FAILED)');

// Unbound 402: the agent refuses to pay for an ungoverned request (§7a.2.1).
let unbound = false;
try { agent.preparePayment({ accepts: [{ maxAmountRequired: '1', extra: {} }] }); } catch (e) { unbound = e.name === 'UnboundPayment'; }
ok(unbound, 'agent refuses an unbound 402 (UnboundPayment)');

// Swapped 402: a 402 for a different authorization is refused.
let mismatch = false;
try { agent.preparePayment(requirements, 'some-other-auth-id'); } catch (e) { mismatch = e.name === 'AuthorizationMismatch'; }
ok(mismatch, 'agent refuses a 402 for a different authorization (AuthorizationMismatch)');

if (failed) { console.error(`\n${failed} case(s) FAILED`); process.exit(1); }
console.log('\nPASS — x402 settlement is bound to the MAGP authorization, exact, single-use, fail-closed.');

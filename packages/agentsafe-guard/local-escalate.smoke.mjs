// local-escalate.smoke.mjs — H-1 (pre-beta evaluation, 2026-10-02): a local-first guard decided ESCALATE in-process, so
// the gate never parked the action. There was no escalationId to poll, nothing in the owner's Escalations queue, and the
// scaffold's "approve it in the dashboard and the action resumes" could not happen. An escalate now goes to the gate —
// for a value action and an amount-0 one alike — and only pure offline (sealValueActions:false) keeps it local.
//
//   node local-escalate.smoke.mjs
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';
import { buildHederaDid } from './magp-did.mjs';

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const agentDid = buildHederaDid('testnet', publicKey.export({ format: 'der', type: 'spki' }).subarray(-32), '0.0.1');

const bundle = {
  mandates: [{ action: 'flight-purchase', document: { uid: 'u', permission: [{ target: 'flight-purchase', action: 'execute', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 500, unit: 'USD' }] }] } }],
  sops: [{ id: 'sop', document: { molecules: [{ id: 'review', name: 'High-risk review', combinator: 'any', atoms: [{ id: 'a', predicate: 'risk-at-or-above', config: { level: 'high' } }], decision: 'escalate', reasonCode: 'RISK_REVIEW' }] } }],
  standards: [],
};

const gateCalls = [];
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  const u = String(url);
  if (u.includes('/policy/bundle/')) return { ok: true, status: 200, json: async () => ({ data: bundle }) };
  if (u.endsWith('/policy/mandate/authorize')) {
    gateCalls.push(JSON.parse(opts.body));
    const data = { decision: 'escalate', reasonCode: 'RISK_REVIEW', authorizationId: null, escalationId: `esc-${gateCalls.length}`, eventId: `evt-${gateCalls.length}`, expiresAt: new Date(Date.now() + 864e5).toISOString() };
    return { ok: false, status: 403, json: async () => ({ success: false, data }) };
  }
  return { ok: true, status: 200, json: async () => ({}) }; // local decision reports etc.
};

const high = { action: 'flight-purchase', currency: 'USD', merchant: 'skyward-air', context: { riskLevel: 'high' } };

try {
  const guard = createGuard({ api: 'http://stub.local/api/v1', agentDid, agentKey });

  let v = await guard.authorizeLocal({ ...high, amount: 250 });
  check(v.decision === 'escalate' && v.escalationId === 'esc-1', `value action: escalate is PARKED at the gate, with an escalationId to poll (got ${v.decision}/${v.escalationId})`);
  check(v.eventId === 'evt-1', 'value action: the gate\'s evidence eventId comes back too');

  v = await guard.authorizeLocal({ ...high, amount: 0 });
  check(v.decision === 'escalate' && v.escalationId === 'esc-2', `amount-0 action: also parked at the gate (got ${v.decision}/${v.escalationId})`);

  // guardTool (what every scaffold registers) — the thrown verdict carries the escalationId the agent polls.
  let ran = false;
  const tool = guard.guardTool('flight-purchase', async () => { ran = true; }, (a) => ({ amount: a.amount, currency: 'USD', merchant: 'skyward-air', context: { riskLevel: 'high' } }));
  let thrown = null;
  try { await tool({ amount: 250 }); } catch (e) { thrown = e; }
  check(!ran, 'guardTool: the tool never runs on an escalate');
  check(thrown?.governance?.decision === 'escalate' && thrown?.governance?.escalationId === 'esc-3', `guardTool: the error carries the gate's escalationId (got ${thrown?.governance?.escalationId})`);

  // A low-risk permit still needs no gate for its rule check; a value one is sealed there as before.
  const before = gateCalls.length;
  await guard.authorizeLocal({ ...high, amount: 0, context: { riskLevel: 'low' } });
  check(gateCalls.length === before, 'a non-value permit is still decided locally (no gate call)');

  // Pure offline: there is no gate to park at, so the escalate stays local.
  const offline = createGuard({ api: 'http://stub.local/api/v1', agentDid, agentKey, sealValueActions: false });
  const n = gateCalls.length;
  v = await offline.authorizeLocal({ ...high, amount: 250 });
  check(v.decision === 'escalate' && gateCalls.length === n, `sealValueActions:false: escalate decided locally, no gate call (got ${v.decision}, gate calls +${gateCalls.length - n})`);
} finally {
  globalThis.fetch = originalFetch;
}

if (failed) {
  console.error(`\n${failed} case(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — a local-first escalate reaches the gate, so the owner can see and decide it.');
process.exit(0);

// outdated-gateway.smoke.mjs — an approval resumed through a gateway that predates the approved-context binding (0.34.0;
// pre-beta rerun 6, FW6-1).
//
// Before: the old gateway's claim was refused AUTHORIZATION_CONTEXT_REQUIRED (nothing ran), the tool relayed that refusal,
// and resume() VOIDED the approved hold as "tool did not run". The resume after upgrading the gateway then said
// AUTHORIZATION_ALREADY_USED — wrong (it was voided, never used) — and the owner had to approve the same request again.
// Now the hold is kept, the error says which gateway to upgrade, the issuer re-opens the one resume, and a voided approval is
// reported AUTHORIZATION_VOIDED.
//
//   node outdated-gateway.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildHederaDid } from './magp-did.mjs';
import { createGuard } from './agentsafe-guard.mjs';
import { approvedContextDigest, resumeRequestDigest } from './resume-binding.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const agentDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.702');
const agentKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');

const HOLD = '6429ad2c-39de-4f5c-9123-fb295efbd82f';
const context = { riskLevel: 'high', target: 'record-A', op: 'read' };
const approved = {
  payloadBound: false,
  requestDigest: resumeRequestDigest({ authorizationId: HOLD, action: 'perform-action', amount: null, currency: 'USD', merchant: '', resource: '', payloadDigest: '' }),
  contextDigest: approvedContextDigest(context),
  resumeClaimVersion: 2,
};
const recordArgs = (a) => ({ context: { riskLevel: a.riskLevel, target: a.target, op: a.op } });

/**
 * A fake issuer that behaves like escalation.service.ts claimResume + mandate.service.ts markDispatching: the one resume is
 * taken once, re-opened when a (signed) gateway claim of the still-held hold is refused AUTHORIZATION_CONTEXT_REQUIRED.
 */
function fakeIssuer({ spendStatus = 'held', outcome = 'not_started', resumeDetail } = {}) {
  const state = { resumeTaken: false, reopened: false, voids: 0, claims: 0 };
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    const reply = (data, code = 200) => ({ ok: code < 400, status: code, json: async () => ({ success: code < 400, message: data?.reasonCode, data }) });
    if (u.endsWith('/resume-claim')) {
      state.claims++;
      if (resumeDetail) return reply({ reasonCode: 'AUTHORIZATION_IN_USE', detail: resumeDetail }, 409);
      if (state.resumeTaken && !state.reopened) return reply({ reasonCode: 'AUTHORIZATION_IN_USE' }, 409);
      state.resumeTaken = true;
      state.reopened = false;
      return reply({ claimed: true });
    }
    if (u.includes('/escalations/')) return reply({ escalationId: 'esc-1', status: 'approved', reasonCode: 'ESCALATION_APPROVED', authorizationId: HOLD, ...approved });
    if (u.endsWith('/effect')) return reply({ outcome: state.voids ? 'not_executed' : outcome, effectState: 'authorized', spendStatus: state.voids ? 'voided' : spendStatus, claimed: false });
    if (u.endsWith('/void')) { state.voids++; return reply({ voided: true }); }
    if (u.endsWith('/capture')) return reply({ captured: true });
    return reply({}, 404);
  };
  return { state, restore: () => { globalThis.fetch = real; } };
}

/** A gateway as a tool sees it: `outdated` refuses (and the issuer re-opens the resume), an upgraded one runs the call. */
function gatewayTool(issuer, gateway) {
  return async () => {
    if (gateway.outdated) {
      issuer.state.reopened = issuer.state.resumeTaken; // the issuer's reopenResume() on the refused, signed claim
      const e = new Error('gateway 403: AUTHORIZATION_CONTEXT_REQUIRED');
      e.name = 'GovernanceBlocked';
      e.governance = { decision: 'block', reasonCode: 'AUTHORIZATION_CONTEXT_REQUIRED' };
      throw e;
    }
    gateway.ran++;
    return { done: true };
  };
}

const guard = createGuard({ api: 'http://issuer.test/api/v1', agentDid, agentKey, mode: 'remote' });

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`ok    ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.stack ?? e.message}`); }
}
const quietly = async (fn) => {
  const warn = console.warn;
  const lines = [];
  console.warn = (...a) => lines.push(a.join(' '));
  try { return { value: await fn(), lines }; } finally { console.warn = warn; }
};

await check('the reproduced defect: an outdated gateway refuses — the approved hold is NOT voided, and the error names the upgrade', async () => {
  const issuer = fakeIssuer();
  const gateway = { outdated: true, ran: 0 };
  try {
    const tool = guard.guardTool('perform-action', gatewayTool(issuer, gateway), recordArgs);
    const { value: err, lines } = await quietly(() => tool.resume('esc-1', context, { timeoutMs: 1000 }).then(() => null, (e) => e));
    assert.equal(err?.governance?.reasonCode, 'AUTHORIZATION_CONTEXT_REQUIRED');
    assert.equal(issuer.state.voids, 0, 'the hold is kept');
    assert.equal(err.upgradeRequired, true);
    assert.equal(err.holdKept, true);
    assert.match(err.message, /agentsafe-mcp-guard >= 0\.27\.0/);
    assert.match(err.message, /agentsafe-http-gateway >= 0\.26\.0/);
    assert.match(err.detail, /resume\(\) again/);
    assert.ok(lines.some((l) => l.includes('AUTHORIZATION_CONTEXT_REQUIRED') && l.includes('Upgrade')), 'one log line says it');
  } finally { issuer.restore(); }
});

await check('after the gateway is upgraded, resume() runs the approval — once — with no re-approval', async () => {
  const issuer = fakeIssuer();
  const gateway = { outdated: true, ran: 0 };
  try {
    const tool = guard.guardTool('perform-action', gatewayTool(issuer, gateway), recordArgs);
    await quietly(() => tool.resume('esc-1', context, { timeoutMs: 1000 }).catch(() => {}));
    gateway.outdated = false;
    const out = await tool.resume('esc-1', context, { timeoutMs: 1000 });
    assert.deepEqual(out, { done: true });
    assert.equal(gateway.ran, 1);
    // ...and it is not handed out a third time: the re-opening was used up.
    const third = await tool.resume('esc-1', context, { timeoutMs: 1000 }).then(() => null, (e) => e);
    assert.equal(third?.governance?.reasonCode, 'AUTHORIZATION_IN_USE');
    assert.equal(gateway.ran, 1);
  } finally { issuer.restore(); }
});

await check('a relayed gateway detail is kept on the error', async () => {
  const issuer = fakeIssuer();
  try {
    const tool = guard.guardTool('perform-action', async () => {
      const e = new Error('gateway 403');
      e.name = 'GovernanceBlocked';
      e.governance = { decision: 'block', reasonCode: 'AUTHORIZATION_CONTEXT_REQUIRED', detail: 'AUTHORIZATION_CONTEXT_REQUIRED: upgrade the gateway (issuer detail)' };
      throw e;
    }, recordArgs);
    const { value: err } = await quietly(() => tool.resume('esc-1', context, { timeoutMs: 1000 }).then(() => null, (e) => e));
    assert.equal(err.detail, 'AUTHORIZATION_CONTEXT_REQUIRED: upgrade the gateway (issuer detail)');
    assert.equal(issuer.state.voids, 0);
  } finally { issuer.restore(); }
});

await check('a plain error carrying the code (reasonCode field) keeps the hold too', async () => {
  const issuer = fakeIssuer();
  try {
    const tool = guard.guardTool('perform-action', async () => { const e = new Error('gateway 403'); e.reasonCode = 'AUTHORIZATION_CONTEXT_REQUIRED'; e.nothingExecuted = true; throw e; }, recordArgs);
    const { value: err } = await quietly(() => tool.resume('esc-1', context, { timeoutMs: 1000 }).then(() => null, (e) => e));
    assert.equal(err.upgradeRequired, true);
    assert.equal(issuer.state.voids, 0);
  } finally { issuer.restore(); }
});

await check('any other downstream refusal still releases the hold (unchanged)', async () => {
  const issuer = fakeIssuer();
  try {
    const tool = guard.guardTool('perform-action', async () => { const e = new Error('gateway 403'); e.name = 'GovernanceBlocked'; e.governance = { decision: 'block', reasonCode: 'AGENT_NOT_ADMITTED' }; throw e; }, recordArgs);
    const err = await tool.resume('esc-1', context, { timeoutMs: 1000 }).then(() => null, (e) => e);
    assert.equal(err?.governance?.reasonCode, 'AGENT_NOT_ADMITTED');
    assert.equal(issuer.state.voids, 1);
    assert.equal(err.upgradeRequired, undefined);
  } finally { issuer.restore(); }
});

await check('a resume of an approval whose hold was voided says AUTHORIZATION_VOIDED (re-approve), not AUTHORIZATION_ALREADY_USED', async () => {
  const issuer = fakeIssuer({ spendStatus: 'voided', outcome: 'not_executed' });
  const ran = [];
  try {
    const tool = guard.guardTool('perform-action', async () => { ran.push(1); return {}; }, recordArgs);
    const err = await tool.resume('esc-1', context, { timeoutMs: 1000 }).then(() => null, (e) => e);
    assert.equal(err?.governance?.reasonCode, 'AUTHORIZATION_VOIDED');
    assert.match(err.message, /owner must approve the request again/);
    assert.equal(ran.length, 0);
    assert.equal(issuer.state.claims, 0, 'the one resume is not touched');
  } finally { issuer.restore(); }
});

await check('a settled approval is still AUTHORIZATION_ALREADY_USED', async () => {
  const issuer = fakeIssuer({ spendStatus: 'captured', outcome: 'settled' });
  try {
    const tool = guard.guardTool('perform-action', async () => ({}), recordArgs);
    const err = await tool.resume('esc-1', context, { timeoutMs: 1000 }).then(() => null, (e) => e);
    assert.equal(err?.governance?.reasonCode, 'AUTHORIZATION_ALREADY_USED');
  } finally { issuer.restore(); }
});

await check("the issuer's detail on a refused resume claim is on the error", async () => {
  const issuer = fakeIssuer({ resumeDetail: 'AUTHORIZATION_IN_USE: another process took it' });
  try {
    const tool = guard.guardTool('perform-action', async () => ({}), recordArgs);
    const err = await tool.resume('esc-1', context, { timeoutMs: 1000 }).then(() => null, (e) => e);
    assert.equal(err?.governance?.reasonCode, 'AUTHORIZATION_IN_USE');
    assert.match(err.message, /another process took it/);
  } finally { issuer.restore(); }
});

if (failed) { console.log(`\n${failed} FAILED`); process.exit(1); }
console.log('\nPASS outdated-gateway');

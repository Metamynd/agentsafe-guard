// hold-settlement.smoke.mjs — what guardTool() does with the hold an allowed call was granted, guard.void(), and
// resuming an approved escalation (0.21.0; pre-beta rerun 3, D-1/D-2/D-3/E-1).
//
// Before: an unclaimed hold lapsed with its TTL whatever happened — a tool that RAN handed its budget back after 15
// minutes, a tool that FAILED kept it reserved until then — and the only documented way to release one (a raw unsigned
// void POST) is refused COUNTERPARTY_AUTH_REQUIRED for any owner with a registered gateway.
//
//   node hold-settlement.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAgentSettleMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createGuard } from './agentsafe-guard.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const agentDid = buildHederaDid('testnet', spki.subarray(spki.length - 32), '0.0.701');
const agentKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
const verifies = (message, sigHex) => crypto.verify(null, Buffer.from(message, 'utf8'), publicKey, Buffer.from(sigHex, 'hex'));

/** A fake issuer: authorize allows (or escalates) with a fresh authorizationId; settlement calls are recorded. */
function fakeIssuer({ decision = 'allow', escalation = [] } = {}) {
  const calls = [];
  const statuses = [...escalation];
  const outcomes = new Map(); // authorizationId -> outcome, as GET .../effect reports it
  const idOf = (u) => decodeURIComponent(u.split('/authorize/')[1].split('/')[0]);
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url: u, body });
    const reply = (data, status = 200) => ({ ok: status < 400, status, json: async () => ({ success: status < 400, data }) });
    if (u.endsWith('/policy/mandate/authorize')) {
      return decision === 'allow'
        ? reply({ decision: 'allow', reasonCode: 'AUTHORIZED', authorizationId: crypto.randomUUID(), eventId: 'e1' })
        : reply({ decision: 'escalate', reasonCode: 'RISK_REVIEW', escalationId: 'esc-1', authorizationId: null }, 403);
    }
    if (u.includes('/escalations/')) return reply(statuses.length > 1 ? statuses.shift() : statuses[0]);
    if (u.endsWith('/void')) { outcomes.set(idOf(u), 'not_executed'); return reply({ voided: true, reasonCode: 'HOLD_VOIDED' }); }
    if (u.endsWith('/capture')) { outcomes.set(idOf(u), 'settled'); return reply({ captured: true }); }
    if (u.endsWith('/effect')) return reply({ outcome: outcomes.get(idOf(u)) ?? 'not_started', effectState: 'authorized' });
    return reply({}, 404);
  };
  return { calls, outcomes, restore: () => { globalThis.fetch = real; } };
}
const settlements = (calls) => calls.filter((c) => /\/(capture|void)$/.test(c.url)).map((c) => c.url.split('/').pop());

const guard = createGuard({ api: 'http://issuer.test/api/v1', agentDid, agentKey, mode: 'remote' });
const mapArgs = (a) => ({ amount: a.amount, currency: 'USD', merchant: 'skyward-air', context: { riskLevel: a.riskLevel ?? 'low' } });

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`ok    ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.stack ?? e.message}`); }
}

await check('a tool that RAN has its hold captured at the authorized amount, signed as the agent', async () => {
  const f = fakeIssuer();
  try {
    const out = await guard.guardTool('flight-purchase', async (a) => ({ pnr: 'PNR-1', ...a }), mapArgs)({ amount: 120 });
    assert.equal(out.pnr, 'PNR-1');
    const cap = f.calls.find((c) => c.url.endsWith('/capture'));
    assert.ok(cap, 'captured');
    assert.equal(cap.body.amountCharged, 120);
    const p = cap.body.agentProof;
    const authId = decodeURIComponent(cap.url.split('/authorize/')[1].split('/')[0]);
    assert.ok(verifies(buildAgentSettleMessage({ verb: 'capture', agentDid, authorizationId: authId, nonce: p.nonce, issuedAt: p.issuedAt, fields: ['120', '', ''] }), p.signature));
  } finally { f.restore(); }
});

// FW6-4 (0.33.1): a call with no amount that the gate decided (remote mode) still got a hold. Nothing settled it, so it sat
// `held` until its TTL and then read as `expired` — an action that never ran. It ran: captured at 0, signed as the agent.
await check('a call with no amount that RAN has its hold captured at 0', async () => {
  const f = fakeIssuer();
  try {
    const nfArgs = (a) => ({ context: { riskLevel: 'low', target: a.target, op: 'read' } });
    const out = await guard.guardTool('records.read', async (a) => ({ read: a.target }), nfArgs)({ target: 'record-A' });
    assert.equal(out.read, 'record-A');
    const cap = f.calls.find((c) => c.url.endsWith('/capture'));
    assert.ok(cap, 'captured');
    assert.equal(cap.body.amountCharged, 0);
    const p = cap.body.agentProof;
    const authId = decodeURIComponent(cap.url.split('/authorize/')[1].split('/')[0]);
    assert.ok(verifies(buildAgentSettleMessage({ verb: 'capture', agentDid, authorizationId: authId, nonce: p.nonce, issuedAt: p.issuedAt, fields: ['0', '', ''] }), p.signature));
    await guard.guardTool('records.read', async () => 'ok', nfArgs, { settle: 'none' })({ target: 'record-B' });
    assert.deepEqual(settlements(f.calls), ['capture'], "settle: 'none' still opts out");
  } finally { f.restore(); }
});

// F-3 (0.27.0): a hold the tool's gateway CLAIMED is the gateway's to settle. The agent capturing it too raced the gateway's
// own settlement — the agent's full-amount capture landed first, recorded `unattested`, and the gateway's real charge was refused.
for (const [label, effect] of [
  ['claimed by the gateway that ran the tool', { outcome: 'in_flight', effectState: 'dispatching', claimed: true }],
  ['already settled by the gateway', { outcome: 'settled', effectState: 'succeeded', claimed: true }],
]) {
  await check(`a hold ${label} is left to the gateway: no agent capture`, async () => {
    const f = fakeIssuer();
    const real = globalThis.fetch;
    globalThis.fetch = async (url, init) => (String(url).endsWith('/effect') ? { ok: true, status: 200, json: async () => ({ success: true, data: effect }) } : real(url, init));
    try {
      const out = await guard.guardTool('flight-purchase', async () => ({ pnr: 'PNR-GW' }), mapArgs)({ amount: 120 });
      assert.equal(out.pnr, 'PNR-GW');
      assert.deepEqual(settlements(f.calls), [], 'the agent settled nothing');
    } finally { globalThis.fetch = real; f.restore(); }
  });
}

await check('when the gate cannot say whether the hold was claimed, the agent still captures (counting the spend is the safe side)', async () => {
  const f = fakeIssuer();
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).endsWith('/effect')) throw new TypeError('fetch failed');
    return real(url, init);
  };
  try {
    await guard.guardTool('flight-purchase', async () => ({ ok: true }), mapArgs)({ amount: 120 });
    assert.deepEqual(settlements(f.calls), ['capture']);
  } finally { globalThis.fetch = real; f.restore(); }
});

await check("settle: 'none' leaves the hold to whoever settles it", async () => {
  const f = fakeIssuer();
  try {
    await guard.guardTool('flight-purchase', async () => ({ ok: true }), mapArgs, { settle: 'none' })({ amount: 120 });
    assert.deepEqual(settlements(f.calls), []);
  } finally { f.restore(); }
});

await check('a capture the issuer refuses (a gateway already settled it) never changes the tool\'s result', async () => {
  const f = fakeIssuer();
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => (String(url).endsWith('/capture') ? Promise.reject(new Error('boom')) : real(url, init));
  try {
    const out = await guard.guardTool('flight-purchase', async () => ({ pnr: 'PNR-2' }), mapArgs)({ amount: 50 });
    assert.equal(out.pnr, 'PNR-2');
  } finally { globalThis.fetch = real; f.restore(); }
});

await check('a downstream refusal (GovernanceBlocked from the tool) releases the hold, signed, and still throws', async () => {
  const f = fakeIssuer();
  try {
    const refusedDownstream = async () => { const e = new Error('gateway 403'); e.name = 'GovernanceBlocked'; e.governance = { decision: 'block', reasonCode: 'AGENT_NOT_ADMITTED' }; throw e; };
    await assert.rejects(() => guard.guardTool('flight-purchase', refusedDownstream, mapArgs)({ amount: 80 }), /gateway 403/);
    assert.deepEqual(settlements(f.calls), ['void']);
    const v = f.calls.find((c) => c.url.endsWith('/void'));
    assert.equal(v.body.reason, 'tool did not run: AGENT_NOT_ADMITTED');
    const authId = decodeURIComponent(v.url.split('/authorize/')[1].split('/')[0]);
    assert.ok(verifies(buildAgentSettleMessage({ verb: 'void', agentDid, authorizationId: authId, nonce: v.body.agentProof.nonce, issuedAt: v.body.agentProof.issuedAt, fields: [v.body.reason] }), v.body.agentProof.signature));
  } finally { f.restore(); }
});

await check('an error marked nothingExecuted releases the hold; any OTHER error keeps it (the tool may have acted)', async () => {
  const f = fakeIssuer();
  try {
    const safe = async () => { throw Object.assign(new Error('validation failed before the call'), { nothingExecuted: true }); };
    await assert.rejects(() => guard.guardTool('flight-purchase', safe, mapArgs)({ amount: 10 }));
    assert.deepEqual(settlements(f.calls), ['void']);
    f.calls.length = 0;
    const unknown = async () => { throw new Error('socket hang up'); };
    await assert.rejects(() => guard.guardTool('flight-purchase', unknown, mapArgs)({ amount: 10 }), /socket hang up/);
    assert.deepEqual(settlements(f.calls), [], 'neither captured nor released');
  } finally { f.restore(); }
});

await check('releaseOnError opts in: true, or a predicate over the error', async () => {
  const f = fakeIssuer();
  try {
    const boom = async () => { throw Object.assign(new Error('upstream 422'), { status: 422 }); };
    await assert.rejects(() => guard.guardTool('flight-purchase', boom, mapArgs, { releaseOnError: (e) => e.status === 422 })({ amount: 10 }));
    await assert.rejects(() => guard.guardTool('flight-purchase', boom, mapArgs, { releaseOnError: (e) => e.status === 400 })({ amount: 10 }));
    await assert.rejects(() => guard.guardTool('flight-purchase', boom, mapArgs, { releaseOnError: true })({ amount: 10 }));
    assert.deepEqual(settlements(f.calls), ['void', 'void']);
  } finally { f.restore(); }
});

await check('guard.void() signs as the agent and reports the issuer\'s answer; it never throws', async () => {
  const f = fakeIssuer();
  try {
    const r = await guard.void('auth-9', 'not needed');
    assert.equal(r.voided, true);
    assert.equal(f.calls[0].body.reason, 'not needed');
    assert.ok(f.calls[0].body.agentProof?.signature);
  } finally { f.restore(); }
  const real = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('ECONNREFUSED'); };
  try {
    const r = await guard.void('auth-9');
    assert.deepEqual([r.voided, r.reasonCode], [false, 'GATE_UNREACHABLE']);
  } finally { globalThis.fetch = real; }
});

await check('.resume() waits for the approval, then runs the tool ONCE with the minted authorization and settles it', async () => {
  const f = fakeIssuer({ decision: 'escalate', escalation: [{ status: 'pending' }, { status: 'approved', reasonCode: 'ESCALATION_APPROVED', authorizationId: 'auth-approved' }] });
  try {
    const seen = [];
    const tool = guard.guardTool('flight-purchase', async (a, d) => { seen.push(d.authorizationId); return { pnr: 'PNR-R' }; }, mapArgs);
    const err = await tool({ amount: 900, riskLevel: 'high' }).catch((e) => e);
    assert.equal(err.governance?.decision, 'escalate');
    assert.deepEqual(seen, [], 'nothing ran while held');
    const out = await tool.resume(err.governance.escalationId, { amount: 900, riskLevel: 'high' }, { intervalMs: 10 });
    assert.equal(out.pnr, 'PNR-R');
    assert.deepEqual(seen, ['auth-approved']);
    assert.ok(f.calls.some((c) => c.url.endsWith('/authorize/auth-approved/capture')), 'the approved hold is captured');
  } finally { f.restore(); }
});

await check('a second .resume() of the same approved escalation is refused AUTHORIZATION_ALREADY_USED and never re-runs the tool', async () => {
  const f = fakeIssuer({ escalation: [{ status: 'approved', reasonCode: 'ESCALATION_APPROVED', authorizationId: 'auth-once' }] });
  try {
    let runs = 0;
    const tool = guard.guardTool('flight-purchase', async () => { runs++; return { pnr: 'ONCE' }; }, mapArgs);
    await tool.resume('esc-1', { amount: 40 }, { intervalMs: 10 });
    const err = await tool.resume('esc-1', { amount: 40 }, { intervalMs: 10 }).catch((e) => e);
    assert.equal(err.governance?.reasonCode, 'AUTHORIZATION_ALREADY_USED');
    assert.equal(runs, 1);
  } finally { f.restore(); }
});

// Pre-beta rerun 6 (resume-status nit): an in-process resume of an action that spends nothing used to leave its hold unsettled,
// so a repeat resume reached the issuer's claim and was told AUTHORIZATION_IN_USE. Since 0.33.1 (FW6-4) the hold is settled
// at 0 once the tool ran, and the repeat is AUTHORIZATION_ALREADY_USED without a claim.
await check('a resume of an action that spends nothing settles its hold at 0, so a repeat resume is AUTHORIZATION_ALREADY_USED', async () => {
  const f = fakeIssuer({ escalation: [{ status: 'approved', reasonCode: 'ESCALATION_APPROVED', authorizationId: 'auth-nf' }] });
  try {
    let runs = 0;
    const perms = guard.guardTool('permissions.update', async () => { runs++; return { ok: true }; }, (a) => ({ context: { riskLevel: 'high', target: a.target } }));
    await perms.resume('esc-1', { target: 'record-A' }, { intervalMs: 10 });
    const cap = f.calls.find((c) => c.url.endsWith('/authorize/auth-nf/capture'));
    assert.ok(cap, 'the hold is captured');
    assert.equal(cap.body.amountCharged, 0);
    const err = await perms.resume('esc-1', { target: 'record-A' }, { intervalMs: 10 }).catch((e) => e);
    assert.equal(err.governance?.reasonCode, 'AUTHORIZATION_ALREADY_USED');
    assert.equal(runs, 1);
  } finally { f.restore(); }
});

await check("a refusal raised by a NESTED guarded call keeps the outer hold (the outer tool may already have acted)", async () => {
  const f = fakeIssuer();
  try {
    const inner = guard.guardTool('permissions.update', async () => ({}), () => ({ context: {} }));
    const real = globalThis.fetch;
    // The inner call is refused by the gate; the outer tool had already "acted" before making it.
    globalThis.fetch = async (url, init) => {
      if (String(url).endsWith('/policy/mandate/authorize') && JSON.parse(init.body).action === 'permissions.update') {
        return { ok: false, status: 403, json: async () => ({ success: false, data: { decision: 'block', reasonCode: 'NO_PERMISSION_FOR_ACTION' } }) };
      }
      return real(url, init);
    };
    try {
      const outer = guard.guardTool('flight-purchase', async () => { /* side effect here */ await inner({}); }, mapArgs);
      const err = await outer({ amount: 30 }).catch((e) => e);
      assert.equal(err.governance?.reasonCode, 'NO_PERMISSION_FOR_ACTION');
      assert.deepEqual(settlements(f.calls), [], 'the outer hold is neither released nor captured');
    } finally { globalThis.fetch = real; }
  } finally { f.restore(); }
});

await check('a capture that cannot reach the gate is retried, so a tool that ran still has its spend counted', async () => {
  const f = fakeIssuer();
  const real = globalThis.fetch;
  let attempts = 0;
  globalThis.fetch = async (url, init) => {
    if (String(url).endsWith('/capture') && ++attempts < 3) throw new Error('ECONNRESET');
    return real(url, init);
  };
  try {
    await guard.guardTool('flight-purchase', async () => ({ ok: 1 }), mapArgs)({ amount: 20 });
    assert.equal(attempts, 3);
    assert.ok([...f.outcomes.values()].includes('settled'));
  } finally { globalThis.fetch = real; f.restore(); }
});

await check('a concurrent .resume() of the same escalation in this process is refused AUTHORIZATION_IN_USE (0.22.0)', async () => {
  const f = fakeIssuer({ escalation: [{ status: 'approved', reasonCode: 'ESCALATION_APPROVED', authorizationId: 'auth-race' }] });
  try {
    let runs = 0; let letGo;
    const gate = new Promise((r) => { letGo = r; });
    const tool = guard.guardTool('flight-purchase', async () => { runs++; await gate; return { pnr: 'RACE' }; }, mapArgs);
    const first = tool.resume('esc-1', { amount: 15 }, { intervalMs: 10 });
    await new Promise((r) => setTimeout(r, 50)); // the first is inside the tool now
    const err = await tool.resume('esc-1', { amount: 15 }, { intervalMs: 10 }).catch((e) => e);
    assert.equal(err.governance?.reasonCode, 'AUTHORIZATION_IN_USE');
    letGo();
    assert.equal((await first).pnr, 'RACE');
    assert.equal(runs, 1);
  } finally { f.restore(); }
});

await check('an authorize whose answer never arrived: the hold the gate minted anyway is found by nonce and released (0.22.0)', async () => {
  const calls = [];
  const real = globalThis.fetch;
  let sentNonce;
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    calls.push(u);
    if (u.endsWith('/policy/mandate/authorize')) { sentNonce = JSON.parse(init.body).nonce; throw new Error('socket hang up'); } // sent; answer lost
    if (u.includes('/authorize/by-request?')) {
      assert.ok(u.includes(`nonce=${encodeURIComponent(sentNonce)}`) && u.includes(`agentDid=${encodeURIComponent(agentDid)}`));
      return { ok: true, status: 200, json: async () => ({ success: true, data: { authorizationId: 'auth-orphan' } }) };
    }
    if (u.endsWith('/authorize/auth-orphan/void')) return { ok: true, status: 200, json: async () => ({ success: true, data: { voided: true, reasonCode: 'HOLD_VOIDED' } }) };
    throw new Error('unexpected ' + u);
  };
  try {
    const g = createGuard({ api: 'http://issuer.test/api/v1', agentDid, agentKey, mode: 'remote', orphanReleaseDelaysMs: [20] });
    const d = await g.authorize({ action: 'flight-purchase', amount: 10, currency: 'USD', merchant: 'skyward-air', context: { riskLevel: 'low' } });
    assert.equal(d.reasonCode, 'GATE_UNREACHABLE');
    await new Promise((r) => setTimeout(r, 150));
    assert.ok(calls.some((u) => u.endsWith('/authorize/auth-orphan/void')), 'the orphaned hold was released');
  } finally { globalThis.fetch = real; }
});

await check('orphanReleaseDelaysMs: [] turns the orphan release off', async () => {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => { calls.push(String(url)); throw new Error('ECONNRESET'); };
  try {
    const off = createGuard({ api: 'http://issuer.test/api/v1', agentDid, agentKey, mode: 'remote', orphanReleaseDelaysMs: [] });
    await off.authorize({ action: 'flight-purchase', amount: 10, currency: 'USD', merchant: 'skyward-air', context: { riskLevel: 'low' } });
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(calls.filter((u) => u.includes('by-request')).length, 0);
  } finally { globalThis.fetch = real; }
});

await check('.resume() of a rejected, or still-pending, escalation throws and never runs the tool', async () => {
  for (const [st, decision] of [[{ status: 'denied', reasonCode: 'ESCALATION_DENIED' }, 'block'], [{ status: 'pending' }, 'escalate']]) {
    const f = fakeIssuer({ escalation: [st] });
    try {
      let ran = false;
      const tool = guard.guardTool('flight-purchase', async () => { ran = true; }, mapArgs);
      const err = await tool.resume('esc-1', { amount: 1 }, { timeoutMs: 30, intervalMs: 10 }).catch((e) => e);
      assert.equal(err.name, 'GovernanceBlocked');
      assert.equal(err.governance.decision, decision);
      assert.equal(ran, false);
    } finally { f.restore(); }
  }
});

if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log('\nPASS — guardTool settles its holds, guard.void() releases one signed, and an approved escalation resumes once.');

// effect-unknown-deprecated.smoke.mjs — guard.effectUnknown() is deprecated: since 2026-09-24 the gate accepts
// `effect/unknown` only from the party that claimed the hold, the hold's owner or an admin, and an agent is none of
// them, so the old call was refused every time. It is still exported (existing imports keep working) but now fails
// fast locally, with an error that says who can report UNKNOWN instead — and it never reaches the network.
//
//   node effect-unknown-deprecated.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import { createGuard } from './agentsafe-guard.mjs';

let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log(`  PASS  ${name}`); }
  catch (e) { failed++; console.log(`  FAIL  ${name}\n        ${e.message}`); }
}

const guard = createGuard({
  api: 'https://gate.example/api/v1',
  agentDid: 'did:hedera:testnet:zX_0.0.1',
  agentKey: '302e020100300506032b657004220420' + '11'.repeat(32),
});

const calls = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  calls.push(String(url));
  return { ok: true, status: 200, json: async () => ({ success: true, data: { effectState: 'dispatched' } }) };
};

try {
  await check('effectUnknown is still exported on the guard (no import breaks)', async () => {
    assert.equal(typeof guard.effectUnknown, 'function');
  });

  await check('effectUnknown rejects with a named, coded error that says who may report UNKNOWN', async () => {
    let err;
    try { await guard.effectUnknown('auth-1', 'timeout'); } catch (e) { err = e; }
    assert.ok(err, 'rejected');
    assert.equal(err.name, 'EffectUnknownNotSupported');
    assert.equal(err.code, 'EFFECT_UNKNOWN_AGENT_UNSUPPORTED');
    assert.equal(err.authorizationId, 'auth-1');
    assert.match(err.message, /deprecated/);
    assert.match(err.message, /markAuthorizationUnknown/);
    assert.match(err.message, /claimToken/);
    assert.match(err.message, /owner/);
  });

  await check('it is a rejected promise, not a synchronous throw (await-able like before)', async () => {
    const p = guard.effectUnknown('auth-1');
    assert.ok(p instanceof Promise);
    await assert.rejects(p, { code: 'EFFECT_UNKNOWN_AGENT_UNSUPPORTED' });
  });

  await check('it never calls the gate', async () => {
    assert.ok(!calls.some((u) => u.includes('/effect/unknown')), `no effect/unknown request (saw: ${calls.join(', ') || 'none'})`);
  });

  await check('the other effect helpers are unchanged', async () => {
    const before = calls.length;
    await guard.effectDispatched('auth-1', 'PNR1');
    await guard.effectStatus('auth-1');
    assert.equal(calls.length, before + 2);
    assert.ok(calls.at(-2).endsWith('/policy/mandate/authorize/auth-1/effect/dispatched'));
    assert.ok(calls.at(-1).endsWith('/policy/mandate/authorize/auth-1/effect'));
  });
} finally {
  globalThis.fetch = realFetch;
}

if (failed) { console.log(`\nFAIL — ${failed} case(s) failed`); process.exit(1); }
console.log('\nPASS — effectUnknown deprecation smoke');

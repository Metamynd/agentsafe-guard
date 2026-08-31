// decision-token.smoke.mjs — proves the Phase-4 PR-5 additions (SAFR §7a.5/§20):
//   (A) durable settlement anti-reuse via an INJECTED store — reserve BEFORE settle, release on
//       failure (retryable), reuse rejected by the store (not an in-process Set);
//   (B) the commitment-bound capability (decision token) is enforced in the PROD guard's
//       guardIncomingTool — an injected verifier blocks authorize-A/execute-B; absent → opt-in.
//
//   node decision-token.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function mint(topic = '0.0.1') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const raw = spki.subarray(spki.length - 32);
  return {
    did: buildHederaDid('testnet', raw, topic),
    keyHex: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex'),
    sign: (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex'),
  };
}

const agent = mint('0.0.100');
const service = mint('0.0.200');
let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };

// ─── (A) Durable settlement anti-reuse via an injected store ───────────────────────────────
{
  // A fake DURABLE store standing in for the backend /magp/settlement endpoints: reserve is an
  // atomic claim, release frees an unsettled claim, finalize marks it settled.
  const rows = new Map(); // authId -> 'reserved' | 'settled'
  const store = {
    reserve: async (id) => (rows.has(id) ? { ok: false, reasonCode: 'SETTLEMENT_REUSED' } : (rows.set(id, 'reserved'), { ok: true })),
    release: async (id) => { if (rows.get(id) === 'reserved') rows.delete(id); },
    finalize: async (id) => rows.set(id, 'settled'),
  };
  const reserveCalls = [];
  const wrapped = { ...store, reserve: async (id) => { reserveCalls.push(id); return store.reserve(id); } };
  const mcp = createMcpGuard({ serviceDid: service.did, settlementStore: wrapped });

  const authId = crypto.randomUUID();
  const requirements = mcp.requirePayment({ authorizationId: authId, agentDid: agent.did, amount: 150, payTo: '0.0.5005', asset: 'USDC', resource: '/x' });
  const paidAmountMinor = requirements.accepts[0].maxAmountRequired;

  // reserve-before-settle: the store is claimed before the facilitator runs.
  let facilitatorCalled = false;
  const good = await mcp.settle({ requirements, authorizationId: authId, paidAmountMinor, settleFn: async () => { facilitatorCalled = true; return { settled: true, txHash: '0xabc' }; } });
  ok(good.settled && good.txHash === '0xabc', 'durable store: settles the first time', good.reasonCode);
  ok(reserveCalls[0] === authId && facilitatorCalled, 'durable store: reserved BEFORE settling');
  ok(rows.get(authId) === 'settled', 'durable store: finalized to settled');

  // reuse rejected by the STORE (survives restarts, unlike the old in-memory Set).
  const reuse = await mcp.settle({ requirements, authorizationId: authId, paidAmountMinor, settleFn: async () => ({ settled: true, txHash: '0xdef' }) });
  ok(!reuse.settled && reuse.reasonCode === 'SETTLEMENT_REUSED', 'durable store: reuse rejected', reuse.reasonCode);

  // release-on-failure: a failing facilitator frees the claim so a legitimate retry can settle.
  const authId2 = crypto.randomUUID();
  const req2 = mcp.requirePayment({ authorizationId: authId2, agentDid: agent.did, amount: 50, payTo: '0.0.5005', asset: 'USDC', resource: '/x' });
  const paid2 = req2.accepts[0].maxAmountRequired;
  const failFirst = await mcp.settle({ requirements: req2, authorizationId: authId2, paidAmountMinor: paid2, settleFn: async () => { throw new Error('facilitator down'); } });
  ok(!failFirst.settled && failFirst.reasonCode === 'SETTLEMENT_FAILED', 'durable store: facilitator failure fails closed');
  ok(!rows.has(authId2), 'durable store: a failed settle RELEASED the claim (retryable)');
  const retry = await mcp.settle({ requirements: req2, authorizationId: authId2, paidAmountMinor: paid2, settleFn: async () => ({ settled: true, txHash: '0x999' }) });
  ok(retry.settled && retry.txHash === '0x999', 'durable store: retry after release settles');
}

// ─── (B) Commitment-bound capability enforced in the prod guard ─────────────────────────────
{
  const bundle = {
    subject: agent.did,
    mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] } }],
  };
  // Fake verifier standing in for checkCapabilityBinding (tested for real in magp-bind.test.mjs):
  // it accepts only the capability token 'CAP-OK', rejecting anything else as COMMITMENT_MISMATCH.
  const verifyCapability = async (signed) => (signed.capability === 'CAP-OK' ? { ok: true, reasonCode: 'CAPABILITY_BOUND' } : { ok: false, reasonCode: 'COMMITMENT_MISMATCH' });
  const guard = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => bundle, verifyCapability });

  function signed({ capability } = {}) {
    const action = 'flight-purchase', currency = 'USD', merchant = 'amadeus', amount = 100, nonce = crypto.randomUUID(), issuedAt = new Date().toISOString();
    const signature = agent.sign(buildAuthMessage({ agentDid: agent.did, action, amount, currency, merchant, nonce, issuedAt }));
    return { agentDid: agent.did, action, amount, currency, merchant, itinerary: {}, nonce, issuedAt, signature, capability };
  }

  let ran = false;
  const tool = guard.guardIncomingTool('flight-purchase', async () => { ran = true; return { booked: 'PNR' }; });

  // A bound capability → proceeds to the handler.
  ran = false;
  const good = await tool(signed({ capability: 'CAP-OK' }));
  ok(ran && good.booked === 'PNR', 'capability: a bound token proceeds to the tool');

  // A capability that does NOT authorize THIS tx (authorize-A/execute-B) → blocked, handler never runs.
  ran = false;
  let threw = null;
  try { await tool(signed({ capability: 'CAP-FORGED' })); } catch (e) { threw = e; }
  ok(threw && threw.name === 'GovernanceBlocked' && threw.governance.reasonCode === 'COMMITMENT_MISMATCH', 'capability: authorize-A/execute-B is rejected', threw?.governance?.reasonCode);
  ok(ran === false, 'capability: the tool never runs on a mismatch');

  // No capability presented → opt-in, unchanged (governance verdict alone gates).
  ran = false;
  const noCap = await tool(signed({}));
  ok(ran && noCap.booked === 'PNR', 'capability: absent → opt-in (proceeds on the governance verdict)');

  // requireCapability: true flips the omission from opt-in-pass to a hard block — this is the
  // gap a security review found: without this flag, a caller can just drop `capability` and
  // skip the whole check above, verifier configured or not.
  const strictGuard = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => bundle, verifyCapability, requireCapability: true });
  const strictTool = strictGuard.guardIncomingTool('flight-purchase', async () => { ran = true; return { booked: 'PNR' }; });

  ran = false;
  let threw2 = null;
  try { await strictTool(signed({})); } catch (e) { threw2 = e; }
  ok(threw2 && threw2.name === 'GovernanceBlocked' && threw2.governance.reasonCode === 'CAPABILITY_REQUIRED', 'requireCapability: omitting capability is now blocked', threw2?.governance?.reasonCode);
  ok(ran === false, 'requireCapability: the tool never runs when capability is required but missing');

  // A bound capability still proceeds — requireCapability only closes the OMISSION gap, it
  // doesn't change behavior for a caller that already presents one.
  ran = false;
  const strictGood = await strictTool(signed({ capability: 'CAP-OK' }));
  ok(ran && strictGood.booked === 'PNR', 'requireCapability: a bound token still proceeds');
}

// ─── (C) Trustless-mode value-bearing calls warn that stateful floors were skipped ──────────
{
  const bundle = {
    subject: agent.did,
    mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }] }] } }],
  };
  const guard = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => bundle });
  const tool = guard.guardIncomingTool('flight-purchase', async () => ({ booked: 'PNR' }));

  function signed(amount) {
    const action = 'flight-purchase', currency = 'USD', merchant = 'amadeus', nonce = crypto.randomUUID(), issuedAt = new Date().toISOString();
    const signature = agent.sign(buildAuthMessage({ agentDid: agent.did, action, amount, currency, merchant, nonce, issuedAt }));
    return { agentDid: agent.did, action, amount, currency, merchant, itinerary: {}, nonce, issuedAt, signature };
  }

  const originalWarn = console.warn;
  const warnings = [];
  console.warn = (msg) => warnings.push(msg);
  try {
    await tool(signed(100));
    await tool(signed(0));
  } finally {
    console.warn = originalWarn;
  }
  const valueWarnings = warnings.filter((w) => /trustless mode/.test(w));
  ok(valueWarnings.length === 1, 'trustless-mode warning: fires once for the value-bearing call, not the zero-amount one', `${valueWarnings.length} warning(s)`);
}

if (failed === 0) { console.log('\nPASS — durable settlement anti-reuse + prod capability binding'); process.exit(0); }
else { console.error(`\nFAIL — ${failed} check(s) failed`); process.exit(1); }

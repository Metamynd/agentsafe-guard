// execution-adapter.smoke.mjs — proves the ExecutionAdapter seam (SAFR §19, Phase-4 PR-4):
// a PERMITTED action runs LIVE by default, a dry-run adapter SUBSTITUTES the side-effect
// (handler never fires), a per-tool adapter overrides the guard default, the env mode selects
// dry-run, and a BLOCKED action never reaches any adapter.
//
//   node execution-adapter.smoke.mjs
//
// Exits 0 and prints PASS when every case matches; exits 1 on the first mismatch.
import crypto from 'node:crypto';
import { createGuard, liveExecutionAdapter, dryRunExecutionAdapter, executionAdapterFromEnv } from './agentsafe-guard.mjs';

const { privateKey } = crypto.generateKeyPairSync('ed25519');
const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const agentDid = 'did:hedera:testnet:z6MkAdapter_0.0.1';

let failures = 0;
function check(name, cond) {
  if (cond) { console.log(`  ok  ${name}`); } else { console.error(`FAIL  ${name}`); failures++; }
}

// A bundle whose mandate blocks over-cap purchases; a within-cap purchase is allowed.
const bundle = {
  mandate: {
    uid: 'urn:metamynd:mandate:smoke',
    permission: [{ target: 'purchase', action: 'execute', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 500, unit: 'USD' }] }],
  },
};
const mapArgs = (a) => ({ amount: a.amount, merchant: a.merchant, context: {} });

async function main() {
  // 1) Default (live): the real handler runs and its result is returned.
  {
    const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });
    let ran = false;
    const book = guard.guardToolLocal('purchase', async () => { ran = true; return { booked: 'PNR123' }; }, mapArgs, bundle);
    const res = await book({ amount: 100 });
    check('live: handler runs', ran === true);
    check('live: returns the real result', res && res.booked === 'PNR123');
  }

  // 2) Guard-level dry-run adapter: the handler NEVER runs; a describe-only result is returned.
  {
    const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey, executionAdapter: dryRunExecutionAdapter });
    let ran = false;
    const book = guard.guardToolLocal('purchase', async () => { ran = true; return { booked: 'PNR123' }; }, mapArgs, bundle);
    const res = await book({ amount: 100 });
    check('dry-run: handler does NOT run', ran === false);
    check('dry-run: substitutes a describe-only result', res && res.dryRun === true && res.action === 'purchase' && res.decision === 'allow');
  }

  // 3) Per-tool adapter overrides the guard default (guard default live, this tool dry-run).
  {
    const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });
    let ran = false;
    const book = guard.guardToolLocal('purchase', async () => { ran = true; return { booked: 'x' }; }, mapArgs, bundle, { executionAdapter: dryRunExecutionAdapter });
    const res = await book({ amount: 100 });
    check('per-tool override: handler does NOT run', ran === false);
    check('per-tool override: dry-run result', res && res.dryRun === true);
  }

  // 4) A BLOCKED action never reaches the adapter (throws GovernanceBlocked; handler + adapter untouched).
  {
    let adapterCalled = false;
    const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey, executionAdapter: (ctx) => { adapterCalled = true; return ctx.proceed(); } });
    let ran = false;
    const book = guard.guardToolLocal('purchase', async () => { ran = true; return {}; }, mapArgs, bundle);
    let threw = null;
    try { await book({ amount: 9000 }); } catch (e) { threw = e; }
    check('block: throws GovernanceBlocked', threw && threw.name === 'GovernanceBlocked');
    check('block: adapter is never consulted', adapterCalled === false);
    check('block: handler never runs', ran === false);
  }

  // 5) The env resolver selects dry-run from AGENTSAFE_EXECUTION_MODE.
  {
    check('env: dry-run mode → dryRunExecutionAdapter', executionAdapterFromEnv({ AGENTSAFE_EXECUTION_MODE: 'dry-run' }) === dryRunExecutionAdapter);
    check('env: unset → null (caller default live)', executionAdapterFromEnv({}) === null);
    // The live adapter simply proceeds.
    let proceeded = false;
    await liveExecutionAdapter({ proceed: () => { proceeded = true; } });
    check('live adapter: calls proceed', proceeded === true);
  }

  if (failures === 0) { console.log('\nPASS — ExecutionAdapter seam behaves correctly'); process.exit(0); }
  else { console.error(`\nFAIL — ${failures} check(s) failed`); process.exit(1); }
}

main().catch((e) => { console.error('ERROR', e); process.exit(1); });

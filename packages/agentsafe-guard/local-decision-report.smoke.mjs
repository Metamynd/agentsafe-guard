// local-decision-report.smoke.mjs — proves that a local-first guard's own offline
// block/escalate/non-value-allow fires a best-effort, signed report to
// /policy/decisions/local WITHOUT ever awaiting it — the caller's own authorizeLocal()
// call resolves immediately regardless of how long (or whether) that report completes.
//
//   node local-decision-report.smoke.mjs
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';
import { verifyDidSignature, buildHederaDid } from './magp-did.mjs';
import { buildLocalDecisionMessage } from './policy-core.mjs';

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}

async function main() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const agentDid = buildHederaDid('testnet', raw, '0.0.1');

  const bundle = {
    mandates: [{ action: 'vehicle-inspection', document: { uid: 'u', permission: [{ target: 'flight-purchase', action: 'execute', constraint: [] }] } }],
    sops: [],
    standards: [],
  };

  const reportedRequests = [];
  let neverResolvingReportHang = null;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    if (String(url).endsWith('/policy/bundle/' + encodeURIComponent(agentDid)) || String(url).includes('/policy/bundle/')) {
      return { ok: true, json: async () => ({ data: bundle }) };
    }
    if (String(url).endsWith('/policy/decisions/local')) {
      reportedRequests.push(JSON.parse(opts.body));
      // Simulate a slow/never-answering server — proves the caller never waits on this.
      neverResolvingReportHang = new Promise(() => {});
      return neverResolvingReportHang;
    }
    return originalFetch ? originalFetch(url, opts) : { ok: false, json: async () => null };
  };

  const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });

  const startedAt = Date.now();
  // 'vehicle-inspection' has no mandate for this agent's ONLY permission (scoped to
  // flight-purchase) — evaluates locally to a block (NO_PERMISSION_FOR_ACTION), no seal needed.
  const verdict = await guard.authorizeLocal({ action: 'vehicle-inspection', context: {} });
  const elapsedMs = Date.now() - startedAt;

  check(verdict.decision === 'block', `local block decided (got ${verdict.decision}/${verdict.reasonCode})`);
  check(elapsedMs < 500, `authorizeLocal() resolved promptly (${elapsedMs}ms) — did not wait on the report`);

  // The report is fire-and-forget; give the microtask queue a moment to dispatch it.
  await new Promise((r) => setTimeout(r, 50));
  check(reportedRequests.length === 1, `exactly one report attempted (got ${reportedRequests.length})`);

  if (reportedRequests.length === 1) {
    const r = reportedRequests[0];
    check(r.agentDid === agentDid && r.action === 'vehicle-inspection', 'report carries the right agentDid/action');
    check(r.decision === verdict.decision && r.reasonCode === verdict.reasonCode, 'report carries the ACTUAL verdict, not a fabricated one');
    const message = buildLocalDecisionMessage(r);
    check(verifyDidSignature(agentDid, message, r.signature), 'report signature verifies against buildLocalDecisionMessage');
  }

  globalThis.fetch = originalFetch;
  void neverResolvingReportHang; // keep it referenced; nothing awaits it, which is the point

  if (failed) {
    console.error(`\n${failed} case(s) FAILED`);
    process.exit(1);
  }
  console.log('\nPASS — a local-first block/escalate/non-value-allow reports itself for audit visibility, never blocking the caller.');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

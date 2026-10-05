// local-decision-report.smoke.mjs — proves that a local-first guard's own offline
// block/escalate/non-value-allow fires a best-effort, signed report to
// /policy/decisions/local WITHOUT ever awaiting it — the caller's own authorizeLocal()
// call resolves immediately regardless of how long (or whether) that report completes.
//
//   node local-decision-report.smoke.mjs
import crypto from 'node:crypto';
import { createGuard, localReceiptDetailOf } from './agentsafe-guard.mjs';
import { verifyDidSignature, buildHederaDid } from './magp-did.mjs';
import { buildLocalReceiptMessage } from './local-receipt.mjs';
import { buildLocalDecisionMessage } from './policy-core.mjs';
import { payloadDigestOf } from './payload-binding.mjs';

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
    check(r.v === 2, 'it is a v2 receipt (0.26.0): the request detail is bound into the signature');
    check(verifyDidSignature(agentDid, buildLocalReceiptMessage(r), r.signature), 'report signature verifies against buildLocalReceiptMessage');
  }

  // AUD-1: an over-cap refusal decided locally names what was refused: the amount, currency, merchant and payload digest,
  // signed with the verdict, so a tampered amount does not verify.
  reportedRequests.length = 0;
  bundle.mandates[0].action = 'flight-purchase';
  bundle.mandates[0].document.permission[0].constraint = [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 100, unit: 'USD' }];
  const payload = { amount: 500, merchant: 'skyward-air', currency: 'USD' };
  const overCap = await guard.authorizeLocal({ action: 'flight-purchase', amount: 500, currency: 'USD', merchant: 'skyward-air', payload, context: { riskLevel: 'low' } });
  check(overCap.decision === 'block', `over-cap blocked locally (got ${overCap.decision}/${overCap.reasonCode})`);
  await new Promise((r) => setTimeout(r, 50));
  const rc = reportedRequests[0];
  check(rc?.v === 2 && rc.detail?.amount === 500 && rc.detail?.currency === 'USD' && rc.detail?.merchant === 'skyward-air', 'the receipt carries amount 500 USD to skyward-air');
  check(rc?.detail?.payloadDigest === payloadDigestOf(payload), 'and the digest of the payload the agent asked to run');
  check(rc && verifyDidSignature(agentDid, buildLocalReceiptMessage(rc), rc.signature), 'the v2 signature verifies');
  check(rc && !verifyDidSignature(agentDid, buildLocalReceiptMessage({ ...rc, detail: { ...rc.detail, amount: 5 } }), rc.signature), 'a receipt with the amount changed does NOT verify');

  // An issuer that predates v2 strips v/detail and refuses SIGNATURE_INVALID: the guard reports the verdict once more as v1.
  reportedRequests.length = 0;
  globalThis.fetch = async (url, opts) => {
    if (String(url).includes('/policy/bundle/')) return { ok: true, json: async () => ({ data: bundle }) };
    if (String(url).endsWith('/policy/decisions/local')) {
      reportedRequests.push(JSON.parse(opts.body));
      return reportedRequests.length === 1
        ? { ok: false, status: 400, json: async () => ({ success: false, data: { recorded: false, reasonCode: 'SIGNATURE_INVALID' } }) }
        : { ok: true, status: 200, json: async () => ({ success: true, data: { recorded: true, reasonCode: 'ACCEPTED' } }) };
    }
    return { ok: false, json: async () => null };
  };
  await guard.authorizeLocal({ action: 'flight-purchase', amount: 500, currency: 'USD', merchant: 'skyward-air', context: { riskLevel: 'low' } });
  await new Promise((r) => setTimeout(r, 100));
  const [first, second] = reportedRequests;
  check(reportedRequests.length === 2 && first.v === 2 && second.v === undefined && second.detail === undefined, 'refused v2 → one v1 report follows');
  check(second && second.nonce !== first.nonce && verifyDidSignature(agentDid, buildLocalDecisionMessage(second), second.signature), 'the v1 report has its own nonce and a valid v1 signature');

  // A merchant cut to the issuer's 120 never ends in half of a surrogate pair (Postgres refuses a lone surrogate).
  const long = 'a'.repeat(119) + '\u{1F600}';
  const cut = localReceiptDetailOf({ amount: 1, merchant: long }).merchant;
  check(cut.length <= 120 && !/[\uD800-\uDBFF]$/.test(cut), 'a merchant is cut at 120 UTF-16 units without splitting a surrogate pair');

  // N-4 (pre-beta rerun 5): a CONTAINED agent's attempt, refused locally from the bundle's `contained` flag, is reported
  // too (0.31.1) — the containment is the server's state, but that the agent kept trying was recorded nowhere.
  {
    const contained = [];
    globalThis.fetch = async (url, opts) => {
      if (String(url).includes('/policy/bundle/')) return { ok: true, json: async () => ({ data: bundle, contained: { status: 'suspended', reason: 'OWNER' } }) };
      if (String(url).endsWith('/policy/decisions/local')) { contained.push(JSON.parse(opts.body)); return { ok: true, json: async () => ({ data: {} }) }; }
      return { ok: false, json: async () => null };
    };
    const containedGuard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });
    const v = await containedGuard.authorizeLocal({ action: 'flight-purchase', amount: 0, currency: 'USD', context: { riskLevel: 'low' } });
    await new Promise((r) => setTimeout(r, 50));
    check(v.decision === 'suspend' && v.reasonCode === 'AGENT_SUSPENDED', `a contained agent is refused locally (got ${v.decision}/${v.reasonCode})`);
    check(contained.length === 1 && contained[0].decision === 'suspend' && contained[0].reasonCode === 'AGENT_SUSPENDED', 'the refused attempt is reported as suspend/AGENT_SUSPENDED');
    check(contained[0] && verifyDidSignature(agentDid, buildLocalReceiptMessage(contained[0]), contained[0].signature), 'and signed like any other receipt');
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

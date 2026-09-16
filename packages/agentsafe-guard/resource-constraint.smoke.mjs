// resource-constraint.smoke.mjs — proves `resource` (the deferred wiring of
// ResourceService.scopeConstraint() into the mandate's signed-operand set) is genuinely
// part of the SIGNED canonical message end to end through this SDK, the same way
// `merchant` already is — not just carried on the wire. A signature over one resource must
// not verify for another, and omitting `resource` entirely must sign identically to before
// this feature existed (non-regression for the overwhelmingly common non-resource-scoped case).
//
// Also locks in a real bug this same PR's own live testing caught: buildSignedRequest()'s
// bothOmitted (amount AND currency genuinely absent) case used to sign with amount/currency
// left undefined — but the real gate's authMessage() ALWAYS defaults a missing amount/currency
// to 0/'USD' before reconstructing, regardless of the wire body, so that signature could never
// verify against the actual backend. Fixed to sign with the SAME 0/'USD' default authorize()
// and the gate both use, while the wire body still keeps a real omission as a real omission.
//
//   node resource-constraint.smoke.mjs
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';
import { verifyDidSignature, buildHederaDid } from './magp-did.mjs';
import { buildAuthMessage } from './policy-core.mjs';

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
  const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });

  console.log('--- buildSignedRequest with a resource declared (explicit amount/currency, the common case) ---');
  const withResource = await guard.buildSignedRequest({ action: 'vehicle-inspection', amount: 100, currency: 'USD', resource: 'inspection-db', context: {} });
  check(withResource.resource === 'inspection-db', 'the returned object carries the resource field');
  const messageWithResource = buildAuthMessage(withResource);
  check(verifyDidSignature(agentDid, messageWithResource, withResource.signature), 'signature verifies against the message reconstructed from the object (self-consistent)');

  console.log('\n--- a DIFFERENT resource, same everything else, does not verify against the ORIGINAL signature ---');
  // Isolates resource as the ONLY changed variable (same nonce/issuedAt/amount/currency as the
  // signed message) — the property this whole feature exists for: a compromised counterparty
  // swapping the declared resource after signing must be detectable, not a silent no-op.
  const crossMessage = buildAuthMessage({ ...withResource, resource: 'billing-db' });
  check(!verifyDidSignature(agentDid, crossMessage, withResource.signature), 'a signature over one resource does not verify for a different one (tamper detection)');

  console.log('\n--- omitting `resource` entirely (amount/currency still explicit) is unaffected ---');
  const noResource = await guard.buildSignedRequest({ action: 'vehicle-inspection', amount: 100, currency: 'USD', context: {} });
  check(noResource.resource === undefined, 'resource stays genuinely omitted, not defaulted to a fabricated value');
  check(JSON.parse(JSON.stringify(noResource)).resource === undefined, 'JSON.stringify drops the field entirely (legacy wire body, non-regression)');
  check(verifyDidSignature(agentDid, buildAuthMessage(noResource), noResource.signature), 'still verifies via the same buildAuthMessage a pre-resource verifier would reconstruct');

  console.log('\n--- authorize() (not just buildSignedRequest) also signs resource correctly ---');
  // authorize() hits the network — point it at an address nothing listens on and confirm it
  // fails CLOSED (GATE_UNREACHABLE), which still proves the signing step itself ran without
  // throwing for a resource-bearing call.
  const guardUnreachable = createGuard({ api: 'http://127.0.0.1:1/api/v1', agentDid, agentKey });
  const verdict = await guardUnreachable.authorize({ action: 'vehicle-inspection', resource: 'inspection-db', context: {} });
  check(verdict.decision === 'block' && verdict.reasonCode === 'GATE_UNREACHABLE', 'authorize() signs a resource-bearing request without throwing, fails closed when the gate is unreachable');

  console.log('\n--- REGRESSION: buildSignedRequest() with amount/currency BOTH genuinely omitted must verify against the real gate\'s own convention ---');
  // A non-financial action (e.g. resource-scoped, no spend concept at all) — amount/currency
  // are not just falsy, they're not passed AT ALL. This is exactly the case a tester found
  // broken: the client used to sign with amount/currency left undefined, but the backend's
  // authMessage() (mandate.service.ts) unconditionally defaults a missing amount/currency to
  // 0/'USD' before reconstructing — so the OLD signature could never verify against the real
  // gate, only against a hypothetical verifier that (incorrectly) reconstructed from the raw,
  // undefined wire values. Fixed: sign with that same 0/'USD' default, unconditionally.
  const nonFinancial = await guard.buildSignedRequest({ action: 'vehicle-inspection', resource: 'inspection-db', context: {} });
  check(nonFinancial.amount === undefined && nonFinancial.currency === undefined, 'amount/currency stay genuinely omitted on the wire (the whole point of the non-financial fix)');
  const gateReconstruction = buildAuthMessage({ ...nonFinancial, amount: nonFinancial.amount ?? 0, currency: nonFinancial.currency ?? 'USD' });
  check(verifyDidSignature(agentDid, gateReconstruction, nonFinancial.signature), "verifies against the REAL GATE's reconstruction convention (amount??0, currency??'USD') — this is the bug fix");
  // Documents the flip side: a NAIVE reconstruction straight from the wire object's own
  // (genuinely undefined) fields does NOT match — a third-party counterparty applying no
  // convention of its own (today's agentsafe-mcp-guard) would need the same fix to
  // interoperate with a bothOmitted request. A known, flagged follow-up, not a silent gap.
  const naiveReconstruction = buildAuthMessage(nonFinancial);
  check(!verifyDidSignature(agentDid, naiveReconstruction, nonFinancial.signature), 'a NAIVE reconstruction (no 0/USD convention applied) correctly does NOT match — documents the follow-up need in agentsafe-mcp-guard');

  if (failed) {
    console.error(`\n${failed} case(s) FAILED`);
    process.exit(1);
  }
  console.log('\nPASS — resource is a genuine signed field, tamper-detectable, non-regressing when omitted, and buildSignedRequest() now verifies against the real gate even when amount/currency are fully omitted.');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

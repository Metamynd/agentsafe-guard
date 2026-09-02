// context-signature.smoke.mjs — proves the Tier 1 context-claim binding opt-in
// (docs/design/context-claim-binding.md): with signContext:true the guard signs the
// GovernanceEnvelope hash (context included) with the same agent key, the signature
// genuinely verifies against that hash, and it changes when context changes — the
// property the original tester report found missing. Off by default: no network.
//
//   node context-signature.smoke.mjs
//
// Exits 0 and prints PASS when every case matches; exits 1 on the first mismatch.
import crypto from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';
import { envelopeHashFor } from './governance-envelope.mjs';

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const agentKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex');
const agentDid = 'did:hedera:testnet:z6MkSmoke_0.0.2';

function verifies(hash, sigHex) {
  return crypto.verify(null, Buffer.from(hash, 'utf8'), publicKey, Buffer.from(sigHex, 'hex'));
}

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}

// --- default (signContext off): no envelopeSignature at all, wire body unchanged ---
{
  const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey });
  const req = guard.buildSignedRequest({ action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } });
  check(req.envelopeSignature === undefined, 'signContext off (default) → no envelopeSignature field');
  check(!('envelopeSignature' in JSON.parse(JSON.stringify(req))), 'signContext off → JSON.stringify drops the field entirely (legacy wire body)');
}

// --- opt-in: envelopeSignature is present and genuinely verifies ---
{
  const guard = createGuard({ api: 'http://unused.local/api/v1', agentDid, agentKey, signContext: true });
  const request = { action: 'flight-purchase', amount: 100, merchant: 'amadeus', context: { riskLevel: 'low' } };
  const req = guard.buildSignedRequest(request);
  check(typeof req.envelopeSignature === 'string' && req.envelopeSignature.length > 0, 'signContext:true → envelopeSignature present');

  const expectedHash = envelopeHashFor({
    agentDid, action: req.action, amount: req.amount, currency: req.currency, merchant: req.merchant,
    itinerary: req.itinerary, trace: req.trace, materiality: req.materiality, nonce: req.nonce, issuedAt: req.issuedAt,
    signature: '',
  });
  check(verifies(expectedHash, req.envelopeSignature), 'envelopeSignature genuinely verifies against the envelope hash (same key as the action signature)');

  // The exact case the external tester found unsigned: swap context after the fact.
  const tamperedHash = envelopeHashFor({
    agentDid, action: req.action, amount: req.amount, currency: req.currency, merchant: req.merchant,
    itinerary: { riskLevel: 'high' }, trace: req.trace, materiality: req.materiality, nonce: req.nonce, issuedAt: req.issuedAt,
    signature: '',
  });
  check(!verifies(tamperedHash, req.envelopeSignature), 'a context swap after signing fails verification (this is what riskLevel low→high after signing now catches)');

  // Action-subset signature is unaffected — same as always.
  check(typeof req.signature === 'string' && req.signature.length > 0, 'action-subset signature is still present and separate');
}

if (failed) {
  console.error(`\n${failed} case(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — Tier 1 context-claim binding: off by default, opt-in envelope signature verifies and detects context tampering.');

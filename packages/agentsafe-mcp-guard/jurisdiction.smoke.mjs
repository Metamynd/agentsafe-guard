// jurisdiction.smoke.mjs — a Service re-verifies a signed-jurisdiction (v2, MAGP 8.3.12) request and judges jurisdiction
// rules on the SIGNED value only, as the issuer's gate does. The request is built by the real agentsafe-guard
// (cross-package interop, not a hand-rolled signer).
//
//   node jurisdiction.smoke.mjs
import crypto from 'node:crypto';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard, JURISDICTION_REASON_CODES } from './agentsafe-mcp-guard.mjs';
import { createGuard } from '../agentsafe-guard/agentsafe-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { did: buildHederaDid('testnet', spki.subarray(spki.length - 32), topic), keyHex: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex') };
}
const agent = mint('0.0.100');
const service = mint('0.0.200');
const agentGuard = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: agent.did, agentKey: agent.keyHex });

const mandateBundle = {
  subject: agent.did,
  standards: [],
  sops: [],
  mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:jurisdiction', operator: 'isAnyOf', rightOperand: ['DE', 'FR'] }] }] } }],
};
const sopBundle = {
  subject: agent.did,
  standards: [],
  sops: [{ id: 'j', document: { molecules: [{ id: 'j', combinator: 'any', atoms: [{ id: 'a', predicate: 'jurisdiction-not-allowed', config: { allowed: ['SG', 'MY'] } }], decision: 'block', reasonCode: 'SOP_JURISDICTION' }] } }],
  mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [] }] } }],
};
let bundle = mandateBundle;
const svc = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => bundle });

let failed = 0;
const check = (ok, label) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) failed++;
};
const sign = (o) => agentGuard.buildSignedRequest({ action: 'flight-purchase', amount: 10, context: { riskLevel: 'low' }, ...o });
const decide = async (signed, opts) => (await svc.verifyRequest(signed, opts));

// Signature: v2 verifies; stripping / changing / adding the field does not.
bundle = mandateBundle;
const de = await sign({ jurisdiction: 'de' });
check((await decide(de)).decision === 'allow', 'a v2 request (signed DE, on the list) verifies and is allowed');
const { jurisdiction: _j, ...stripped } = de;
check((await decide(stripped)).reasonCode === 'SIGNATURE_INVALID', 'the jurisdiction stripped in transit → SIGNATURE_INVALID (no v1 fallback)');
check((await decide({ ...de, jurisdiction: 'FR' })).reasonCode === 'SIGNATURE_INVALID', 'the jurisdiction changed in transit → SIGNATURE_INVALID');
const plain = await sign({});
check((await decide({ ...plain, jurisdiction: 'DE' })).reasonCode === 'SIGNATURE_INVALID', 'a jurisdiction added to a v1 request → SIGNATURE_INVALID');
check((await decide({ ...de, jurisdiction: 'DEU' })).reasonCode === 'MALFORMED_REQUEST', 'a malformed jurisdiction → MALFORMED_REQUEST');

// The mandate term.
check((await decide(await sign({ jurisdiction: 'SG' }))).reasonCode === 'JURISDICTION_NOT_ALLOWED', 'signed SG (off the list) → JURISDICTION_NOT_ALLOWED');
check((await decide(plain)).reasonCode === 'JURISDICTION_REQUIRED', 'nothing signed under a restricted mandate → JURISDICTION_REQUIRED');
check((await decide(await sign({ context: { riskLevel: 'low', jurisdiction: 'DE', 'mm:jurisdiction': 'DE' } }))).reasonCode === 'JURISDICTION_REQUIRED', 'an itinerary jurisdiction never stands in for a signed one');

// The SOP atom.
bundle = sopBundle;
check((await decide(await sign({ jurisdiction: 'SG' }))).decision === 'allow', 'SOP atom: signed SG → allow');
check((await decide(await sign({ jurisdiction: 'RU' }))).reasonCode === 'SOP_JURISDICTION', 'SOP atom: signed RU → the rule fires');
check((await decide(await sign({}))).reasonCode === 'JURISDICTION_REQUIRED', 'SOP atom enforced, nothing signed → JURISDICTION_REQUIRED');
check((await decide(await sign({ context: { riskLevel: 'low', jurisdiction: 'RU' } }))).reasonCode === 'JURISDICTION_REQUIRED', 'SOP atom: an itinerary RU is never judged');
check((await decide(await sign({}), { trustedContext: { jurisdiction: 'RU' } })).reasonCode === 'SOP_JURISDICTION', "a jurisdiction THIS service derived (trustedContext) is judged by the rule");
check(JURISDICTION_REASON_CODES.includes('JURISDICTION_MISMATCH'), 'the three gate codes are exported');

if (failed) {
  console.error(`\n${failed} check(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — a Service verifies the v2 message and judges jurisdiction on the signed value only.');

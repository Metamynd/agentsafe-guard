// bundle-authentication.smoke.mjs — D-08 (independent pre-beta eval, 2026-09-20; rerun 2026-09-24): a guard with no
// policyPublicKey that fetches its policy bundle over plain http:// trusted whatever came back. A proxy on that path
// dropped the SOP spend cap and a $5,000 over-cap purchase executed. Nothing authenticates such a bundle, so a
// value-bearing action on it is now refused (POLICY_BUNDLE_UNVERIFIED) unless the integrator opts out explicitly.
//
//   node bundle-authentication.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import http from 'node:http';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), topic);
  return { did, sign: (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex') };
}
const agent = mint('0.0.100');
const service = mint('0.0.200');

// What a man-in-the-middle serves: the SOP cap is gone and the mandate allows anything.
const forgedBundle = {
  subject: agent.did,
  standards: [],
  sops: [],
  mandates: [{ action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1e9 }] }] } }],
};

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ success: true, data: forgedBundle }));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const issuerApi = `http://127.0.0.1:${server.address().port}/api/v1`;

function signed(amount) {
  const action = 'flight-purchase';
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const merchant = 'amadeus';
  const signature = agent.sign(buildAuthMessage({ agentDid: agent.did, action, amount, currency: 'USD', merchant, nonce, issuedAt }));
  return { agentDid: agent.did, action, amount, currency: 'USD', merchant, itinerary: { riskLevel: 'low' }, nonce, issuedAt, signature };
}

const warnings = [];
const realWarn = console.warn;
console.warn = (...a) => warnings.push(a.join(' '));

let failed = 0;
const check = (name, ok, detail) => {
  if (!ok) failed++;
  realWarn.call(console, `${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? `  →  ${detail}` : ''}`);
};

try {
  const unpinned = createMcpGuard({ serviceDid: service.did, issuerApi });
  check('an unpinned guard over plain http warns at construction', warnings.some((w) => w.includes('POLICY_BUNDLE_UNVERIFIED')));

  let v = await unpinned.verifyRequest(signed(5000));
  check('THE D-08 ATTACK: $5,000 on a forged bundle over http → refused', v.decision === 'block' && v.reasonCode === 'POLICY_BUNDLE_UNVERIFIED', `${v.decision}/${v.reasonCode}`);

  v = await unpinned.verifyRequest(signed(0));
  check('a non-value action is not refused for it (nothing to protect)', v.reasonCode !== 'POLICY_BUNDLE_UNVERIFIED', `${v.decision}/${v.reasonCode}`);

  warnings.length = 0;
  const optedOut = createMcpGuard({ serviceDid: service.did, issuerApi, allowUnverifiedBundle: true });
  v = await optedOut.verifyRequest(signed(5000));
  check('allowUnverifiedBundle: true restores the old behaviour (explicit, local dev only)', v.reasonCode !== 'POLICY_BUNDLE_UNVERIFIED', `${v.decision}/${v.reasonCode}`);
  check('...and still says so at construction', warnings.some((w) => w.includes('allowUnverifiedBundle is set')));

  warnings.length = 0;
  const custom = createMcpGuard({ serviceDid: service.did, fetchBundle: async () => forgedBundle });
  v = await custom.verifyRequest(signed(5000));
  check('a custom fetchBundle is the integrator\'s own source: not refused by this rule', v.reasonCode !== 'POLICY_BUNDLE_UNVERIFIED', `${v.decision}/${v.reasonCode}`);
  check('...but still warned that nothing pins the bundle', warnings.some((w) => w.includes('no policyPublicKey')));

  warnings.length = 0;
  createMcpGuard({ serviceDid: service.did, issuerApi: 'https://metamynd.ai/api/v1' });
  check('an https issuer with no key is warned about, not refused (TLS authenticates the issuer)', warnings.some((w) => w.includes('TLS alone')) && !warnings.some((w) => w.includes('POLICY_BUNDLE_UNVERIFIED')));
} finally {
  console.warn = realWarn;
  await new Promise((r) => server.close(r));
}

console.log(failed === 0 ? '\n  PASS unauthenticated policy bundles cannot move value' : `\n  ${failed} FAILED`);
process.exitCode = failed === 0 ? 0 : 1;

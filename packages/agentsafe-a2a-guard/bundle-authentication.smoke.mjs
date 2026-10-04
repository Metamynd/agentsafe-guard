// bundle-authentication.smoke.mjs — item 5 of the 2026-10-02 open-items list: an A2A guard with no policyPublicKey that
// fetched its policy bundle over plain http:// trusted whatever came back — for EVERY task, value-bearing included (the MCP
// guard has refused value-bearing ones since 0.12.0, D-08). A proxy on that path can lift a cap or grant an amount-0
// action the agent never had. Since 0.13.3 such a bundle governs nothing: every task is refused POLICY_BUNDLE_UNVERIFIED
// unless the integrator opts out explicitly.
//
//   node bundle-authentication.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import http from 'node:http';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createA2aGuard } from './agentsafe-a2a-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), topic);
  return { did, sign: (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex') };
}
const agent = mint('0.0.920');

// What a man-in-the-middle serves: a mandate the agent never had (permissions.update, amount 0) and no cap on spend.
const forgedBundle = {
  subject: agent.did,
  standards: [],
  sops: [],
  mandates: [
    { action: 'permissions.update', document: { permission: [{ target: 'permissions.update', constraint: [] }] } },
    { action: 'wire-transfer', document: { permission: [{ target: 'wire-transfer', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1e9 }] }] } },
  ],
};

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ success: true, data: forgedBundle }));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const issuerApi = `http://127.0.0.1:${server.address().port}/api/v1`;

function signed(action, amount) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const signature = agent.sign(buildAuthMessage({ agentDid: agent.did, action, amount, currency: 'USD', merchant: '', nonce, issuedAt }));
  return { agentDid: agent.did, action, amount, currency: 'USD', merchant: '', itinerary: { riskLevel: 'low' }, nonce, issuedAt, signature };
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
  const unpinned = createA2aGuard({ allowedAgents: 'any', issuerApi });
  check('an unpinned guard over plain http warns at construction', warnings.some((w) => w.includes('POLICY_BUNDLE_UNVERIFIED')));

  let v = await unpinned.verifyRequest(signed('wire-transfer', 5000));
  check('$5,000 on a forged bundle over http → refused (was ALLOWED: the A2A guard had no D-08 rule)', v.decision === 'block' && v.reasonCode === 'POLICY_BUNDLE_UNVERIFIED', `${v.decision}/${v.reasonCode}`);

  v = await unpinned.verifyRequest(signed('permissions.update', 0));
  check('an amount-0 action the forged bundle granted → refused too', v.decision === 'block' && v.reasonCode === 'POLICY_BUNDLE_UNVERIFIED', `${v.decision}/${v.reasonCode}`);

  warnings.length = 0;
  const optedOut = createA2aGuard({ allowedAgents: 'any', issuerApi, allowUnverifiedBundle: true });
  v = await optedOut.verifyRequest(signed('permissions.update', 0));
  check('allowUnverifiedBundle: true restores the old behaviour (explicit, local dev only)', v.reasonCode !== 'POLICY_BUNDLE_UNVERIFIED', `${v.decision}/${v.reasonCode}`);
  check('...and still says so at construction', warnings.some((w) => w.includes('allowUnverifiedBundle is set')));

  warnings.length = 0;
  const custom = createA2aGuard({ allowedAgents: 'any', fetchBundle: async () => forgedBundle });
  v = await custom.verifyRequest(signed('permissions.update', 0));
  check("a custom fetchBundle is the integrator's own source: not refused by this rule", v.reasonCode !== 'POLICY_BUNDLE_UNVERIFIED', `${v.decision}/${v.reasonCode}`);

  warnings.length = 0;
  createA2aGuard({ allowedAgents: 'any', issuerApi: 'https://metamynd.ai/api/v1' });
  check('an https issuer with no key is warned about, not refused (TLS authenticates the issuer)', warnings.some((w) => w.includes('TLS alone')) && !warnings.some((w) => w.includes('POLICY_BUNDLE_UNVERIFIED')));
} finally {
  console.warn = realWarn;
  await new Promise((r) => server.close(r));
}

console.log(failed === 0 ? '\n  PASS unauthenticated policy bundles govern nothing' : `\n  ${failed} FAILED`);
process.exitCode = failed === 0 ? 0 : 1;

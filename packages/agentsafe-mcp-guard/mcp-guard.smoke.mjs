// mcp-guard.smoke.mjs — proves the MCP-side guard (a) completes the mutual
// handshake (§8.2) and (b) enforces TRUSTLESSLY (§9.6): it re-verifies the agent's
// signed request via key-in-DID and re-evaluates policy against the agent's bundle.
//
//   node mcp-guard.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard, createHandshakeInitiator } from './agentsafe-mcp-guard.mjs';

/** Mint an Ed25519 identity: raw-key-in-DID + a sign() over UTF-8 messages. */
function mint(topic = '0.0.1') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const raw = spki.subarray(spki.length - 32);
  const did = buildHederaDid('testnet', raw, topic);
  const keyHex = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
  const sign = (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex');
  return { did, keyHex, sign };
}

const agent = mint('0.0.100');
const service = mint('0.0.200');

// The agent's issuer-hosted policy bundle (injected here; in prod the guard GETs
// it from /policy/bundle/:did). One enforced Standard, one SOP, one mandate.
const bundle = {
  subject: agent.did,
  standards: [
    {
      key: 'eu-ai-act',
      document: {
        molecules: [
          { id: 'risk', combinator: 'any', atoms: [{ id: 'r', predicate: 'risk-at-or-above', config: { level: 'high' } }], decision: 'escalate', reasonCode: 'RISK_REVIEW' },
        ],
      },
    },
  ],
  sops: [
    {
      id: 'travel',
      document: {
        molecules: [
          { id: 'cap', combinator: 'any', atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 500 } }], decision: 'block', reasonCode: 'SOP_SPEND_CAP' },
        ],
      },
    },
  ],
  mandates: [
    {
      action: 'flight-purchase',
      document: {
        permission: [
          {
            target: 'flight-purchase',
            constraint: [
              { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 },
              { leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: ['amadeus'] },
            ],
          },
        ],
      },
    },
  ],
};

const guard = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => bundle });

/** Build a signed authorize request the way the agent guard would. */
function signedRequest({ amount, currency = 'USD', merchant = 'amadeus', context = {}, issuedAt = new Date().toISOString(), tamper = false }) {
  const action = 'flight-purchase';
  const nonce = crypto.randomUUID();
  const message = buildAuthMessage({ agentDid: agent.did, action, amount, currency, merchant, nonce, issuedAt });
  const signature = tamper ? agent.sign(message + 'x') : agent.sign(message);
  return { agentDid: agent.did, action, amount, currency, merchant, itinerary: context, nonce, issuedAt, signature };
}

let failed = 0;
const check = async (name, req, expect) => {
  const v = await guard.verifyRequest(req);
  const ok = v.decision === expect[0] && v.reasonCode === expect[1];
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}  →  ${v.decision}/${v.reasonCode}`);
};

console.log('— trustless re-evaluation (§9.6) —');
await check('within cap, allowed merchant → allow', signedRequest({ amount: 100 }), ['allow', 'AUTHORIZED']);
await check('SOP cap exceeded → block', signedRequest({ amount: 600 }), ['block', 'SOP_SPEND_CAP']);
await check('high risk → escalate', signedRequest({ amount: 100, context: { riskLevel: 'high' } }), ['escalate', 'RISK_REVIEW']);
await check('disallowed merchant → block', signedRequest({ amount: 100, merchant: 'sabre' }), ['block', 'MERCHANT_NOT_ALLOWED']);
await check('tampered signature → block', signedRequest({ amount: 100, tamper: true }), ['block', 'SIGNATURE_INVALID']);
await check('stale request → block', signedRequest({ amount: 100, issuedAt: new Date(Date.now() - 10 * 60 * 1000).toISOString() }), ['block', 'REQUEST_EXPIRED']);
await check('a few seconds in the future (ordinary clock skew) → allow', signedRequest({ amount: 100, issuedAt: new Date(Date.now() + 10 * 1000).toISOString() }), ['allow', 'AUTHORIZED']);
// Math.abs() used to treat a future issuedAt identically to a past one, accepting a request
// signed up to 5 minutes ahead of server time — not clock skew, a pre-signing window.
await check('minutes in the future → block (was accepted before this was fixed)', signedRequest({ amount: 100, issuedAt: new Date(Date.now() + 4 * 60 * 1000).toISOString() }), ['block', 'REQUEST_EXPIRED']);
await check('forged itinerary cannot shadow signed $600 → block', signedRequest({ amount: 600, context: { 'mm:payAmount': 1 } }), ['block', 'SOP_SPEND_CAP']);

console.log('\n— unit-bearing mandate constraint (currency) —');
{
  // A payAmount/cumulativeSpend constraint issued with a `unit` (currency) is only
  // satisfied in that currency — verdictFromBundle must supply 'mm:currency' (default
  // 'USD') to the evaluator, or a unit-bearing cap fails EVERY request regardless of
  // amount, since undefined never equals a real unit.
  const unitBundle = {
    ...bundle,
    mandates: [
      {
        action: 'flight-purchase',
        document: {
          permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 500, unit: 'USD' }] }],
        },
      },
    ],
  };
  const unitGuard = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => unitBundle });
  const checkUnit = async (name, req, expect) => {
    const v = await unitGuard.verifyRequest(req);
    const ok = v.decision === expect[0] && v.reasonCode === expect[1];
    if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}  →  ${v.decision}/${v.reasonCode}`);
  };
  await checkUnit('within cap, implicit USD → allow', signedRequest({ amount: 100 }), ['allow', 'AUTHORIZED']);
  await checkUnit('within cap, explicit matching USD → allow', signedRequest({ amount: 100, currency: 'USD' }), ['allow', 'AUTHORIZED']);
  await checkUnit('same numeric amount in a DIFFERENT currency → block', signedRequest({ amount: 100, currency: 'JPY' }), ['block', 'SPEND_LIMIT_EXCEEDED']);
}

console.log('\n— operating-mode autonomy ladder at the edge (Phase 2.5b) —');
{
  // The mode rides as a NON-ENUMERABLE sibling (invisible to canonicalization, like
  // __contained), so a mode-carrying guard fetches the same bundle + the flag.
  const withMode = (mode) => createMcpGuard({
    serviceDid: service.did, serviceKey: service.keyHex,
    fetchBundle: async () => { const b = JSON.parse(JSON.stringify(bundle)); Object.defineProperty(b, '__operatingMode', { value: { mode }, enumerable: false }); return b; },
  });
  const checkMode = async (name, mode, req, expect) => {
    const v = await withMode(mode).verifyRequest(req);
    const ok = v.decision === expect[0] && v.reasonCode === expect[1];
    if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}  →  ${v.decision}/${v.reasonCode}`);
  };
  await checkMode('READ_ONLY blocks a value-bearing action', 'read_only', signedRequest({ amount: 100 }), ['block', 'MODE_READ_ONLY']);
  await checkMode('READ_ONLY allows a zero-amount read', 'read_only', signedRequest({ amount: 0 }), ['allow', 'AUTHORIZED']);
  await checkMode('RESTRICTED escalates a value-bearing action', 'restricted', signedRequest({ amount: 100 }), ['escalate', 'MODE_RESTRICTED_REVIEW']);
  await checkMode('SUPERVISED escalates a spend at/above the cap', 'supervised', signedRequest({ amount: 100 }), ['escalate', 'MODE_SUPERVISED_REVIEW']);
  await checkMode('SUPERVISED allows a small spend below the cap', 'supervised', signedRequest({ amount: 10 }), ['allow', 'AUTHORIZED']);
  await checkMode('a mode escalate never downgrades a rule block', 'restricted', signedRequest({ amount: 600 }), ['block', 'SOP_SPEND_CAP']);
}

console.log('\n— mutual handshake (§8.2) —');
{
  const initiator = createHandshakeInitiator({ fromDid: agent.did, sign: agent.sign });
  const { nonceA, message } = initiator.hello();
  const challenge = guard.handshakeChallenge(message); // B signs nonceA
  const prove = initiator.prove({ nonceA, challenge }); // A verifies B, signs nonceB
  const ready = guard.handshakeVerify(prove); // B verifies A
  const ok = !!ready.channelId && ready.remoteDid === agent.did;
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  agent↔service mutual verify → channel ${ready.channelId?.slice(0, 8)}…`);

  // A forged PROVE (wrong key) must be rejected.
  let rejected = false;
  const c2 = guard.handshakeChallenge(initiator.hello().message);
  try {
    guard.handshakeVerify({ handshakeId: c2.handshakeId, sigA: service.sign(c2.nonceB) }); // wrong signer
  } catch (e) {
    rejected = e.name === 'HandshakeFailed';
  }
  if (!rejected) failed++;
  console.log(`${rejected ? 'ok  ' : 'FAIL'}  forged PROVE rejected`);
}

console.log('\n— signed policy bundle: staleness + risk-tiered fail-closed (Phase F, §5.3.2/§5.3.3) —');
{
  const { signBundle, rawPublicKeyHex } = await import('./magp-policy.mjs');
  const issuer = crypto.generateKeyPairSync('ed25519');
  const policyPublicKey = rawPublicKeyHex(issuer.publicKey);
  const withBundle = (b) => createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => b, policyPublicKey });

  const fresh = signBundle({ ...bundle, issuedAt: new Date().toISOString(), maxStaleness: 'PT10M' }, issuer.privateKey);
  const stale = signBundle({ ...bundle, issuedAt: new Date(Date.now() - 11 * 60 * 1000).toISOString(), maxStaleness: 'PT10M' }, issuer.privateKey);
  const tampered = JSON.parse(JSON.stringify(fresh)); tampered.sops[0].document = { molecules: [] }; // loosen after signing
  const unsigned = { ...bundle, issuedAt: new Date().toISOString(), maxStaleness: 'PT10M' };

  const req = signedRequest({ amount: 100 }); // value-bearing (amount > 0)
  const cases = [
    ['fresh signed bundle → allow', fresh, ['allow', 'AUTHORIZED']],
    ['stale bundle, value action → fail closed', stale, ['block', 'POLICY_BUNDLE_STALE']],
    ['tampered bundle → block', tampered, ['block', 'POLICY_BUNDLE_SIGNATURE_INVALID']],
    ['unsigned bundle, value action → fail closed', unsigned, ['block', 'POLICY_BUNDLE_UNSIGNED']],
  ];
  for (const [label, b, [wantDecision, wantReason]] of cases) {
    const v = await withBundle(b).verifyRequest(req);
    const ok = v.decision === wantDecision && v.reasonCode === wantReason;
    if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${label} (${v.decision}/${v.reasonCode})`);
  }
  // A non-value read tolerates a stale bundle (only value-bearing fails closed).
  const readOk = await withBundle(stale).verifyRequest(signedRequest({ amount: 0 }));
  const okRead = readOk.decision !== 'block' || readOk.reasonCode !== 'POLICY_BUNDLE_STALE';
  if (!okRead) failed++;
  console.log(`${okRead ? 'ok  ' : 'FAIL'}  non-value read tolerates a stale bundle`);
}

if (failed) {
  console.error(`\n${failed} case(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — MCP guard verifies trustlessly, enforces signed-bundle freshness, and completes the handshake.');

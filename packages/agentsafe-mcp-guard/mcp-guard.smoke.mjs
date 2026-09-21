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
// An honest client states its risk: the bundle's Standard has a risk rule, and a request that leaves `riskLevel`
// out is escalated, not waved through (see the D-03 section below).
function signedRequest({ amount, currency = 'USD', merchant = 'amadeus', context = { riskLevel: 'low' }, issuedAt = new Date().toISOString(), tamper = false }) {
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
await check('forged itinerary cannot shadow signed $600 → block', signedRequest({ amount: 600, context: { riskLevel: 'low', 'mm:payAmount': 1 } }), ['block', 'SOP_SPEND_CAP']);

console.log('\n— D-03: the agent cannot skip a risk rule by hiding, garbling or understating its risk (spec §6.4.3) —');
{
  await check('OMITTING riskLevel → escalate (was allow)', signedRequest({ amount: 100, context: {} }), ['escalate', 'CONTEXT_UNVERIFIABLE']);
  await check('"HIGH" upper-case is read as high → escalate RISK_REVIEW (was allow)', signedRequest({ amount: 100, context: { riskLevel: 'HIGH' } }), ['escalate', 'RISK_REVIEW']);
  await check('an unrecognised riskLevel → escalate, never "not risky"', signedRequest({ amount: 100, context: { riskLevel: 'banana' } }), ['escalate', 'CONTEXT_UNVERIFIABLE']);
  await check('null riskLevel → escalate', signedRequest({ amount: 100, context: { riskLevel: null } }), ['escalate', 'CONTEXT_UNVERIFIABLE']);

  // The owner classed the action high: it travels in the signed mandate, so the guard applies the same floor.
  const tiered = { ...bundle, mandates: [{ action: 'flight-purchase', document: { permission: [{ ...bundle.mandates[0].document.permission[0], riskTier: 'high' }] } }] };
  const tierGuard = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => tiered });
  const checkTier = async (name, req, expect) => {
    const v = await tierGuard.verifyRequest(req);
    const ok = v.decision === expect[0] && v.reasonCode === expect[1];
    if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}  →  ${v.decision}/${v.reasonCode}`);
  };
  await checkTier('owner tier=high: an agent claiming "low" is still judged high → escalate', signedRequest({ amount: 100, context: { riskLevel: 'low' } }), ['escalate', 'RISK_REVIEW']);
  await checkTier('owner tier=high: an agent that says nothing is judged high too', signedRequest({ amount: 100, context: {} }), ['escalate', 'RISK_REVIEW']);
  await checkTier('owner tier=high: garbage cannot hurt the floor', signedRequest({ amount: 100, context: { riskLevel: 'banana' } }), ['escalate', 'RISK_REVIEW']);

  // What the SERVICE derived from the real call beats the agent's claim, and the agent can only raise it.
  const gwCheck = async (name, req, trustedContext, expect) => {
    const v = await guard.verifyRequest(req, { trustedContext });
    const ok = v.decision === expect[0] && v.reasonCode === expect[1];
    if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}  →  ${v.decision}/${v.reasonCode}`);
  };
  await gwCheck('gateway-derived riskLevel=high beats an agent claim of "low" → escalate', signedRequest({ amount: 100, context: { riskLevel: 'low' } }), { riskLevel: 'high' }, ['escalate', 'RISK_REVIEW']);
  await gwCheck('gateway-derived riskLevel=low supplies the risk when the agent sent none → allow', signedRequest({ amount: 100, context: {} }), { riskLevel: 'low' }, ['allow', 'AUTHORIZED']);
  await gwCheck('the agent may still raise its own risk above the gateway\'s → escalate', signedRequest({ amount: 100, context: { riskLevel: 'high' } }), { riskLevel: 'low' }, ['escalate', 'RISK_REVIEW']);

  // A rule can DEMAND a trusted source: the agent's own honest "low" is then not enough.
  const strict = JSON.parse(JSON.stringify(bundle));
  strict.standards[0].document.molecules[0].requireProvenance = { riskLevel: 'gateway_derived' };
  const strictGuard = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => strict });
  const strictCheck = async (name, req, opts, expect) => {
    const v = await strictGuard.verifyRequest(req, opts);
    const ok = v.decision === expect[0] && v.reasonCode === expect[1];
    if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}  →  ${v.decision}/${v.reasonCode}`);
  };
  await strictCheck('requireProvenance=gateway_derived: an honest agent-only "low" → escalate', signedRequest({ amount: 100, context: { riskLevel: 'low' } }), undefined, ['escalate', 'CONTEXT_UNVERIFIABLE']);
  await strictCheck('requireProvenance=gateway_derived: satisfied by the gateway\'s own derivation → allow', signedRequest({ amount: 100, context: { riskLevel: 'low' } }), { trustedContext: { riskLevel: 'low' } }, ['allow', 'AUTHORIZED']);

  // A trustedContext the Service CONFIGURED but that yields nothing usable means the deriver is broken. That is a
  // refused request — never a quiet fallback to the agent's own word, which is what the deriver was there to avoid.
  for (const [name, bad] of [['riskLevel that is not a level', { riskLevel: 'severe' }], ['riskLevel undefined (a lookup that missed)', { riskLevel: undefined }], ['riskLevel a number', { riskLevel: 7 }], ['null', null], ['an array', ['high']], ['a string', 'high']]) {
    const v = await guard.verifyRequest(signedRequest({ amount: 100, context: { riskLevel: 'low' } }), { trustedContext: bad });
    const good = v.decision === 'block' && v.reasonCode === 'GUARD_ERROR';
    if (!good) failed++;
    console.log(`${good ? 'ok  ' : 'FAIL'}  broken trustedContext (${name}) → refused, not a quiet fallback  →  ${v.decision}/${v.reasonCode}`);
  }
  {
    const empty = await guard.verifyRequest(signedRequest({ amount: 100, context: { riskLevel: 'low' } }), { trustedContext: {} });
    const good = empty.decision === 'allow';
    if (!good) failed++;
    console.log(`${good ? 'ok  ' : 'FAIL'}  an empty trustedContext object is valid (it states nothing; requireProvenance is how a rule insists)  →  ${empty.decision}/${empty.reasonCode}`);
  }
  const broken = async (opt) => { try { await guard.guardIncomingTool('flight-purchase', async () => 'done', { trustedContext: opt })(signedRequest({ amount: 100, context: { riskLevel: 'low' } })); return 'ran'; } catch (e) { return `threw:${/trustedContext/.test(String(e?.message))}`; } };
  for (const [name, opt, want] of [['a function returning undefined', () => undefined, 'threw:true'], ['a function returning a junk riskLevel', () => ({ riskLevel: 'nope' }), 'threw:true'], ['a function that throws', () => { throw new Error('classifier down'); }, 'threw:false']]) {
    const got = await broken(opt); const good = got === want; if (!good) failed++;
    console.log(`${good ? 'ok  ' : 'FAIL'}  guardIncomingTool trustedContext ${name} → the call is refused, the handler never runs  →  ${got}`);
  }

  // guardIncomingTool: the tool author states the risk of THIS tool; an object or a function of the call.
  const denied = async (tool) => { try { await tool(signedRequest({ amount: 100, context: { riskLevel: 'low' } })); return 'ran'; } catch (e) { return `${e.governance?.decision}/${e.governance?.reasonCode}`; } };
  const okA = await denied(guard.guardIncomingTool('flight-purchase', async () => 'done', { trustedContext: { riskLevel: 'high' } }));
  const okB = await denied(guard.guardIncomingTool('flight-purchase', async () => 'done', { trustedContext: () => ({ riskLevel: 'high' }) }));
  const okC = await denied(guard.guardIncomingTool('flight-purchase', async () => 'done', { trustedContext: { riskLevel: 'low' } }));
  for (const [name, got, want] of [['guardIncomingTool trustedContext object', okA, 'escalate/RISK_REVIEW'], ['guardIncomingTool trustedContext function', okB, 'escalate/RISK_REVIEW'], ['guardIncomingTool low trustedContext lets an honest request run', okC, 'ran']]) {
    const ok = got === want; if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}  →  ${got}`);
  }
}

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

console.log('\n— SOP-side currency-scoped amount-over atom (verdictFromBundle context) —');
{
  // Regression: verdictFromBundle's `context` (what Standards/SOP atoms read) used to omit
  // currency/merchant/resource entirely — only `mandateRequest.values` got them. A
  // currency-scoped `amount-over` atom therefore always saw currency as absent and fired
  // closed, blocking even a genuinely in-cap request in a non-default currency.
  const gbpSopBundle = {
    ...bundle,
    sops: [
      {
        id: 'travel-gbp',
        document: {
          molecules: [
            { id: 'cap', combinator: 'any', atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 200, currency: ['GBP'] } }], decision: 'block', reasonCode: 'SOP_SPEND_CAP' },
          ],
        },
      },
    ],
  };
  const gbpGuard = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => gbpSopBundle });
  const checkGbp = async (name, req, expect) => {
    const v = await gbpGuard.verifyRequest(req);
    const ok = v.decision === expect[0] && v.reasonCode === expect[1];
    if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}  →  ${v.decision}/${v.reasonCode}`);
  };
  await checkGbp('GBP request within the GBP-scoped cap → allow (was falsely SOP_SPEND_CAP)', signedRequest({ amount: 100, currency: 'GBP' }), ['allow', 'AUTHORIZED']);
  await checkGbp('GBP request over the GBP-scoped cap → block', signedRequest({ amount: 300, currency: 'GBP' }), ['block', 'SOP_SPEND_CAP']);
}

console.log('\n— resource included in the signed message (canonical §7.3, 8 fields) —');
{
  // Regression: verifyRequest()'s destructure + buildAuthMessage call used to omit `resource`
  // entirely, so a genuinely-valid signature over a resource-bearing request always failed
  // SIGNATURE_INVALID at this guard.
  const resourceBundle = {
    ...bundle,
    mandates: [
      {
        action: 'vehicle-inspection',
        document: { permission: [{ target: 'vehicle-inspection', constraint: [{ leftOperand: 'resource', operator: 'isAnyOf', rightOperand: ['inspection-db'] }] }] },
      },
    ],
  };
  const resourceGuard = createMcpGuard({ serviceDid: service.did, serviceKey: service.keyHex, fetchBundle: async () => resourceBundle });
  function signedResourceRequest({ resource, tamperResource }) {
    const action = 'vehicle-inspection';
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    const message = buildAuthMessage({ agentDid: agent.did, action, amount: 0, currency: 'USD', merchant: '', resource, nonce, issuedAt });
    const signature = agent.sign(message);
    return { agentDid: agent.did, action, amount: 0, currency: 'USD', resource: tamperResource ?? resource, itinerary: { riskLevel: 'low' }, nonce, issuedAt, signature };
  }
  const checkResource = async (name, req, expect) => {
    const v = await resourceGuard.verifyRequest(req);
    const ok = v.decision === expect[0] && v.reasonCode === expect[1];
    if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}  →  ${v.decision}/${v.reasonCode}`);
  };
  await checkResource('in-scope resource, genuinely signed → allow (was SIGNATURE_INVALID)', signedResourceRequest({ resource: 'inspection-db' }), ['allow', 'AUTHORIZED']);
  await checkResource('out-of-scope resource → block', signedResourceRequest({ resource: 'billing-db' }), ['block', 'CONSTRAINT_FAILED:resource']);
  await checkResource('resource swapped after signing → block (signature no longer covers it)', signedResourceRequest({ resource: 'inspection-db', tamperResource: 'billing-db' }), ['block', 'SIGNATURE_INVALID']);
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

  // SUPERVISED escalates a HIGH-risk action even for a small spend — and the risk it judges is the effective one,
  // so an agent cannot skip that by claiming "low" about an action its owner classed high.
  const tieredMode = (mode) => createMcpGuard({
    serviceDid: service.did, serviceKey: service.keyHex,
    fetchBundle: async () => {
      const b = JSON.parse(JSON.stringify(bundle));
      b.standards = []; // isolate the mode gate from the rule layer
      b.mandates[0].document.permission[0].riskTier = 'high';
      Object.defineProperty(b, '__operatingMode', { value: { mode }, enumerable: false });
      return b;
    },
  });
  const tv = await tieredMode('supervised').verifyRequest(signedRequest({ amount: 10, context: { riskLevel: 'low' } }));
  const tvOk = tv.decision === 'escalate' && tv.reasonCode === 'MODE_SUPERVISED_REVIEW';
  if (!tvOk) failed++;
  console.log(`${tvOk ? 'ok  ' : 'FAIL'}  SUPERVISED + owner tier=high: a small spend claimed "low" still escalates  →  ${tv.decision}/${tv.reasonCode}`);
}

console.log('\n— mutual handshake (§8.2) —');
{
  const initiator = createHandshakeInitiator({ fromDid: agent.did, sign: agent.sign });
  const { nonceA, message } = initiator.hello();
  const challenge = await guard.handshakeChallenge(message); // B signs nonceA
  const prove = await initiator.prove({ nonceA, challenge }); // A verifies B, signs nonceB
  const ready = guard.handshakeVerify(prove); // B verifies A
  const ok = !!ready.channelId && ready.remoteDid === agent.did;
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  agent↔service mutual verify → channel ${ready.channelId?.slice(0, 8)}…`);

  // A forged PROVE (wrong key) must be rejected.
  let rejected = false;
  const c2 = await guard.handshakeChallenge(initiator.hello().message);
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

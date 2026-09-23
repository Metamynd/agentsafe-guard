// verify_with_real_guard.mjs — the counterparty side of the Python client's conformance test.
//
// The REAL `agentsafe-mcp-guard` and the REAL `agentsafe-http-gateway`, from this repository, verifying requests
// the Python client signed. Nothing here is a stand-in for the protocol: if the Python client signs the wrong
// bytes, sends the wrong header, or drops a field (the seven-field bug), the real verifier says so.
//
//   node verify_with_real_guard.mjs --did <public-key-hex>       print the did:hedera that embeds that key
//   node verify_with_real_guard.mjs --verify                     read {publicKeyHex, cases} on stdin, print results
//
// Zero dependencies (the guard and gateway are zero-dependency), so this runs anywhere Node 18+ does.
import { readFileSync } from 'node:fs';
import { createMcpGuard } from '../../agentsafe-mcp-guard/agentsafe-mcp-guard.mjs';
import { buildHederaDid } from '../../agentsafe-mcp-guard/magp-did.mjs';
import { createHttpGateway } from '../../agentsafe-http-gateway/gateway.mjs';
import { payloadDigestOf } from '../../agentsafe-mcp-guard/payload-binding.mjs';

const didFor = (publicKeyHex) => buildHederaDid('testnet', Buffer.from(publicKeyHex, 'hex'), '0.0.4242');

if (process.argv.includes('--did')) {
  process.stdout.write(didFor(process.argv[process.argv.indexOf('--did') + 1]));
  process.exit(0);
}

const { publicKeyHex, cases } = JSON.parse(readFileSync(0, 'utf8'));
const did = didFor(publicKeyHex);

// The agent's policy bundle, the way the issuer would serve it: a high-risk review rule and a spend cap (rules),
// a flight mandate (merchant allow-list) and a resource-scoped read mandate (mandates).
const bundle = {
  subject: did,
  standards: [{ key: 'risk', document: { molecules: [{ id: 'risk', combinator: 'any', atoms: [{ id: 'r', predicate: 'risk-at-or-above', config: { level: 'high' } }], decision: 'escalate', reasonCode: 'RISK_REVIEW' }] } }],
  sops: [{ id: 'cap', document: { molecules: [{ id: 'cap', combinator: 'any', atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 500 } }], decision: 'block', reasonCode: 'SOP_SPEND_CAP' }] } }],
  mandates: [
    { action: 'flight-purchase', document: { permission: [{ target: 'flight-purchase', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 1000 }, { leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: ['skyward-air'] }] }] } },
    { action: 'db-read', document: { permission: [{ target: 'db-read', constraint: [{ leftOperand: 'resource', operator: 'isAnyOf', rightOperand: ['inspection-db'] }] }] } },
  ],
};

const guard = createMcpGuard({ serviceDid: 'did:local:python-conformance', fetchBundle: async () => bundle });

const forwarded = [];
const gateway = createHttpGateway({
  guard,
  routes: [
    { method: 'POST', path: '/book', action: 'flight-purchase', valueFields: ['amount', 'merchant'], allowedFields: ['amount', 'merchant'] },
    // A route whose tool takes more than the eight signed fields: the payee is only bound by the payload digest (spec 8.3.9).
    { method: 'POST', path: '/pay', action: 'flight-purchase', valueFields: ['amount', 'merchant'], allowedFields: ['amount', 'merchant', 'payee', 'passenger'] },
    { method: 'POST', path: '/pay-strict', action: 'flight-purchase', valueFields: ['amount', 'merchant'], allowedFields: ['amount', 'merchant', 'payee', 'passenger'], requirePayloadBinding: true },
  ],
  forward: async (req) => { forwarded.push(req.path); return { status: 200, body: { booked: true } }; },
  denyByDefault: true,
});

const results = [];
for (const c of cases) {
  if (c.kind === 'gateway') {
    const before = forwarded.length;
    const res = await gateway({ method: 'POST', path: c.path ?? '/book', headers: c.headers ?? {}, rawBody: Buffer.from(JSON.stringify(c.body ?? {})) });
    results.push({ name: c.name, status: res.status, reasonCode: res.body?.reasonCode ?? null, decision: res.governance?.decision ?? res.body?.decision ?? null, forwarded: forwarded.length > before });
  } else {
    // `executed` is the payload THIS service is about to run; it digests it with its own bundled copy of the canonicalisation.
    const v = await guard.verifyRequest(c.request, c.executed !== undefined ? { payloadDigest: payloadDigestOf(c.executed), requirePayloadBinding: c.requirePayloadBinding } : {});
    results.push({ name: c.name, decision: v.decision, reasonCode: v.reasonCode });
  }
}
process.stdout.write(JSON.stringify({ did, results }));

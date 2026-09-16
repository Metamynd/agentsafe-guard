// guard-incoming-tool.smoke.mjs — proves guardIncomingTool pins the WRAPPED TOOL's own action,
// never the caller's claimed `signed.action` — the "wrong action" adversarial case named by a
// readiness review's release gate ("test the pattern against ... wrong action ...").
//
// This is a DIFFERENT layer than claim-authorization.smoke.mjs's own "action-swap" case: that
// file proves a claimed authorizationId's HOLD must match the presented action. This file proves
// something upstream of that — which wrapped tool's HANDLER FUNCTION runs at all. A real MCP
// Service normally wraps MANY tools with ONE guard instance (one server, several actions); before
// this fix, `guardIncomingTool(action, handler)` verified whatever `signed.action` the CALLER
// claimed instead of the tool's own bound `action` — so a genuinely-valid signature for a cheap,
// harmless action (e.g. a free read) verified successfully and then ran a COMPLETELY DIFFERENT
// tool's handler (e.g. a wire transfer), because nothing ever checked that the claimed action
// matched the tool actually being invoked. Mirrors gateway.mjs's already-correct
// `route.action ?? signed.action` ("the route pins the action ... the client can't pick it").
//
//   node guard-incoming-tool.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const raw = spki.subarray(spki.length - 32);
  const did = buildHederaDid('testnet', raw, topic);
  const sign = (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex');
  return { did, sign };
}

const agent = mint('0.0.900');
const service = mint('0.0.901');

// Two genuinely-permitted actions, so this proves a cross-tool swap — not "no mandate for this
// action" (a different, already-handled block case). 'read-report' is free; 'wire-transfer' has
// a real cap, so a swap that reached the handler would matter.
const bundle = {
  subject: agent.did,
  mandates: [
    { action: 'read-report', document: { permission: [{ target: 'read-report', constraint: [] }] } },
    { action: 'wire-transfer', document: { permission: [{ target: 'wire-transfer', constraint: [{ leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: 10 }] }] } },
  ],
};

const guard = createMcpGuard({ serviceDid: service.did, fetchBundle: async () => bundle });

function signedRequest(action, amount = 0) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const message = buildAuthMessage({ agentDid: agent.did, action, amount, currency: 'USD', merchant: '', nonce, issuedAt });
  const signature = agent.sign(message);
  return { agentDid: agent.did, action, amount, currency: 'USD', merchant: '', nonce, issuedAt, signature };
}

let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };

let readReportRan = false;
let wireTransferRan = false;
const readReportTool = guard.guardIncomingTool('read-report', () => { readReportRan = true; return { ok: true }; });
const wireTransferTool = guard.guardIncomingTool('wire-transfer', (signed) => { wireTransferRan = true; return { moved: signed.amount }; });

console.log('— wrong action: a signature for one tool must not run a DIFFERENT tool\'s handler —');
{
  // The attacker's only real, valid signature ever authorizes the harmless free read.
  const onlyEverAuthorizedFor = signedRequest('read-report', 0);

  readReportRan = false; wireTransferRan = false;
  let threw = null;
  try { await wireTransferTool(onlyEverAuthorizedFor); } catch (e) { threw = e; }
  ok(!wireTransferRan, 'the wire-transfer tool\'s handler never ran on a read-report-only signature');
  ok(threw?.name === 'GovernanceBlocked', 'the call is rejected as GovernanceBlocked, not silently permitted', threw?.name);
  ok(threw?.governance?.reasonCode === 'SIGNATURE_INVALID', 'rejected because the signature does not cover the tool\'s OWN action', threw?.governance?.reasonCode);
}

console.log('\n— sanity: the legitimate, matching case still works —');
{
  readReportRan = false; wireTransferRan = false;
  await readReportTool(signedRequest('read-report', 0));
  ok(readReportRan, 'read-report tool runs on its own genuinely-signed request');

  await wireTransferTool(signedRequest('wire-transfer', 5));
  ok(wireTransferRan, 'wire-transfer tool runs on its own genuinely-signed, in-cap request');
}

console.log('\n— the swap fails even in the OTHER direction (cheap tool invoked with the expensive action\'s signature) —');
{
  readReportRan = false;
  let threw = null;
  try { await readReportTool(signedRequest('wire-transfer', 5)); } catch (e) { threw = e; }
  ok(!readReportRan, 'the read-report tool\'s handler never ran on a wire-transfer-signed request');
  ok(threw?.governance?.reasonCode === 'SIGNATURE_INVALID', 'rejected — the signature does not cover read-report', threw?.governance?.reasonCode);
}

if (failed) {
  console.error(`\n${failed} case(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — guardIncomingTool pins each wrapped tool to its own action; a signature valid for one tool cannot run another.');

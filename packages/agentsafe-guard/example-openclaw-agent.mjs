// example-openclaw-agent.mjs — a runnable demo of the guard against a seeded bound agent.
//
// Simulates how an OpenClaw agent's TOOL is wrapped: the raw tool only runs if the
// AgentSafe gate returns `allow`. Run it after seeding an agent with
// backend/scripts/demo-seed-governance.ts:
//
//   $env:AGENTSAFE_API="http://localhost:9926/api/v1"
//   $env:AGENT_DID="did:hedera:testnet:..."
//   $env:AGENT_KEY="302e0201..."
//   node example-openclaw-agent.mjs
import { createGuard } from './agentsafe-guard.mjs';

const guard = createGuard({
  api: process.env.AGENTSAFE_API ?? 'http://localhost:9926/api/v1',
  agentDid: process.env.AGENT_DID,
  agentKey: process.env.AGENT_KEY,
});

// --- The agent's tool. In OpenClaw you register this handler for the tool; here we
//     wrap it with guard.guardTool so every call is gated first. ---
const bookFlight = guard.guardTool(
  'flight-purchase', // the governed action (matches the mandate scope)
  async (args, decision) => {
    // Only reached when the gate ALLOWED. Real booking would go here.
    return { booked: true, pnr: 'PNR-DEMO', remaining: decision.remaining, ...args };
  },
  // Map the tool args → gate inputs. `context` carries what the Standard/SOP rules need.
  (a) => ({ amount: a.amount, currency: 'USD', merchant: a.merchant, context: { tool: a.tool ?? 'book-flight', riskLevel: a.riskLevel ?? 'low' } }),
);

async function ask(label, args) {
  try {
    const r = await bookFlight(args);
    console.log(`  \x1b[32m✅ ALLOW\x1b[0m   ${label.padEnd(30)} → booked ${r.pnr} (remaining $${r.remaining})`);
  } catch (e) {
    const g = e.governance ?? {};
    const tag = g.decision === 'escalate' ? '\x1b[33m⚠ ESCALATE\x1b[0m' : '\x1b[31m⛔ BLOCK\x1b[0m';
    console.log(`  ${tag} ${label.padEnd(30)} → ${g.reasonCode ?? e.message}`);
  }
}

console.log(`\n  OpenClaw agent — every booking passes through the AgentSafe gate\n  ${'─'.repeat(60)}`);
await ask('$150 book-flight, low risk', { amount: 150, merchant: 'skyward-air', tool: 'book-flight', riskLevel: 'low' });
await ask('$600 book-flight', { amount: 600, merchant: 'skyward-air', tool: 'book-flight', riskLevel: 'low' });
await ask('$100 wire-transfer tool', { amount: 100, merchant: 'skyward-air', tool: 'wire-transfer', riskLevel: 'low' });
await ask('$100 high-risk decision', { amount: 100, merchant: 'skyward-air', tool: 'book-flight', riskLevel: 'high' });
console.log(`\n  The agent refuses blocked/escalated actions itself — governance decided, not the LLM.\n`);

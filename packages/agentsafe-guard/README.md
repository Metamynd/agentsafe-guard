# AgentSafe Guard — runtime governance for OpenClaw (and any Node agent)

Drop-in middleware that gates an agent's actions through the AgentSafe **authorize** endpoint
before they run. The gate deterministically returns `allow` / `block` / `escalate` after checking
the agent's **mandate**, its enforced **Standards**, and its assigned **SOPs** — the same rules a
compliance team edits in the dashboard, changeable live with no redeploy.

- **Zero dependencies.** Uses Node's built-in Ed25519 (`node:crypto`) + `fetch` (Node 18+).
- **Deterministic + tamper-resistant.** Every call is Ed25519-signed over a canonical message with a
  single-use nonce; the gate is server-authoritative and cannot be bypassed. No LLM at the gate.
- **Fail-closed.** A network/gate failure returns `block`, so the agent never proceeds blind.

## 1. Seed a bound agent (once)

Run the seed against a running stack — it prints the agent's `DID` and `KEY`:

```powershell
cd backend
$env:API_BASE="http://localhost:9926/api/v1"   # or https://metamynd.ai/api/v1
node_modules\.bin\tsx scripts\demo-seed-governance.ts
# → AGENT_DID = did:hedera:testnet:...
# → AGENT_KEY = 302e0201...
```

The agent is now bound to a mandate (`flight-purchase`), an **enforced Standard** (EU AI Act) and an
**active SOP** (spend cap + approved tools). Manage/toggle these from the dashboard:
Super Admin → Standards, Legal Entity → SOPs.

## 2. Try the example

```powershell
cd integrations\agentsafe-guard
$env:AGENTSAFE_API="http://localhost:9926/api/v1"
$env:AGENT_DID="did:hedera:testnet:..."
$env:AGENT_KEY="302e0201..."
node example-openclaw-agent.mjs
```

```
✅ ALLOW    $150 book-flight, low risk     → booked PNR-DEMO (remaining $200)
⛔ BLOCK    $600 book-flight               → SOP_SPEND_CAP
⛔ BLOCK    $100 wire-transfer tool        → SOP_TOOL_BLOCKED
⚠ ESCALATE $100 high-risk decision        → RISK_REVIEW
```

Now flip the SOP's **active → inactive** toggle in the UI (or edit a rule) and re-run — the decision
changes in real time.

## 3. Wire it into your OpenClaw agent

Wrap each governed tool's handler with `guardTool(...)`. The wrapped handler only runs when the gate
allows; otherwise it throws a `GovernanceBlocked` error your agent surfaces to the user.

```js
import { createGuard } from './agentsafe-guard.mjs';

const guard = createGuard({
  api: process.env.AGENTSAFE_API,
  agentDid: process.env.AGENT_DID,
  agentKey: process.env.AGENT_KEY,   // held only by the agent
});

// Your existing OpenClaw tool handler:
async function bookFlight(args) { /* …call the airline… */ return { pnr: 'ABC123' }; }

// Register the GATED version with OpenClaw instead of the raw handler:
const gatedBookFlight = guard.guardTool(
  'flight-purchase',                 // the governed action (matches the mandate scope)
  bookFlight,
  (a) => ({                          // map tool args → gate inputs
    amount: a.amount,
    currency: 'USD',
    merchant: a.merchant,
    context: { tool: 'book-flight', jurisdiction: a.jurisdiction, riskLevel: a.riskLevel },
  }),
);
```

- If your OpenClaw build has a **pre-tool hook / middleware** instead of raw handlers, call
  `await guard.authorize({ action, amount, merchant, context })` there and refuse on any non-`allow`.
- **`context`** is what the Standard/SOP atoms read (jurisdiction, model, tool, PII, risk, …). Each
  atom declares what it needs — fetch the catalog at `GET /api/v1/standards/atoms` to see the exact
  fields (`requiredContext`) for the rules your agent is bound to.
- For **payment** tools, after the real charge succeeds call
  `await guard.capture(decision.authorizationId, amountCharged, bookingRef)` to settle the two-phase hold.

## Trust model

The gate is a **checkpoint** — enforcement is real when it's actually called.
- **Trustless:** the counterparty the agent transacts with calls the *public* authorize endpoint and
  only proceeds on `allow`. A rogue agent that skips the call can't get the counterparty to act.
- **Cooperative:** the agent's own tool layer (this guard) calls the gate and refuses on block/escalate.

Either way, every decision is Ed25519-authenticated, deterministic, and anchored as evidence
(visible in the dashboard's Regulator log and on HashScan).

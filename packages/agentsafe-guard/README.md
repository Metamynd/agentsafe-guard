# AgentSafe Guard — runtime governance for OpenClaw (and any Node agent)

Drop-in middleware that gates an agent's actions through the AgentSafe **authorize** endpoint
before they run. The gate deterministically returns `allow` / `block` / `escalate` after checking
the agent's **mandate**, its enforced **Standards**, and its assigned **SOPs** — the same rules a
compliance team edits in the dashboard, changeable live with no redeploy.

- **Zero dependencies.** Uses Node's built-in Ed25519 (`node:crypto`) + `fetch` (Node 18+), plus
  `policy-core.mjs` — the deterministic evaluator, itself dependency-free, generated from
  `backend/src/policy-core` (regenerate with `npm run build:guard-core`).
- **Deterministic + tamper-resistant.** Every call is Ed25519-signed over a canonical message with a
  single-use nonce; the gate is server-authoritative and cannot be bypassed. No LLM at the gate.
- **Fail-closed.** A network/gate failure returns `block`, so the agent never proceeds blind.
- **Local evaluation.** The guard can also evaluate a signed policy bundle **locally** with the same
  `policy-core` the gate runs (MAGP §9.2 cooperative mode) — identical inputs give the identical
  verdict, with no network round-trip. See §4.

## Install

```bash
npm i @metamynd/agentsafe-guard
```

Requires Node ≥ 18 (built-in `fetch` + Ed25519). The package has **no dependencies**.

### Fastest start — scaffold a governed agent in one command

If you don't have an agent config yet, let the scaffolder log you in, provision the agent
(identity + mandate + starter SOP + Standards in one call), write `agent.metamynd.json`, and drop a
runnable example:

```bash
npm create metamynd-agent@latest      # or: npx create-metamynd-agent
```

Then:

```js
import { createGuardFromConfig } from '@metamynd/agentsafe-guard';
const guard = await createGuardFromConfig('./agent.metamynd.json');   // no env vars
```

The rest of this guide shows the manual path (seed → wire) and the advanced features
(local eval, handshake, escalation, payments).

### Enforcement mode: local-first (default) or remote

Since v0.2.0 the guard decides **locally by default**. `guardTool` (and the mode-aware
`guard.check(...)`) evaluate the rule layer against the agent's cached signed policy
bundle using the **same `policy-core` bytes the gate runs** — so a **block or escalate
is decided with no network** (instant, works offline). An **allowed value action**
(`amount > 0`) is still sealed by the remote gate, because the cumulative-spend cap,
nonce/replay + atomic cap, and anchored evidence **must** be server-side. If the bundle
can't be fetched, the guard defers to the authoritative remote gate rather than
blind-allowing; a value action it can neither evaluate nor seal **fails closed**.

```js
// default — local-first
const guard = await createGuardFromConfig('./agent.metamynd.json');
// opt out — every call hits the gate
const remote = await createGuardFromConfig('./agent.metamynd.json', { mode: 'remote' });
// pure offline (no remote seal; drops cumulative-cap + evidence — you accept the trade)
const offline = await createGuardFromConfig('./agent.metamynd.json', { mode: 'local', sealValueActions: false });
```

`guard.authorize(...)` is always the explicit **remote** call (unchanged);
`guard.authorizeLocal(...)` is the explicit local-first call; `guard.check(...)` follows
the configured `mode`. All return `{ decision, reasonCode, authorizationId, … }`.

### Trustless currency check (`verifyOnChain`)

Local eval trusts a bundle fetched over TLS. With `{ verifyOnChain: true }` the guard
additionally confirms — from a **public Hedera mirror node, with MetaMynd offline** —
that its local bundle is the **latest one anchored on the agent's own topic**. On each
recompile MetaMynd publishes `sha256(bundle signature)` to the topic; the guard reads
the latest `policy-update` op and requires `sha256(bundle.proof.signature)` to match it.
If it can't confirm (mismatch / not yet anchored / mirror down), it **defers to the
authoritative remote gate** rather than evaluate a bundle it can't prove is current.
Append-only Hedera consensus makes the latest op authoritative and a **rollback**
(serving an older signed bundle) detectable; a monotonic sequence number defeats a mirror
that hides recent updates.

```js
const guard = await createGuardFromConfig('./agent.metamynd.json', { verifyOnChain: true });
await guard.policyAnchor(); // → { sigDigest, seq } read from Hedera (or null)
```

### Bring your own key (BYOK)

Provision the agent with your **own** public key so MetaMynd never sees the private key. The identity
is issued unverified with a one-time `challenge`; the gate blocks it (`AGENT_KEY_UNVERIFIED`) until you
prove control. The guard signs the challenge with your key and submits it:

```js
const guard = await createGuardFromConfig('./agent.metamynd.json', { agentKey: myPrivateKey });
await guard.verifyKey({ ref: config.identityId, challenge: config.challenge, token: ownerToken }); // one-time
```

`guard.signChallenge(challenge)` returns just the hex signature if you'd rather submit verify-key
yourself. (Fastest path: `npm create metamynd-agent@latest -- --byok` does all of this for you.)

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
import { createGuard, createGuardFromConfig } from '@metamynd/agentsafe-guard';

// Preferred: load the portable config the one-call onboarding endpoint returns (no env vars).
const guard = await createGuardFromConfig('./agent.metamynd.json');

// Or configure explicitly:
const guardExplicit = createGuard({
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
- For **payment** tools (x402, §7a): after `authorize` allows, the Service returns a 402 bound to
  your `authorizationId`. Call `guard.preparePayment(requirements, authorizationId)` — it refuses an
  unbound or mismatched 402 — pay via x402, then reconcile the hold with
  `await guard.capture(authorizationId, amountCharged, bookingRef, settlementTxHash)`. An
  uncaptured hold auto-voids at its expiry (`POST /policy/mandate/authorize/:id/void` to release early).

## 4. Evaluate locally (no network)

For low-latency, cooperative-mode governance the guard can evaluate a **policy bundle** locally with
the same deterministic `policy-core` the gate runs — no round-trip. Given the same rule packs,
mandate, and request, it returns the **identical** `allow` / `block` / `escalate` verdict.

```js
const verdict = guard.evaluateLocally({
  standards: [{ standardKey: 'eu-ai-act', document: { molecules: [/* … */] } }],
  sops:      [{ standardKey: 'sop:travel', document: { molecules: [/* … */] } }],
  mandate:   { permission: [/* ODRL constraints … */] },
  request:   { action: 'flight-purchase', amount: 600, merchant: 'amadeus',
               context: { riskLevel: 'low' } },
});
// → { decision: 'block', reasonCode: 'SOP_SPEND_CAP', authorizationId: null, remaining: null, proofRef: null }
```

Or wrap a tool to gate it against a local bundle (fails closed like `guardTool`):

```js
const gated = guard.guardToolLocal('flight-purchase', bookFlight, mapArgs, { standards, sops, mandate });
```

Signed request fields (`amount`, `merchant`) are always applied over the unsigned `context`, so a
forged context key can never shadow them (MAGP §6.4.2). Run the self-check:

```powershell
cd integrations\agentsafe-guard
node local-eval.smoke.mjs   # PASS when every local verdict matches the gate
```

Local evaluation is the cooperative-mode pre-check; the gate still owns the stateful parts
(single-use nonce, atomic spend-cap reservation, evidence anchoring), so value-bearing actions should
still settle through the gate / `capture` flow.

## 5. Mutual handshake with a Service (§8.2)

Before transacting with a Service (an MCP), the agent and Service prove control of their DIDs
to each other — no issuer calls, because the keys are embedded in the DIDs (§4.1.2). The agent
drives the initiator side:

```js
const hs = guard.handshake();
const { nonceA, message } = hs.hello();              // → send HELLO to the Service
// Service replies with CHALLENGE { toDid, nonceB, sigB(nonceA) }
const { sigA, handshakeId } = hs.prove({ nonceA, challenge });  // verifies the Service, → send PROVE
// Service replies READY { channelId }
```

`prove()` throws `HandshakeFailed` if the Service's CHALLENGE does not verify against the key in
its DID. The Service side uses [`agentsafe-mcp-guard`](../agentsafe-mcp-guard), which also
re-evaluates the agent's signed request trustlessly (§9.6). Discover a Service's endpoint and
confirm its key via the public resolver `GET /did/:did` (§4.4).

## 6. Escalation — human-in-the-loop (§9a)

An `escalate` verdict is **not a denial** — the action is *held* pending the Owner's approval. The
verdict carries an `escalationId`; no budget is reserved and (for payments) nothing settles until it
is approved. The Owner resolves it in the dashboard / via `POST /policy/escalations/:id/resolve`;
the agent polls the outcome:

```js
const d = await guard.authorize({ action: 'flight-purchase', amount: 5000, context: { riskLevel: 'high' } });
if (d.decision === 'escalate') {
  // parked for review — d.escalationId, d.expiresAt
  const outcome = await guard.escalationStatus(d.escalationId);
  // → { status: 'approved' | 'denied' | 'expired' | 'pending', authorizationId, reasonCode }
  // on 'approved', outcome.authorizationId carries into the §7a capture/pay flow.
}
```

On approval the budget/cap gate re-runs (§9a.3), so an approval still can't overspend; an
unresolved escalation lapses to denied after its TTL (§9a.4).

## Trust model

The gate is a **checkpoint** — enforcement is real when it's actually called.
- **Trustless:** the counterparty the agent transacts with calls the *public* authorize endpoint and
  only proceeds on `allow`. A rogue agent that skips the call can't get the counterparty to act.
- **Cooperative:** the agent's own tool layer (this guard) calls the gate and refuses on block/escalate.

Either way, every decision is Ed25519-authenticated, deterministic, and anchored as evidence
(visible in the dashboard's Regulator log and on HashScan).

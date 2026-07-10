# AgentSafe MCP Guard — the service side of MAGP governance

The counterpart to [`agentsafe-guard`](../agentsafe-guard) (the agent side). A Service
(an MCP, e.g. an Amadeus flight API) is an **identity-bearing peer** under MAGP (§4.6): it
holds its own `did:hedera` + key, completes a **mutual handshake** with the agent, and
**enforces governance trustlessly** — it independently re-verifies and re-evaluates the
agent's request instead of trusting the agent's own guard.

- **Zero external dependencies.** Node's built-in Ed25519 (`node:crypto`) + `fetch`, plus two
  generated, dependency-free bundles: `policy-core.mjs` (the deterministic evaluator) and
  `magp-did.mjs` (key-in-DID verification). Regenerate with `npm run build:mcp-guard-core`.
- **No issuer round-trip to verify identity.** The verification key is embedded in the DID
  (§4.1.2), so the guard verifies signatures and handshakes offline.
- **Fail-closed.** A bad signature, a stale request, a failed bundle fetch, or any error
  yields `block`.

## 1. Mutual handshake (§8.2)

Each side proves control of its DID; neither calls the issuer (keys are in the DIDs).

```
A → B  HELLO      { fromDid, nonceA }
B → A  CHALLENGE  { toDid, nonceB, sigB(nonceA) }   ← B proves it controls toDid
A → B  PROVE      { sigA(nonceB) }                    ← A proves it controls fromDid
B → A  READY      { channelId }
```

```js
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';

const guard = createMcpGuard({
  serviceDid: process.env.SERVICE_DID,
  serviceKey: process.env.SERVICE_KEY,      // the MCP's Ed25519 DER key (held only by the MCP)
  issuerApi: 'https://metamynd.ai/api/v1',  // where policy bundles are fetched from
});

// Responder side, over your HTTP transport:
const challenge = guard.handshakeChallenge(hello);   // POST /magp/handshake  (HELLO → CHALLENGE)
const ready     = guard.handshakeVerify(prove);      // POST /magp/handshake  (PROVE → READY, or throws)
```

The agent drives the initiator side with `createGuard(...).handshake()` from `agentsafe-guard`.

## 2. Trustless enforcement (§9.3, §9.6)

For a value-bearing tool call the Service re-checks the agent's **signed authorize request**
and re-evaluates policy against the agent's **issuer-hosted bundle** — the same deterministic
`policy-core` the gate runs. It never trusts the agent's guard.

```js
// The agent presents its signed authorize request alongside the tool call.
const decision = await guard.verifyRequest({
  agentDid, action: 'flight-purchase', amount: 150, currency: 'USD', merchant: 'amadeus',
  itinerary: { riskLevel: 'low' }, nonce, issuedAt, signature,
});
// { decision: 'allow' | 'block' | 'escalate', reasonCode }

// Or wrap a tool so it runs only after verification allows (throws GovernanceBlocked otherwise):
const bookFlight = guard.guardIncomingTool('flight-purchase', rawBookFlight);
```

`verifyRequest`:
1. rebuilds the canonical message (§7.3) and verifies the Ed25519 signature via **key-in-DID**;
2. checks freshness (single-use nonce stays the gate's job);
3. fetches the agent's policy bundle from the issuer (`GET /policy/bundle/:did`, over TLS);
4. evaluates Standards → SOPs → mandate with `policy-core` — signed fields applied last, so a
   forged `itinerary` key can't shadow the signed amount/merchant (§6.4.2).

Run the self-check (handshake + trustless eval, no network):

```powershell
cd integrations\agentsafe-mcp-guard
node mcp-guard.smoke.mjs   # PASS when every case matches
```

## Where this fits

MetaMynd is the **control plane** (issuer/anchor): it exposes the public DID resolver
(`GET /did/:did`, §4.4) and the policy bundle (`GET /policy/bundle/:did`, §5.3.2). The agent
guard and this MCP guard are the **data plane**: they discover each other via DID, verify
mutually, and evaluate governance at the edge — no per-action call to the issuer for a routine
decision. A value-bearing action is governed by BOTH sides (§9.6): the agent's guard, then this
guard's trustless re-check.

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
2. checks freshness (single-use nonce stays the gate's job **unless `requireAuthorization` is
   set** — see below, that's the exception);
3. fetches the agent's policy bundle from the issuer (`GET /policy/bundle/:did`, over TLS);
4. evaluates Standards → SOPs → mandate with `policy-core` — signed fields applied last, so a
   forged `itinerary` key can't shadow the signed amount/merchant (§6.4.2).

`policy-core`'s `amount-unknown` atom (0.3.0) is a deny-by-default check for any value-moving
tool call whose amount the guard can't determine — a signed-transaction or nested x402 payload
can carry its value somewhere a naive spend cap never looks, and this blocks that case instead
of letting it slip past the cap untested.

### Replay and cumulative spend (`requireAuthorization`)

Re-evaluating policy per request (above) proves the request is well-formed and in-policy — it
does **not** stop a captured, still-fresh request from being replayed, and it can't enforce the
mandate's TOTAL budget across many separately-legal calls (each is only checked against its own
per-transaction cap). Both are the stateful issuer gate's job, not something a stateless re-check
can do on its own.

```js
const guard = createMcpGuard({ serviceDid, issuerApi, requireAuthorization: true });
```

When set, a PERMIT verdict (allow/observe) additionally requires `signed.authorizationId` to
**atomically claim single-use execution** against the issuer (`AUTHORIZED → DISPATCHING`, the
effect-safety state machine) — a second claim of the same id, whether a genuine replay or a race,
fails, because that transition is legal exactly once. The claimed hold's own bound
`agentDid`/`amount`/`currency`/`merchant` are checked against what's actually being executed, too
— a claim alone only proves *some* real, unclaimed authorization exists; without this check, a
cheap legitimate hold's id could be presented to unlock a completely different, more expensive
execution (`AUTHORIZATION_AGENT_MISMATCH` / `AUTHORIZATION_AMOUNT_MISMATCH` /
`AUTHORIZATION_CURRENCY_MISMATCH` / `AUTHORIZATION_MERCHANT_MISMATCH`). A field the backend
response omits (e.g. an older, not-yet-migrated deployment with no `merchant` column) is skipped,
not treated as a mismatch — this degrades gracefully, it doesn't silently under-check going
forward once the backend does report it.

The `authorizationId` has to come from a **real** `guard.authorize()` call on the agent side —
not `buildSignedRequest()`, which never talks to the network. In practice this usually needs no
extra agent-side plumbing: `agentsafe-guard`'s default `guardTool()` path already calls the real
remote `authorize()` for any value-bearing action (`sealValueActions`, on by default), so its
`authorizationId` is already sitting in the `decision` object `guardTool()` hands your handler —
thread it through to the signed request you present to this guard.

Off by default: it costs a network round trip per value-bearing call, so it's a deliberate
choice, not a strictly-dominant one. A Service happy with per-request policy re-evaluation alone
(no replay/cumulative-spend guarantee) can skip it.

Run the self-check (handshake + trustless eval, no network):

```powershell
cd integrations\agentsafe-mcp-guard
node mcp-guard.smoke.mjs             # PASS when every case matches
node claim-authorization.smoke.mjs   # requireAuthorization: replay, mismatch, fail-closed
```

## 3. Payment binding (x402, §7a)

MAGP authorizes and reserves budget; it never custodies funds (§7a.5). Value moves over
**x402**, and this guard **binds each settlement to exactly one authorization** so a payment
can't be reused, can't exceed the authorized amount, and can't settle without a governance
authorization behind it. The order is **authorize-before-pay** (§7a.1):

```
1. authorize   agent → gate: reserve amount → authorizationId (allow)
2. request     agent → Service tool call
3. 402         Service → agent: guard.requirePayment(...) — bound to authorizationId
4. verify      guard.verifyRequest(...) re-checks the authorization trustlessly (§2)
5. pay         agent → Service: X-PAYMENT; guard.settle(...) verifies + settles
6. fulfil      Service performs the action → PNR + tx hash
7. capture     agent → gate: capture(authorizationId, amountCharged, settlementTxHash)
```

```js
// 3 — demand payment bound to the MAGP authorization (§7a.2):
const requirements = guard.requirePayment({
  authorizationId, agentDid, amount: 150, payTo: SERVICE_ADDR, asset: 'USDC', resource: '/book-flight',
});

// 5 — verify the binding, then settle via your x402 facilitator (injected):
const { settled, txHash, reasonCode } = await guard.settle({
  requirements, authorizationId, paidAmountMinor, xPayment,
  settleFn: async ({ xPayment }) => facilitator.settle(xPayment),  // returns { settled, txHash }
});
```

`settle` returns `AMOUNT_MISMATCH` for an overpayment (§7a.2.2), `SETTLEMENT_REUSED` if the
authorization already settled (anti-reuse), and `SETTLEMENT_FAILED` if the facilitator can't
settle — all fail-closed. `requirePayment` / `settle` don't move money; the injected facilitator
does. On the agent side, `guard.preparePayment(requirements, authorizationId)` refuses an
**unbound** 402 and one whose authorization doesn't match the agent's own hold.

**Durable anti-reuse (SAFR §34).** By default `settle` tracks settled ids in-process (single
instance). For HA, inject a `settlementStore` that persists the claim — e.g. one backed by
`POST /magp/settlement/{reserve,finalize,release}` — so "one settlement per authorization" holds
across instances + restarts. `settle` **reserves before settling** (atomic claim) and **releases**
a claim whose settlement failed, so a legitimate retry can proceed:

```js
const guard = createMcpGuard({ serviceDid, settlementStore: {
  reserve:  (id) => post('/magp/settlement/reserve',  { authorizationId: id }).then(r => ({ ok: r.reserved, reasonCode: r.reasonCode })),
  release:  (id) => post('/magp/settlement/release',  { authorizationId: id }),
  finalize: (id, { txHash, amountMinor }) => post('/magp/settlement/finalize', { authorizationId: id, txHash, amountMinor }),
}});
```

**Commitment-bound capability (decision token, §7.7/§20).** Inject `verifyCapability(signed)` and,
when a request carries a signed capability, `guardIncomingTool` requires it to authorize **this exact
transaction** — the host reconstructs the tx and verifies MetaMynd's signature offline (via
`checkCapabilityBinding` from `magp-bind`), so "authorize $150, execute $5,000" is rejected in the
prod guard, not just the demo gateway. No verifier configured → opt-in (unchanged).

Holds carry an expiry (§7a.4): if not captured, the reservation auto-voids and the budget returns
to the cap; a party can also void explicitly via `POST /policy/mandate/authorize/:id/void`.

Run the self-check:

```powershell
node pay.smoke.mjs   # bound / exact / single-use / fail-closed
```

## Where this fits

MetaMynd is the **control plane** (issuer/anchor): it exposes the public DID resolver
(`GET /did/:did`, §4.4) and the policy bundle (`GET /policy/bundle/:did`, §5.3.2). The agent
guard and this MCP guard are the **data plane**: they discover each other via DID, verify
mutually, and evaluate governance at the edge — no per-action call to the issuer for a routine
decision. A value-bearing action is governed by BOTH sides (§9.6): the agent's guard, then this
guard's trustless re-check.

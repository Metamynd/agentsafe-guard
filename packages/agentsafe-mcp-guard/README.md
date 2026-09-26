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
const challenge = await guard.handshakeChallenge(hello);  // POST /magp/handshake  (HELLO → CHALLENGE)
const ready     = guard.handshakeVerify(prove);           // POST /magp/handshake  (PROVE → READY, or throws)
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
1. rebuilds the canonical message (§8.3) and verifies the Ed25519 signature via **key-in-DID**;
2. checks freshness (single-use nonce stays the gate's job **unless `requireAuthorization` is
   set** — see below, that's the exception);
3. fetches the agent's policy bundle from the issuer (`GET /policy/bundle/:did`, over TLS);
4. evaluates Standards → SOPs → mandate with `policy-core` — signed fields applied last, so a
   forged `itinerary` key can't shadow the signed amount/merchant (§6.4.2).

`policy-core`'s `amount-unknown` atom (0.3.0) is a deny-by-default check for any value-moving
tool call whose amount the guard can't determine — a signed-transaction or nested x402 payload
can carry its value somewhere a naive spend cap never looks, and this blocks that case instead
of letting it slip past the cap untested. As of 0.3.2 it also fires on a **negative** amount,
which previously read as "a real, known number" and could clear a spend cap for free.

**0.3.2 — freshness is no longer symmetric.** The staleness check used to compare
`|now - issuedAt|` against the freshness window, which treated a request timestamped in the
*future* the same as one from the past — accepting anything signed up to 5 minutes ahead of
server time, a pre-signing window rather than ordinary clock skew. `issuedAt` may now lag by up
to the freshness window (network/processing delay) but lead by no more than 30 seconds (clock
skew only).

**0.3.4 — a mandate's currency check no longer lets a PROHIBITION be dodged by relabeling
the currency.** A payAmount/cumulativeSpend constraint issued with a `unit` (currency) is
only satisfied in that currency — correct for a PERMISSION (fail closed to deny on a
mismatch), but a prohibition only fires when every one of its own constraints is satisfied,
so the identical "mismatch → not satisfied" rule let a prohibition like `payAmount gteq 1000
unit USD` be silently skipped by declaring any other currency, including a mere case
difference (`'usd'` vs `'USD'`). The currency comparison is also now case-insensitive.

**0.3.5 — a degraded claim now warns instead of only being silently tolerated.**
`claimAuthorization()`'s per-field cross-checks each skip when the issuer's claim response
omits that field — a deliberate, documented rolling-upgrade tolerance for a Service pinned
against an older backend whose response predates one of these fields existing at all. That
tolerance was never meant to also mask a REGRESSION on an otherwise-current backend: this
version logs (`console.warn`) whenever a value-bearing request's claim response omits
`agentDid`/`amount`/`currency`, or a request that signed a real `merchant` gets a claim
response that omits it — the one place a future backend change could quietly re-open the
confused-deputy gap this check exists to close, with nothing else here able to notice. The
decision is unchanged (still tolerated, not blocked) — this is visibility, not a new refusal.

**0.3.6 — two gaps a security review found in what this guard actually enforces, not just what
its docs claimed.** First: `requireAuthorization`'s doc only ever named replay and cumulative
spend as what it closes, but rate limits, circuit breakers, and spend-pattern anomaly detection
are equally stateful and equally invisible to the stateless bundle re-check — the doc undersold
its own scope. A value-bearing call permitted with `requireAuthorization` off now logs a warning
naming all five. Second: `guardIncomingTool`'s capability check only ran when the CALLER chose to
include `signed.capability` — an agent could simply omit it and the "authorize $150, execute
$5,000" protection never engaged, verifier configured or not. New `requireCapability: true` makes
an omitted capability a hard block (`CAPABILITY_REQUIRED`) instead of a silent pass-through. Both
off by default — existing embeds are unchanged.

**0.5.0 — the `keyProvider` seam
([docs/design/agent-key-custody-local-signer-daemon-plan.md](../../docs/design/agent-key-custody-local-signer-daemon-plan.md)).**
`serviceKey` no longer has to be a raw hex key living in this process. Pass
`keyProvider: 'daemon'` + `daemonSocketPath` instead, and `handshakeChallenge` gets its signature
from a separate `@metamynd/agentsafe-signer` daemon (`role: 'service'`) over a local socket — the
key never enters this process at all. `serviceKey` (unchanged) still works exactly as before and
remains the default. **Breaking, disclosed plainly**: `handshakeChallenge` and
`createHandshakeInitiator(...).prove()` are now `async` (a daemon-backed provider needs a socket
round trip); every caller needs an `await` added. New internal module `key-providers.mjs` — still
zero external dependencies.

**0.5.3 — `requireAuthorization`'s claim now actually enforces revoked authority and mandate
expiry, and the claim-binding check closes the action axis too.** A four-client readiness review's
P0 finding required a tested counterparty-verification pattern covering, by name, replay, wrong
identity, wrong action, expired mandate, and revoked authority. Building the end-to-end trial
against a real backend (not the mocked cases below) surfaced that two of those five were silently
unenforced at the claim step itself, not just untested:

- **Revoked authority.** Revoking a mandate (`POST /mandate/:ref/revoke`) only ever flipped the
  hold's `mandate_event.status` to `voided` — it never touched the `effect_transition` chain, and
  `markEffect`'s transition check only validated the state-machine shape (`authorized →
  dispatching` is always syntactically legal), never the hold's own status. A resource relying on
  `requireAuthorization` could successfully claim and execute a hold whose mandate had already been
  revoked. Now refused with `AUTHORIZATION_VOIDED`.
- **Expired mandate.** A hold's expiry (`isWithinHoldWindow`/the TTL) is a *derived* property —
  nothing writes it back to the row when time passes, so the same claim step had no way to see a
  hold was stale. Now refused with `AUTHORIZATION_EXPIRED`.
- **Wrong action.** `claimAuthorization()`'s mismatch checks compared the claimed hold's
  `agentDid`/`amount`/`currency`/`merchant` against the request being executed, but never `action`
  — because the backend's claim response never carried it. A real, unclaimed authorization minted
  for one action (e.g. `office-supplies-purchase`) could be claimed while executing a *different*
  action at the identical agent/amount/currency/merchant — the same confused-deputy shape the 0.3.6
  merchant check closed, one axis short. The backend now resolves and returns the hold's authorized
  `action` on claim (backward-compatible — an older backend simply omits it, same
  skip-when-absent tolerance as every other field here). Now refused with
  `AUTHORIZATION_ACTION_MISMATCH`.

All three are backend-side (`MandateService.markEffect`) except the action check, which also
needed this guard to compare the new field. See
[`docs/design/mcp-reverification-quickstart.md`](../../docs/design/mcp-reverification-quickstart.md) (§7)
for the end-to-end trial these gaps were found and closed against.

**0.5.1 — `keyProvider: 'daemon'` retries a transient connect failure.** Same fix as
`@metamynd/agentsafe-guard` 0.9.1: on Windows the signer daemon's socket is a pool of independent
named-pipe instances, each consumed by one connection and replaced asynchronously, so two
signing requests close together could race that replacement window and fail with
`DAEMON_UNREACHABLE` even though the daemon was healthy. `key-providers.mjs` now retries a
connection that fails with `ENOENT` for up to 3 seconds before giving up. No API change.

**0.11.0 — payload binding: the claim states what this Service will actually execute (MAGP §8.3.9, §8.7.11).**
`guardIncomingTool(action, handler, { bindPayload: true })` digests the tool's arguments (or `bindPayload: (signed, ...args) => value`
to choose), refuses locally (`PAYLOAD_NOT_BOUND`) when they differ from the digest the agent signed, and sends the digest with the
claim — in the `x-magp-payload-digest` header and as a signed field of the claim message — so the issuer compares it with the
digest it stored at authorize time and refuses a mismatch, leaving the hold unclaimed. `requirePayloadBinding: true` also refuses
an authorization the agent did not bind (`PAYLOAD_BINDING_REQUIRED`). A payload JSON cannot carry is refused
(`PAYLOAD_NOT_CANONICALIZABLE`), not skipped, and a grant that does not echo the digest (an issuer that predates binding) is
refused too. Both options are off by default; `verifyRequest(signed, { payloadDigest, requirePayloadBinding })` is the lower-level form.

**0.10.0 — the agent can no longer skip a risk rule by hiding or understating its risk (D-03).** The rules
now judge `riskLevel` with provenance (MAGP §6.3), identically to the issuer's gate:

- A missing or unrecognised `riskLevel` **escalates** (`CONTEXT_UNVERIFIABLE`) for any rule that uses the
  risk atom (it used to read as "not risky" and be allowed); `"HIGH"` is read as `high`. An agent that sends no
  `riskLevel` will now be escalated.
- **`trustedContext`** — what *this Service* derived from the real call, never from the agent. Pass it to
  `verifyRequest(signed, { trustedContext: { riskLevel: 'high' } })`, or per tool:
  `guardIncomingTool('wire-transfer', handler, { trustedContext: { riskLevel: 'high' } })` (an object, or
  `(signed, ...rest) => object`). It is applied over the agent's claim and labelled `gateway_derived`; the agent
  can raise its risk above it, never lower it below it. A deriver that throws, or that is configured but yields
  nothing usable (returns `undefined`, a non-object, or a `riskLevel` that is not a level), fails the call closed —
  it never falls back to the agent's word.
- The mandate's owner-set **`riskTier`** (in the signed bundle) is a further floor, so the agent's "low" about an
  action the owner classed `high` is judged `high`; and the SUPERVISED-mode high-risk escalation judges that
  effective risk too.
- A rule can demand a trusted source with `requireProvenance: { riskLevel: 'gateway_derived' }`.

Without `trustedContext`, an owner tier or `requireProvenance`, the agent's claim is still all the rules see —
this closes hiding and garbling; those three close understating.

**0.9.0 — a lost claim response no longer strands the hold, and a refused claim can be looked up.**
- Every claim now carries a fresh, unguessable `Idempotency-Key`, and a claim whose response never arrives
  (dropped connection, a 5xx) is **retried once with the same key**. If the first attempt had actually landed,
  the issuer recognises the retry as yours and returns your original grant (`claimAuthorization()` reports
  `replayed: true`) instead of refusing, so you can go on to execute. Before this, a lost response left the
  hold claimed with nobody executing it, committed to the cap until reconciled. The key is per call and never
  persisted: a restarted process, or a second request for the same authorization, gets no replay — a claim is
  still single-use. A definite answer is never retried; the issuer's `EFFECT_TRANSITION_CONTENDED` (an
  overlapping attempt of yours is mid-claim) is retried, since it is not a refusal.
- A second claim of the same authorization is now refused with the stable code
  **`AUTHORIZATION_ALREADY_CLAIMED`** whatever became of the first (it used to be
  `INVALID_EFFECT_TRANSITION` or `EFFECT_TRANSITION_CONTENDED` depending on timing).
- New `lookupOutcome({ authorizationId })` — what became of it? Returns `outcome`
  (`not_started | expired | in_flight | settled | not_executed | unknown | reversing | reversed |
  reversal_failed`) and two safety bits: `nothingExecuted` (nothing has run *so far*) and **`retrySafe`**
  (nothing can run *later* either — true only for `expired` and `not_executed`). Re-authorize and retry only on
  `retrySafe`. A `not_started` hold is `nothingExecuted` but **not** `retrySafe`: it can still be claimed until
  its window closes, so a request queued behind a slow gateway could run it while your retry runs too — void
  it first, then read `not_executed`. Use it after an `AUTHORIZATION_ALREADY_CLAIMED`, and never retry an
  `unknown` or `in_flight` outcome blindly.
- The idempotency key must stay secret from the agent (128 bits of randomness; the issuer refuses one under 32
  characters or containing the authorization id). Never use the authorization id as a *claim* key — it is the
  one thing the agent knows; it is only the right key to give an *upstream* to de-duplicate on.
- The authorization id is the effect's natural idempotency key: pass `decision.authorizationId` to an
  upstream that de-duplicates, and the effect is exactly-once even if you ever run the same call twice.
  (`@metamynd/agentsafe-http-gateway` 0.9.0 does this for you.) Needs an issuer that understands
  `Idempotency-Key` (MAGP §8.7.7); an older issuer ignores it and behaves as before.

**A claim refused with `COUNTERPARTY_NOT_REGISTERED` (or `COUNTERPARTY_AUTH_REQUIRED`).** The owner of the mandate has a registry of the
services that may claim their holds, and this Service is not on it — or it did not identify itself. Nothing was executed and the hold is
still claimable by a trusted service. Fix it on the owner's side, not in code: sign in as the mandate's owner, open **Trusted
Counterparties** in the dashboard (`/dashboard/counterparties`) and register this service's `serviceDid` (`did:key:…` or
`did:hedera:…`; the key must be inside the identifier), optionally scoped to the merchants it acts for. Until an owner registers
anyone the registry is open and no service is refused; registering the first one switches it on for that owner. Other codes from the
same check: `COUNTERPARTY_NOT_ALLOWED_FOR_MERCHANT` (the entry is scoped and this hold's merchant is not in scope) and
`COUNTERPARTY_MISMATCH` (a settlement call was signed by someone other than the service that claimed the hold).

**0.8.0 — a Service can prove who it is.** A claim token is a bearer secret: it proves "I made the claim",
not who you are. Give the guard a signing identity and it signs the claim and every settlement call
(capture / release / mark-unknown) instead:

```js
const guard = createMcpGuard({
  serviceDid: 'did:hedera:testnet:…',   // did:key or did:hedera; the key must be the one the DID commits to
  serviceKey: privateKeyHex,            // or keyProvider: a signing-capable provider
  issuerApi, requireAuthorization: true,
});
```

The issuer records `svc:<did>` as the claimer and only that identity can lower or void the hold; no
claim token is issued, so nothing can leak. The signature covers the action, the authorization id and
the amount/reason fields, plus a one-time nonce and timestamp, so a captured call can't be replayed or
edited. A `serviceDid` with no key (or a non-DID label) keeps the 0.7.0 token behaviour. Limits, stated
plainly: the issuer verifies the key controls the DID, not that the DID is one you trust — see spec
§8.7.6.

**0.14.0 — declare an x402 payment at the claim (`x402: true`).** A tool paid by x402 should say so when it claims:
`guardIncomingTool(action, handler, { x402: true })`, `verifyRequest(signed, { x402: true })` or
`claimAuthorization({ authorizationId, x402: true })`. The issuer then records the hold as **x402-bound**, and only an
x402-bound hold has a settlement *below* its authorization (or a release after the claim) confirmed by an independent
observer — the Hedera mirror node, from the `settlementTxHash` and `payTo` you state at capture. So after `settle()`
returns `txHash`, capture with `settlementTxHash: txHash, payTo: requirements.payTo`. A lower figure the observer can't
confirm is refused (`SETTLEMENT_NOT_CONFIRMED`); settling at the full amount needs no observer. Before 0.14.0 no guard
could set the flag, so SDK-claimed holds were never observed. Unset, the claim request is exactly as before.

**0.13.0 — a daemon-held service key signs claims and settlements too.** With `keyProvider: 'daemon'` (and an
`@metamynd/agentsafe-signer` 0.16.0+ daemon started `--role service`), `claimAuthorization`,
`captureAuthorization`, `releaseAuthorization` and `markAuthorizationUnknown` are signed as your `serviceDid`
by the daemon — the private key never enters this process. Before 0.13.0 a daemon-backed Service could only
claim anonymously, which is refused for every mainnet hold. A custom `keyProvider` may implement either
`signServiceMessage(message)` (sign the built message) or `signServiceCall({ serviceDid, action,
authorizationId, fields, nonce, issuedAt })` (the structured call). If signing fails — daemon not running,
or its identity is not `serviceDid` — the call is **not** sent anonymously: the claim returns `{ claimed:
false, reasonCode: 'SERVICE_SIGNING_FAILED' }` and the settlement helpers `{ ok: false, reasonCode:
'SERVICE_SIGNING_FAILED', error }`, without throwing.

**0.7.0 — the claim token is relayed, and a Service can close the hold it claimed.** The issuer now
treats a *claimed* hold as a commitment: it stays against the mandate's cap until it is settled (it no
longer lapses with the 15-minute hold TTL), and once claimed it can be settled *below* its amount, or
voided, only with the **claim token** returned by that hold's successful claim. Without that, an agent
could wait for a Service to execute and then capture `$0` (or void) its own hold to get the budget back
— 26 × $250 executed against a $5,000 cap that way. This package used to discard the token, so a Service
could neither settle below the hold nor release one after an upstream failure. Now:

- `verifyRequest()` / `guardIncomingTool()` return the token as `decision.claimToken` (and
  `decision.authorizationId`) on a claimed permit. They are **non-enumerable**, so an echoed,
  logged, spread or `JSON.stringify`-ed verdict does not carry the token to the calling agent —
  the one party that must not have it. Keep it server-side.
- New guard methods, all best-effort and non-throwing (they return `{ ok, reasonCode }`):
  `captureAuthorization({ authorizationId, claimToken, amountCharged, bookingRef?, settlementTxHash?, payTo? })`,
  `releaseAuthorization({ authorizationId, claimToken, reason? })`, and
  `markAuthorizationUnknown({ authorizationId, reason?, claimToken? })`. Since 2026-09-24 the issuer accepts
  mark-unknown only from the claimer (or the hold's owner or an admin): a Service whose claim was **anonymous**
  must pass that claim's `claimToken`; a Service that signed its claim (`serviceDid` + key) needs none — the call is
  signed. Without either, it is refused `COUNTERPARTY_MISMATCH`. (The agent-side `effectUnknown()` in
  `@metamynd/agentsafe-guard` is deprecated for this reason: the agent is not the claimer.)
  **0.15.0** — `refundAuthorization({ authorizationId, amount?, reason?, claimToken? })`, see [Refunds](#refunds-refundauthorization--since-0150).
  **0.11.4** — a successful call also spreads the issuer's response onto the top level of the returned object (same
  convention `lookupOutcome` already used): `result.settlementEvidence`, `result.amountCharged`, `result.authorizedAmount`
  are readable directly, not only via `result.data` (which is unchanged and still there).
  **0.12.2** — `payTo` (a Hedera account id or an EVM address): the account this service paid. Pass it whenever you
  settle **below** the authorized amount. If the owner lists that merchant's accounts (dashboard → Trusted
  Counterparties → Merchant payee accounts, MAGP §8.7.14) a lowered capture without a listed `payTo` is refused
  `PAYEE_NOT_REGISTERED`, and the settlement observer only counts a credit to the account you name. Since backend
  v1.68.2 a refused release (the owner forced the hold into reconciliation, or a claim landed first) is an HTTP 409;
  the returned `{ ok: false, reasonCode }` is the same as before.
- `guardIncomingTool(action, handler, { settle: true })` settles a handler that returns (at the
  authorized amount) and parks one that throws as **UNKNOWN** — it never *releases* on a throw, because a
  throw does not prove nothing was executed. Off by default: an existing embed is unchanged.
- **Release only what provably did not happen.** `releaseAuthorization` returns the budget. Use it when
  the upstream cleanly refused; use `markAuthorizationUnknown` for a timeout, a 5xx or a dropped
  connection, which keeps the spend committed and hands it to reconciliation. Failing to settle can only
  over-count spend, never under-count it.

### Refunds (`refundAuthorization`) — since 0.15.0

When you give money back for a hold you already **captured** (a cancelled booking, a returned item), record it
so the mandate's cumulative-spend cap stops counting it:

```js
await guard.refundAuthorization({ authorizationId, amount: 50, reason: 'customer-cancelled' }); // partial
await guard.refundAuthorization({ authorizationId });                                           // everything still captured
// → { ok: true, refundAmount, remainingCaptured, reasonCode: 'REFUNDED' }  or  { ok: false, status?, reasonCode }
```

It calls `POST /policy/mandate/authorize/:id/refund` and is **record-only**: MetaMynd moves no money, so returning
the funds stays your (or your facilitator's) job, exactly as the original charge was. Only a captured hold can be
refunded, and never for more than remains captured. **Only the hold's claimer** may refund it (or the hold's owner or
an admin, from their own session). A Service that signed its claim signs the refund as its `serviceDid` under the
dedicated `refund` action, over `[amount ('' for a full refund), reason]`, so a release signature can never be replayed
as a refund or the reverse. A Service whose claim was **anonymous** passes that claim's token:
`refundAuthorization({ authorizationId, amount, reason, claimToken: decision.claimToken })`. Anyone else is refused
`COUNTERPARTY_MISMATCH` (HTTP 403). This needs an issuer with the dedicated refund action; an older one checks a refund
as a `void` and refuses the signature (401 `COUNTERPARTY_SIGNATURE_INVALID`). A daemon-held key needs
`@metamynd/agentsafe-signer` 0.17.0. Best-effort and non-throwing, like the other settlement helpers.

### Computing the payload digest yourself (`payloadDigestOf`) — exported since 0.15.0

`guardIncomingTool(..., { bindPayload: true })` digests the tool's arguments for you. A Service that calls
`verifyRequest` directly must state the digest of what it is about to execute, computed with the **same**
canonicalisation the agent SDK and the issuer use. The helpers are exported from the package entry (and from
`@metamynd/agentsafe-mcp-guard/payload-binding`):

```js
import { createMcpGuard, payloadDigestOf, toWireJson } from '@metamynd/agentsafe-mcp-guard';

const wire = toWireJson(bookingRequest);          // the JSON value as it travels; execute THIS
const verdict = await guard.verifyRequest(signed, { payloadDigest: payloadDigestOf(wire) });
if (verdict.decision === 'allow' || verdict.decision === 'observe') await upstream.book(wire);
```

| Export | What it does |
|---|---|
| `payloadDigestOf(value)` | `"sha256:<64 hex>"` over the canonical JSON of `value`; throws `PayloadNotCanonicalizable` for a value JSON cannot carry exactly (NaN, a lone surrogate, a class instance, over 256 KiB or 32 levels) |
| `toWireJson(value)` | `value` after a JSON round trip (applies `toJSON`, drops `undefined`), so what you digest is what you send |
| `canonicalPayload(value)` | the canonical JSON text that is hashed |
| `isPayloadDigest(s)` | whether `s` is a well-formed digest |
| `PAYLOAD_DIGEST_HEADER` | `x-magp-payload-digest`, the header a claim carries it in |
| `PayloadNotCanonicalizable` | the error class thrown above |

### Pin the policy key (`policyPublicKey`)

The bundle is what `verifyRequest` enforces, so whoever can change it in flight can change the rules. Pin MetaMynd's
policy-signing key — fetch `GET /magp/policy/pubkey` once, out of band, and bake it into your config — and the guard
verifies every bundle's signature and freshness, refusing a tampered, unsigned or stale one for a value-bearing call
(`POLICY_BUNDLE_SIGNATURE_INVALID`, `POLICY_BUNDLE_UNSIGNED`, `POLICY_BUNDLE_STALE`). `create-metamynd-agent`'s gateways
pin it for you.

```js
const guard = createMcpGuard({ serviceDid, issuerApi: 'https://metamynd.ai/api/v1', policyPublicKey: '<hex from /magp/policy/pubkey>' });
```

**Since 0.12.0** a guard with no pinned key says so at startup, and one that fetches its bundle over plain `http://`
refuses value-bearing calls (`POLICY_BUNDLE_UNVERIFIED`): nothing authenticates that bundle, and an independent tester
used exactly that path to drop the spend cap and run a $5,000 over-cap purchase. Over `https://` it warns and carries
on (TLS authenticates the issuer). For local development only, `allowUnverifiedBundle: true` restores the old
behaviour. A custom `fetchBundle` is your own source and is not affected.

### Replay, cumulative spend, rate limits, breakers, spend anomalies (`requireAuthorization`)

Re-evaluating policy per request (above) proves the request is well-formed and in-policy — it
does **not** stop a captured, still-fresh request from being replayed, and it can't enforce the
mandate's TOTAL budget across many separately-legal calls (each is only checked against its own
per-transaction cap). Neither is something a stateless re-check can do on its own: both, like
rate limits, circuit breakers, and spend-pattern anomaly detection, key off the agent's history
on the issuer's side, which never travels to this guard's stateless bundle re-check. **All of
these are the stateful issuer gate's job.** `requireAuthorization` is the one setting that closes
all of them at once, because it forces the exact request back through that gate before this
Service executes anything. Left off, a value-bearing call permitted here logs a warning saying
exactly that, so the gap is visible in your own logs rather than silent:

```
[mcp-guard] "flight-purchase" (amount=100) permitted in trustless mode — rate-limit,
circuit-breaker, replay, cumulative-spend, and spend-anomaly floors are stateful and were NOT
re-verified against live issuer state. Set requireAuthorization:true for custodial/value-bearing
surfaces.
```

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

Presenting a capability is otherwise the **caller's** choice: an agent can simply omit
`signed.capability` and the check above never runs, verifier configured or not. Set
`requireCapability: true` to close that omission — a PERMIT with no capability is then blocked
(`CAPABILITY_REQUIRED`) instead of silently passing through unbound:

```js
const guard = createMcpGuard({ serviceDid, verifyCapability, requireCapability: true });
```

Off by default, so an existing integration whose callers don't yet present a capability keeps
working unchanged. Turn it on for any Service where the decision-token binding is meant to be
mandatory, not opt-in.

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

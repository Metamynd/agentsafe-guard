# AgentSafe A2A Guard — MAGP governance for the Agent2Agent protocol

The A2A sibling to [`agentsafe-mcp-guard`](../agentsafe-mcp-guard): MCP governs *tool calls*,
this governs *agent-to-agent task delegation*. Full design rationale and citations against the
real A2A protobuf spec (not the paraphrased prose docs) live in
[`docs/design/a2a-compatibility-scope.md`](../../docs/design/a2a-compatibility-scope.md) —
read that first if anything here seems under-explained.

A2A already gives you transport-level auth (`AgentCard.securitySchemes`) and a task-lifecycle
state machine. What it explicitly leaves as "application-level responsibility" is spend limits, a
policy engine, an audit trail, and any notion of accountability surviving a task handoff. This
package closes that the same way `agentsafe-mcp-guard` closes it for MCP: the **receiving** agent
independently re-verifies a signed MAGP envelope against the calling agent's own published
policy — it never trusts the caller's claim about what it's authorized to do.

- **Zero external dependencies.** Node's built-in Ed25519 (`node:crypto`) + `fetch`, plus two
  generated bundles (`policy-core.mjs`, `magp-did.mjs` — regenerate with
  `npm run build:a2a-guard-core` in `backend/`) and one hand-written one (`magp-policy.mjs`,
  an identical copy of the MCP guard's own — see that file's header for why it's duplicated).
- **No mutual handshake.** Unlike the MCP guard, this does **not** port MAGP §8.2's
  challenge-response identity proof — A2A already has transport-level auth and a discovery-time
  AgentCard exchange, so a second identity proof on top would duplicate work the base protocol
  already does for no added guarantee. Identity rides entirely in the per-message signed envelope.
- **Fail-closed.** A missing envelope, a bad signature, a stale request, a failed bundle fetch, or
  any error refuses the task. With `policyPublicKey` pinned, an unsigned or stale policy bundle
  refuses every task, amount 0 included (`POLICY_BUNDLE_UNSIGNED` / `POLICY_BUNDLE_STALE`) —
  since 0.13.1; before, only a value-bearing task was refused, so an interceptor could strip the
  bundle's proof and grant a delegated agent a task nobody gave it. With NO key pinned and the issuer
  on plain `http://`, nothing authenticates the bundle, so every task is refused
  (`POLICY_BUNDLE_UNVERIFIED`) — since 0.13.3; before, this guard accepted any task on such a bundle.
  `allowUnverifiedBundle: true` restores that, for local development only. Over `https://` it warns
  and carries on (TLS authenticates the issuer); a custom `fetchBundle` is your own source.
- **A refusal is a returned `TaskStatus`, never a thrown error.** A2A tasks have a formal state
  machine; unlike `guardIncomingTool`'s throw-based model, `guardA2ATask` returns a structured
  refusal your own server code folds into its response however your transport expects.

## 1. Where the envelope lives

`Message` has both an `extensions: string[]` field (URIs of extensions in use) and a
`metadata` struct (arbitrary JSON) — the protocol's own first-class place for exactly this,
not a workaround bolted onto a `DataPart` meant for task content:

```js
import { createGuard } from '@metamynd/agentsafe-guard';
import { buildA2AEnvelope } from '@metamynd/agentsafe-a2a-guard';

const guard = createGuard({ agentDid, agentKey, api: 'https://metamynd.ai/api/v1' });

const { metadata, extensions } = await buildA2AEnvelope(guard, {
  action: 'raise-purchase-order',   // = the target AgentSkill.id
  amount: 7_500, currency: 'USD', merchant: 'acme-supplies',
});

// Splice into your outgoing A2A Message:
const message = { role: 'user', parts: [{ text: 'Raise a PO for 20x monitors' }], metadata, extensions };
```

`buildA2AEnvelope` is a pure serialization adapter over `agentsafe-guard`'s existing, already
publicly-exported `buildSignedRequest` — no new signing code path, just a new shape for an
already-signed payload.

## 2. Trustless enforcement, per skill

```js
import { createA2aGuard } from '@metamynd/agentsafe-a2a-guard';

const guard = createA2aGuard({ issuerApi: 'https://metamynd.ai/api/v1' });

const raisePurchaseOrder = guard.guardA2ATask('raise-purchase-order', async (message, task) => {
  // your real skill logic — runs ONLY on a permit
  return { po: 'PO-10231' };
});

// Wire into your A2A server's task dispatch, however it calls skill handlers:
const result = await raisePurchaseOrder(incomingMessage, incomingTask);
if (result?.state) {
  // a refusal — a TaskStatus (state, message, timestamp). Return it as the task's status.
} else {
  // a permit — result is whatever your handler returned.
}
```

`skillId` is authoritative — never a claim read out of the message — the same confused-deputy fix
`guardIncomingTool` documents for MCP, one layer down: a guard registered for many skills must not
let a cheap skill's valid envelope run an expensive one's handler.

### The task input is held to what the agent signed (0.6.0, MAGP §8.3.9)

The eight signed fields do not cover a payee or an account number, so the input of a task is otherwise unbound. Pass
`payload` when building the envelope — for a skill guarded with `bindPayload: true` that is the message's `parts` — and the
agent also signs a digest of it (RFC 8785 canonical JSON). The receiver digests what it is about to execute, refuses a difference
(`PAYLOAD_NOT_BOUND`) without claiming, and states the digest in the claim it signs, so the issuer compares it with the one it
stored at authorize time and refuses a mismatch, leaving the hold unclaimed:

```js
// initiator
const env = await buildA2AEnvelope(guard, { action: 'book-hotel', amount: 250, payload: parts });
// receiver
const skill = a2a.guardA2ATask('book-hotel', handler, { bindPayload: true, requirePayloadBinding: true });
```

`bindPayload: true` hands the handler the same JSON snapshot that was digested; `bindPayload: (envelope, message, task) => value`
chooses what to digest instead. `requirePayloadBinding` also refuses an authorization the agent did not bind
(`PAYLOAD_BINDING_REQUIRED`) and needs `bindPayload` (without a digest of what the skill executes there is nothing to compare).
**Scope (`bindScope`, 0.7.0):** with `bindPayload: true`, `bindScope: 'parts'` binds only the message's `parts`, and
`bindScope: 'message'` binds everything a handler can read from the message — `parts`, `metadata`, `referenceTaskIds` and
`extensions` — minus the MAGP envelope itself (its metadata key and extension URI), which carries the digest and so cannot be
inside it. `a2aBindingValue(message, scope)` computes the value, so the initiator digests the same thing:

```js
import { a2aBindingValue } from '@metamynd/agentsafe-a2a-guard';
// initiator — build the message first (without the envelope), then bind all of it
const env = await buildA2AEnvelope(guard, { action: 'book-hotel', amount: 250, payload: a2aBindingValue(message, 'message') });
// receiver
const skill = a2a.guardA2ATask('book-hotel', handler, { bindPayload: true, bindScope: 'message', requirePayloadBinding: true });
```

Omitting `bindScope` keeps the 0.6 behaviour (`'parts'`) and logs a one-time warning, because a skill that reads `metadata`
would act on something the agent never signed. **The default becomes `'message'` in the next major version** — set
`bindScope` explicitly now to keep either behaviour across that change. The `task` argument is never covered by a scope; a
skill acting on it should return what it uses from a `bindPayload` function.

Both sides must digest the identical value — a receiver that widens `bindPayload` without the initiator matching it gets
`PAYLOAD_NOT_BOUND`, which is the mechanism working (find what differs, don't loosen it).
Input JSON cannot carry is refused (`PAYLOAD_NOT_CANONICALIZABLE`), and a grant that does not echo the digest (an issuer that
predates binding) is refused too. Both options are off by default; nothing changes for a skill that does not use them.

### The agent's context is read from `itinerary` (0.11.0)

The unsigned request context (`riskLevel`, `tool`, `piiPresent`, a mandate's context operands, …) travels in the envelope
as **`itinerary`** — the MAGP §8.2 wire name, what `buildA2AEnvelope` / agentsafe-guard's `buildSignedRequest` send, what
the issuer's gate reads, and what an `envelopeSignature` (context-claim binding) covers. `buildA2AEnvelope`'s `context`
parameter is unchanged; only the receiver changed. **0.10.0 and earlier read `context`**, so a guard-built envelope was
judged with no context at all: a rule that fires on a present value (`tool-not-allowed`, `model-not-allowed`,
`data-residency-violation`, `pii-present`, `text-matches`) let the task run, and an honest `riskLevel` or a mandate
context operand was refused. Upgrade receivers.

`context` is still read as a **deprecated alias** from hand-built envelopes. Refused `MALFORMED_REQUEST`: both present
and different (the receiver never picks one), the alias beside an `envelopeSignature` (that signature covers
`itinerary`), a context that is not a JSON object.

### The caller's context signature is verified (`requireContextSignature`, 0.12.0, MAGP §8.3.13)

The itinerary (and `trace` / `materiality`) is not in the signed message, so anything relaying the A2A message could
rewrite what your skill's rules judge — a blocked `tool` into an allowed one, `riskLevel: 'high'` into `'low'`. A
caller that signs its context (agentsafe-guard ≥ 0.17.0 does by default, so `buildA2AEnvelope` carries it) sends
`envelopeSignature`, and `guardA2ATask` / `verifyRequest` now check it the way the issuer's gate does, right after the
request signature and before any rule:

- **Present** → verified with the caller's key (the key in its DID) over `envelopeHashFor` — the gate's own function,
  bundled as `governance-envelope.mjs` — computed over the envelope as received and the exact `itinerary` object the
  rules then read (`unsignedContextOf`'s). A mismatch (altered after signing, another key, an empty or non-string value)
  is `CONTEXT_SIGNATURE_INVALID` → `TASK_STATE_AUTH_REQUIRED`. **0.11.0 and earlier ignored it** and ran the task on the
  altered context.
- **Absent** → judged exactly as before: the signature is optional.
- **`requireContextSignature: true`** (on `createA2aGuard`, or per skill on `guardA2ATask` / per call on
  `verifyRequest`, which override it) refuses an absent one: `CONTEXT_SIGNATURE_REQUIRED` → `TASK_STATE_AUTH_REQUIRED`.
  A relay can strip the signature as easily as rewrite the context, so turn this on where the caller's context drives a
  decision. `CONTEXT_SIGNATURE_REQUIRED` is receiver-only (the gate has no such option).

Both codes are exported as `CONTEXT_SIGNATURE_REASON_CODES`. A signed context is attributed to the caller, not proven
true — keep deriving what you can (`trustedContext`).

### Jurisdiction (signed, 0.10.0, MAGP §8.3.12)

`buildA2AEnvelope(guard, { ..., jurisdiction: 'SG' })` (agentsafe-guard ≥ 0.16.0) signs the jurisdiction into the
envelope (the v2 message: the eight fields, `MAGP-AUTH-v2`, the jurisdiction). The receiver's `verifyRequest`
rebuilds v2 when the field is present and v1 when it is absent — stripping, changing or adding it is
`SIGNATURE_INVALID` — and judges the mandate's allowed-jurisdictions term and the `jurisdiction-not-allowed` atom on
the **signed** value only (an `itinerary` jurisdiction is dropped). Refusals, exported as `JURISDICTION_REASON_CODES`:
`JURISDICTION_REQUIRED`, `JURISDICTION_NOT_ALLOWED`, and from the issuer's gate `JURISDICTION_MISMATCH` — **a
registered payee's country wins** over the signed one.

### Risk that cannot be hidden or understated (0.5.0)

Same as `@metamynd/agentsafe-mcp-guard` 0.10.0 (MAGP §6.3). A missing or unrecognised `riskLevel` in the
envelope's `itinerary` now **escalates** (`CONTEXT_UNVERIFIABLE`), `"HIGH"` is read as `high`, the mandate's
owner-set `riskTier` is a floor under the agent's claim, and `guardA2ATask(skillId, handler, { trustedContext })`
(an object, or `(envelope, message, task) => object`) lets the skill's author state the risk of THIS skill —
applied over the agent's claim, labelled `gateway_derived`, raisable by the agent but never lowerable. A deriver
that throws or yields nothing usable becomes a structured `GUARD_ERROR` refusal (never a fallback to the agent's
word). An envelope that sends no `riskLevel` will now be held for review (`TASK_STATE_INPUT_REQUIRED`).

### Retrying a lost claim, and looking up an outcome (0.4.0)

Each claim carries a fresh `Idempotency-Key` and is retried once, with the same key, when its response is
lost (no response, or a 5xx); the issuer recognises the retry as yours and returns the original grant
(`replayed: true`) rather than refusing, so a claim that landed but was never acknowledged no longer strands
the hold. A definite refusal, including the new stable **`AUTHORIZATION_ALREADY_CLAIMED`**, is never retried.
`lookupOutcome({ authorizationId })` reports what became of an authorization (`outcome`, and
`nothingExecuted` — nothing ran so far — and `retrySafe`, true only when nothing can run later either:
`expired` and `not_executed`, **not** `not_started`, which is still claimable until its window closes).
Same semantics as
`@metamynd/agentsafe-mcp-guard` 0.9.0 (MAGP §8.7.7–8.7.8).

**A claim refused with `COUNTERPARTY_NOT_REGISTERED` (or `COUNTERPARTY_AUTH_REQUIRED`).** The owner of the mandate has a registry of the
services that may claim their holds, and this agent is not on it — or it did not identify itself. Nothing was executed and the hold is
still claimable by a trusted service. Fix it on the owner's side, not in code: sign in as the mandate's owner, open **Trusted
Counterparties** in the dashboard (`/dashboard/counterparties`) and register this service's `serviceDid` (`did:key:…` or
`did:hedera:…`; the key must be inside the identifier), optionally scoped to the merchants it acts for. Until an owner registers
anyone the registry is open and no service is refused; registering the first one switches it on for that owner. Other codes from the
same check: `COUNTERPARTY_NOT_ALLOWED_FOR_MERCHANT` (the entry is scoped and this hold's merchant is not in scope) and
`COUNTERPARTY_MISMATCH` (a settlement call was signed by someone other than the service that claimed the hold).

### Proving who you are (0.3.0)

Pass `serviceDid` (a `did:key` / `did:hedera`) and `serviceKey` (the matching Ed25519 private key) and the
claim and the settlement calls are signed instead of relying on the bearer claim token. The issuer
records the identity as the claimer, only that identity can lower or release the hold, and no token is
issued. Same message format as `@metamynd/agentsafe-mcp-guard` 0.8.0 (spec §8.7.6).

### Settling the hold you claimed (0.2.0)

With `requireAuthorization`, a permit **claims** a hold at the issuer, which then stays against the
mandate's cap until settled and can be settled below its amount, or released, only with the **claim
token** from that claim. The guard now relays it: `decision.claimToken` / `decision.authorizationId`
on the permit (non-enumerable, so an echoed verdict never carries the token to the calling agent), plus
`captureAuthorization`, `releaseAuthorization` and `markAuthorizationUnknown` (best-effort, they return
`{ ok, reasonCode }` and never throw; on success (0.6.3) the issuer's response is also spread onto the top level —
`result.settlementEvidence`, `result.amountCharged` — not only reachable via `result.data`, same convention
`lookupOutcome` already used). `guardA2ATask(skillId, handler, { settle: true })` settles a skill
that returns and parks one that throws as UNKNOWN — it never releases on a throw. Same semantics as
`@metamynd/agentsafe-mcp-guard` 0.7.0; see its README for why release is reserved for a provable
non-execution. **0.7.1:** `captureAuthorization({ ..., payTo })` — the account this service paid. Pass it when you
settle **below** the authorized amount: for a merchant whose accounts the owner lists (MAGP §8.7.14) a lowered
capture without a listed `payTo` is refused `PAYEE_NOT_REGISTERED`, and the settlement observer only counts a credit
to that account. **0.8.0:** a skill paid by x402 declares it at the claim — `guardA2ATask(skillId, handler, { x402: true })`,
`verifyRequest(envelope, { x402: true })` or `claimAuthorization({ authorizationId, x402: true })` — so the issuer records
the hold as x402-bound and has an independent observer confirm any settlement below the authorization (state the
payment's `settlementTxHash` and `payTo` at capture). Unset, the claim request is unchanged.

**0.9.0:** `refundAuthorization({ authorizationId, amount?, reason?, claimToken? })` records a refund of a **captured**
hold (`POST /policy/mandate/authorize/:id/refund`). It is record-only: no money moves, but the mandate's cumulative cap
stops counting the refunded amount. `amount` omitted refunds everything still captured. Only the hold's claimer may
refund it (or its owner / an admin): with `serviceDid` + `serviceKey` the call is signed under the dedicated `refund`
action over `[amount ('' = full), reason]`; an anonymous claimer passes its `claimToken`. Anyone else: 403
`COUNTERPARTY_MISMATCH`. `markAuthorizationUnknown` takes `claimToken` too:
since 2026-09-24 the issuer accepts it only from the claimer, so an anonymous claim must pass its token.

**0.9.1:** a settlement refusal is `{ ok: false, status?, reasonCode, detail? }`, where `reasonCode` is always the issuer's
stable code (read from `data.reasonCode` first, then `message`) and the status is the one that code always has (MAGP
§8.7.8): state conflicts such as `NOT_HELD`, `HOLD_STATE_CHANGED`, `NOT_CAPTURED`, `ALREADY_REFUNDED` are 409,
`COUNTERPARTY_MISMATCH` is 403, an unknown id is `404 AUTHORIZATION_NOT_FOUND` (on `lookupOutcome` too). `detail` is a
sentence for logs; branch on `reasonCode`. Same as `@metamynd/agentsafe-mcp-guard` 0.15.1.

## 3. Decision → `TaskState`

| MetaMynd decision | `TaskState` | Why |
|---|---|---|
| `allow` / `observe` | `TASK_STATE_WORKING` | Permitted (observe is permit-but-flag, SAFR §11) |
| `escalate` | `TASK_STATE_INPUT_REQUIRED` | A HOLD, not a denial — poll `escalationId` in the attached message's metadata the same way every existing MetaMynd client already does |
| a signature/identity/envelope failure | `TASK_STATE_AUTH_REQUIRED` | The spec's own more precise state for exactly this |
| a policy refusal, or containment | `TASK_STATE_REJECTED` | Terminal; the specific reason still travels in the attached message's metadata |

## 4. What this does not cover (v1)

- **Multi-hop delegation** (A→B→C). One hop only, same starting scope the MCP guard had.
- **Formal extension registration** in any future AAIF extension registry. The extension URI
  (`MAGP_A2A_EXTENSION_URI`) is a documented, owned path for now.
- **Push-notification webhook signing.** Orthogonal to task-boundary enforcement.
- **AgentCard signature (JWS) verification.** Already solved by the base protocol.

## Testing

```
npm test        # node a2a-guard.smoke.mjs
```

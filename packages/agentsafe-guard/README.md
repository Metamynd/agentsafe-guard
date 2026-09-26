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

## The protocol

This guard is one implementation of an open specification. You do not have to use it — the
protocol is published so you can implement it yourself, verify a verdict independently, or
re-implement the gate:

**[MAGP v1.0 — MetaMynd Agentic Governance Protocol](https://metamynd.ai/en/developers/spec)**
([markdown](https://metamynd.ai/specs/magp-v1.0.md))

It defines agent identity, the canonical signed message (§8.3), the sixteen-stage order of
checks (§8.5), all 64 reason codes (Appendix A), delegation narrowing (§5.4), and evidence
you can verify offline without MetaMynd (§13.4). If you are writing a client in a language
other than JavaScript, read §8.3.3–8.3.5 first: key encoding, number stringification and
signed-vs-sent field identity each surface only as `SIGNATURE_INVALID`.

## Try it first — no account, no network

```bash
npx @metamynd/agentsafe-guard demo
```

Runs the policy engine in-process against a sample bundle and prints the verdict for a
dozen tool calls — allow, observe, block, escalate, quarantine — including the ones that
matter most: an agent that lies about its own spend in unsigned context, and a quarantined
agent refused before any rule is read. It mints an ephemeral key, never opens a socket, and
needs nothing from MetaMynd. Exits non-zero if any verdict disagrees with the policy, so
it doubles as a smoke test of the installed package.

You need an account only for what can't be enforced client-side: live policy edits,
cumulative spend caps, human escalation, and anchored evidence.

## Governance as a build step

```bash
npx @metamynd/agentsafe-guard verify
```

Asserts your agent **cannot** exceed its mandate, and exits non-zero if it can. Put it in
CI and a pull request that widens an agent's authority fails the build, which is a control;
a dashboard that would have shown you is not.

```
  ok   permits ordinary in-scope work
  ok   refuses an action the mandate never granted   → block/NO_PERMISSION_FOR_ACTION
  ok   refuses 501 against a cap of 500              → block/SOP_SPEND_CAP
  n/a  no merchant allow-list in this mandate
       EVERY merchant is permitted

  1 control(s) are not configured — reported, not passed.
  Fail the build on these with:  verify --require merchants
```

**A control the mandate does not set is reported, never passed.** That distinction is the
entire point, and it exists because the alternative shipped: our own public sandbox was
issued with an empty merchant list, an unapproved supplier was paid $250, and
`MERCHANT_NOT_ALLOWED` sat documented in the example's own glossary the whole time. A green
check on a control that does not exist is worse than no check.

`--require merchants,perTxn,cumulative` promotes "not configured" to a build failure — how
you state *our agents must carry a merchant allow-list* and find out when one does not.
`--json` for machine-readable output. Evaluation is local and pure: no holds are minted, no
nonces spent, no budget consumed, and a run costs one GET.

**0.6.0 — `amount-unknown`.** The same discipline applied to the amount itself: a spend cap
is only as good as the number it's checked against, and a signed-transaction or nested x402
payload can carry its amount somewhere a naive check never looks. `amount-unknown` is a
deny-by-default atom for exactly that case — an action whose value the gate can't determine
is blocked, not silently waved through an untested cap.

**0.6.2 — `amount-unknown` closes negative amounts too.** A negative `amount` (e.g. `-5`)
previously read as "a real, known number" and sailed straight past `amount-unknown` — and
past a naive `amount-over` cap, since `-5 > 500` is never true. An attacker submitting a
negative value could clear a spend cap for free, or erode a cumulative-spend tracker that
sums signed amounts over time. `amount-unknown` now fires on any non-finite, non-numeric,
**or negative** amount; a genuine `0` still passes.

**0.6.4 — a mandate's currency check no longer lets a PROHIBITION be dodged by relabeling
the currency.** A payAmount/cumulativeSpend constraint issued with a `unit` (currency) is
only satisfied in that currency — correct for a PERMISSION (fail closed to deny on a
mismatch), but a prohibition only fires when every one of its own constraints is satisfied,
so the identical "mismatch → not satisfied" rule let a prohibition like `payAmount gteq 1000
unit USD` be silently skipped by declaring any other currency, including a mere case
difference (`'usd'` vs `'USD'`). The currency comparison is also now case-insensitive.

**0.6.5 — `IDENTITY_KEY_MISMATCH`, a new reason code (now 63 total).** The backend gate
now cross-checks a resolved agent's registered public key against the key embedded in its
own self-certifying DID (`did:hedera` / `did:key`) before trusting a signature against it —
free, local, no network round-trip, since the DID already carries its own proof. Nothing in
this package's own evaluation changes; documented here because the count in this README and
the linked spec moved.

**0.6.6 — `SPEND_PATTERN_ANOMALY`, a new reason code (now 64 total).** The backend gate can
now escalate an otherwise-permitted decision whose amount deviates sharply from an agent's
OWN recorded spend history — a baseline the platform's trust-graph engine learns, not a
threshold a human pre-sets. Opt-in (`SPEND_ANOMALY_MODE=on`), off by default. Nothing in this
package's own evaluation changes; documented here because the count moved again.

**0.9.0 — the `keyProvider` seam
([docs/design/agent-key-custody-local-signer-daemon-plan.md](../../docs/design/agent-key-custody-local-signer-daemon-plan.md)).
`agentKey` no longer has to be a raw hex key living in this process. Pass
`keyProvider: 'daemon'` + `daemonSocketPath` instead, and every signature is produced by a
separate `@metamynd/agentsafe-signer` daemon over a local socket — the key never enters this
process at all. `agentKey` (unchanged) still works exactly as before and remains the default;
this is additive, not a replacement.**

**Breaking, disclosed plainly rather than silently shipped**: `buildSignedRequest`,
`signChallenge`, and `guard.handshake().prove()` are now `async` — they return a `Promise` of
what they used to return directly, because a `daemon`-backed provider genuinely needs a socket
round trip to produce a signature, and there is no honest way to make that synchronous. Every
caller of these three needs an `await` added. `authorize()` and `verifyKey()` were already
`async` and need no changes. New internal module: `key-providers.mjs` (exports
`createStaticKeyProvider`, `createDaemonKeyProvider`, and the resolution logic `createGuard`
itself uses) — still zero external dependencies, `node:crypto` + `node:net` only.

**0.9.1 — `keyProvider: 'daemon'` retries a transient connect failure.** On Windows the signer
daemon's socket is a pool of independent named-pipe instances (see
`@metamynd/agentsafe-signer`'s `windows-secure-pipe.mjs`); each instance is consumed by one
connection and replaced asynchronously, so two signing requests close together could race that
replacement window and fail with `DAEMON_UNREACHABLE` even though the daemon was healthy.
`key-providers.mjs` now retries a connection that fails with `ENOENT` for up to 3 seconds before
giving up — a genuinely unreachable daemon still fails fast on any other error. No API change.

**0.11.0 — `keyProvider: 'daemon'` now supports `signLocalDecision`.** A daemon-custody agent
gets the same local-first block/escalate/non-value-allow audit reporting the static-key provider
has had since 0.9.4 — `createDaemonKeyProvider` gained the fifth, optional `signLocalDecision`
method, and `@metamynd/agentsafe-signer`'s daemon gained the matching `sign-local-decision`
signing-socket operation. No change for a `createGuard({ agentKey })` caller.

**0.12.0 — passphrase-encrypted managed key delivery**
([docs/design/passphrase-encrypted-key-delivery-plan.md](../../docs/design/passphrase-encrypted-key-delivery-plan.md)).
A managed key can now be delivered as ciphertext instead of plaintext: set a passphrase at
issuance, and `agent.metamynd.json` carries `agentKeyEncrypted` (`agentKey: null`) instead of a
raw key. `createGuardFromConfig(source, { passphrase })` decrypts it in memory before building
the guard — see "Passphrase-encrypted managed key" above. New export from `key-providers.mjs`:
`decryptAgentKeyWithPassword` (a byte-for-byte, `node:crypto`-only reimplementation of the
backend's `encryptWithPassword`/`decryptWithPassword`, cross-verified against it). Fully
additive: a config without `agentKeyEncrypted` is loaded exactly as before, no passphrase needed.

**0.15.1 — the mandate can require payload binding (MAGP §8.3.9).** A mandate issued with `requirePayloadBinding: true` makes the gate refuse
an authorization for that action that carries no signed payload digest (`PAYLOAD_BINDING_REQUIRED`) and refuse to grant a claim on a hold that
has none — so the guarantee no longer depends on the agent or every executor opting in. `authorize({ …, payload })` is all a caller does; nothing
changes without the flag. The bundled `policy-core` gains the `requiresPayloadBindingFor` helper. See `docs/integration/payload-binding.md`.

**0.15.0 — payload binding through the signer daemon, and after a reviewer's MODIFY (MAGP §8.3.9, §8.3.11).**
Two gaps in 0.14.0 are closed:

- **A daemon-backed guard (`keyProvider: 'daemon'`) can now bind a payload.** It signs through the daemon's new `sign-payload`
  operation (`@metamynd/agentsafe-signer` **0.15.0**), so the key still never enters this process. Against an older daemon, `authorize({
  payload })` blocks with `PAYLOAD_BINDING_UNSUPPORTED` (naming the fix) instead of sending an unbound request.
- **`guard.bindPayload({ authorizationId, action, payload })` binds a hold that already exists and has no digest.** A reviewer's
  MODIFY changes the action this agent signed, so the hold it mints — or the one minted when the re-entered review is approved —
  carries none, and an executor that requires binding could never claim it. The agent signs a message that names the authorization
  (so the digest cannot be lifted onto another hold, and cannot be confused with the authorize-time binding) and the gate applies
  it only while the hold is live, unclaimed and unbound:

  ```js
  const status = await guard.escalationStatus(escalationId);            // approved, or modified
  const bound = await guard.bindPayload({ authorizationId: status.authorizationId, action, payload });
  if (!bound.bound) throw new Error(`payload not bound: ${bound.reasonCode}`);
  // then hand the executor a FRESH signed request for the same payload and the same authorization
  const signed = { ...(await guard.buildSignedRequest({ action, ...modified, payload })), authorizationId: status.authorizationId };
  ```

  It never throws for a gate answer: `{ bound: true, payloadDigest }` or `{ bound: false, reasonCode }` (`PAYLOAD_ALREADY_BOUND`,
  `AUTHORIZATION_ALREADY_CLAIMED`, `PAYLOAD_BINDING_NOT_CONFIRMED` from a backend that predates it, …). Needs a backend that knows §8.3.11.

**0.14.0 — sign the WHOLE payload, not just eight fields (MAGP §8.3.9).** The signed authorize message covers the
agent, action, amount, currency, merchant and resource — not a payee, an account number or a passenger list. Pass
`payload` to `authorize()` / `buildSignedRequest()` and the guard also signs a digest of it (RFC 8785 canonical JSON,
`sha256:`), bound to that one authorization:

```js
await guard.authorize({ action: 'wire', amount: 250, currency: 'USD', merchant: 'skyward-air',
  payload: { payee: { iban: 'NL91ABNA0417164300' }, reference: 'INV-1042' } });
```

The gate stores the digest with the hold, and the service that executes it (an `agentsafe-mcp-guard` with
`bindPayload`, or an `agentsafe-http-gateway`, both 0.11.0) must present the digest of what it is about to run: a claim
with a different payload is refused and the hold stays claimable. Pass the payload exactly as the service will receive
it as JSON. A payload JSON cannot carry (`NaN`, a function, a lone surrogate) or a `keyProvider` that cannot sign a
binding (the signer daemon, for now) **blocks** with `PAYLOAD_NOT_CANONICALIZABLE` / `PAYLOAD_BINDING_UNSUPPORTED` —
it is never sent unbound. Off unless you pass `payload`; the wire body is otherwise unchanged. Also from `guardTool`: have `mapArgs`
return `payload`. The gate echoes the digest it stored, and an agent that sent one **refuses a permit that does not echo
it** (`PAYLOAD_BINDING_NOT_CONFIRMED`, releasing the hold) — so a proxy that strips the fields, or a backend that predates
MAGP §8.3.9, is a loud failure, not a silently unbound request.

**0.13.0 — a risk rule can no longer be skipped by staying silent about risk (D-03).** The rule layer
now labels every context field with where it came from (`agent_asserted`, `agent_signed`,
`gateway_derived`, `authoritative`, `attested`; MAGP §6.3) and judges `riskLevel` accordingly:

- **A missing or unrecognised `riskLevel` escalates** (`CONTEXT_UNVERIFIABLE`) for any rule that uses the
  risk atom, instead of reading as "not risky". `"HIGH"` and `" high "` are read as `high`. **If your requests
  do not send a `riskLevel`, they will now escalate** — send one (`context: { riskLevel: 'low' }`), or have
  your mandate's owner set a `riskTier` (below) so the risk does not depend on you.
- **`riskTier` on a mandate permission** is the owner's classification of the action: a floor the agent's own
  claim can never lower (the effective risk is the *maximum* of the tier and the claim — an agent may raise
  its risk, never lower it). It travels in the signed mandate, so `evaluateLocally` and the issuer's gate agree.
- **`requireProvenance`** on a rule (`{ riskLevel: 'authoritative' }`) makes it demand a trusted source: the
  agent's own honest "low" is then not enough.
- `evaluateLocally` builds its context the same way, and judges the SUPERVISED-mode high-risk escalation on
  the effective risk.

The claim itself is still the agent's word when no owner tier, gateway derivation or `requireProvenance`
exists: this closes hiding and garbling risk, and gives owners the means to close understating it.

```yaml
# .github/workflows/governance.yml
name: Governance
on: [push, pull_request]

jobs:
  mandate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: '20'
      - run: npx @metamynd/agentsafe-guard verify --require merchants,perTxn
```

`agent.metamynd.json` holds no secret beyond the agent key, so commit a key-less config and
set `AGENT_KEY` in the environment — `AGENT_KEY`, `AGENT_DID` and `METAMYND_API` all
override the file when present.

### As a packaged Action

Same check, packaged so you don't hand-roll the workflow above — and it writes a
pass/fail table straight into the PR's checks summary instead of a log a reviewer has to
open:

```yaml
# .github/workflows/governance.yml
name: Governance
on: [push, pull_request]

jobs:
  mandate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: Metamynd/agentsafe-guard/packages/agentsafe-guard@v0.5.3
        with:
          config: ./agent.metamynd.json
          require: merchants,perTxn
        env:
          AGENT_KEY: ${{ secrets.AGENT_KEY }}
```

Pinned to a released tag, the same way you'd pin any third-party action — not `@main`,
which moves under you every time this repository resyncs. The action's tag is a release tag of the
public [`Metamynd/agentsafe-guard`](https://github.com/Metamynd/agentsafe-guard/tags) repository (latest `v0.5.3`),
not the npm version of this package; the npm package the action runs is chosen by its `version` input. Inputs: `config` (default
`./agent.metamynd.json`), `require`, `version` (the `@metamynd/agentsafe-guard` npm range
to run, default `latest`), `working-directory`. Output: `ok` (`"true"`/`"false"`), if a
later step needs to branch on the result.

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

A block/escalate/non-value-allow decided locally is still reported to the gate as a
best-effort, signed **local decision receipt** — visible in the Activity Log and fleet
decision-mix, but not anchored/evidence-grade (see "Trust model" below). This never
blocks or delays the call above it.

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

### Push invalidation (`watchPolicy`)

By default a rule change is picked up within the bundle's `maxStaleness` (or on the
next on-chain check). `guard.watchPolicy()` subscribes to a Server-Sent-Events stream
(`GET /policy/events/:did`, zero-dep — plain `fetch`) so a change **invalidates the
guard's cache in ~1s** and the next call re-fetches (and re-verifies) the new rules.
It auto-reconnects; a dropped stream still leaves staleness + the on-chain check as the
floor, so a missed push degrades latency, never safety.

```js
const stop = guard.watchPolicy((change) => console.log('rules changed', change));
// … later: stop.close();
```

### Bring your own key (BYOK)

Provision the agent with your **own** public key so MetaMynd never sees the private key. The identity
is issued unverified with a one-time `challenge`; the gate blocks it (`AGENT_KEY_UNVERIFIED`) until you
prove control. The guard signs the challenge with your key and submits it:

```js
const guard = await createGuardFromConfig('./agent.metamynd.json', { agentKey: myPrivateKey });
await guard.verifyKey({ ref: config.identityId, challenge: config.challenge, token: ownerToken }); // one-time
```

`await guard.signChallenge(challenge)` returns just the hex signature if you'd rather submit
verify-key yourself. (Fastest path: `npm create metamynd-agent@latest -- --byok` does all of this
for you.)

### Passphrase-encrypted managed key

If you didn't set a passphrase at issuance, a managed key is delivered **plaintext** — the
`agentKey` field in `agent.metamynd.json` is usable as-is. Setting a passphrase (Launchpad's
Identity stage, or `passphrase` on `POST /onboarding/agent`) instead delivers an
`agentKeyEncrypted` object and leaves `agentKey: null`; decrypt it in memory when you load the
config:

```js
const guard = await createGuardFromConfig('./agent.metamynd.json', { passphrase: myPassphrase });
```

This is strictly better than a plaintext file sitting on disk, in an email attachment, or in a
`git add .` — but strictly weaker than `keyProvider: 'daemon'` (no key material in this process
at all): the decrypted key still lives in this process's memory for as long as it runs.
**Passphrase loss is unrecoverable**, the same as a lost BYOK private key — MetaMynd never sees
or stores the passphrase itself, so there is nothing to reset. Omitting `{ passphrase }` when the
config actually needs one throws a clear, specific error rather than the generic "requires
agentKey or keyProvider" message.

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
  `await guard.authorize({ action, amount, merchant, resource, context })` there and refuse on any
  non-`allow`. `resource` is a genuine, non-spoofable "what this action touches" declaration —
  checked against a mandate's `{leftOperand:'resource'}` constraint the same way `merchant` is
  checked against its own allow-list, and just as much a SIGNED field (tampering with it after
  signing fails the request with `SIGNATURE_INVALID`, not a silent bypass).
- **`context`** is what the Standard/SOP atoms read (jurisdiction, model, tool, PII, risk, …). Each
  atom declares what it needs — fetch the catalog at `GET /api/v1/standards/atoms` to see the exact
  fields (`requiredContext`) for the rules your agent is bound to.
- For **payment** tools (x402, §7a): after `authorize` allows, the Service returns a 402 bound to
  your `authorizationId`. Call `guard.preparePayment(requirements, authorizationId)` — it refuses an
  unbound or mismatched 402 — pay via x402, then reconcile the hold with
  `await guard.capture(authorizationId, amountCharged, bookingRef, settlementTxHash)`. An
  uncaptured hold auto-voids at its expiry (`POST /policy/mandate/authorize/:id/void` to release early).
- **An ambiguous outcome (a timeout, a lost response) is reported by the service, not the agent.**
  `guard.effectUnknown()` is **deprecated since 0.15.4** and rejects immediately (`EffectUnknownNotSupported`,
  `code: 'EFFECT_UNKNOWN_AGENT_UNSUPPORTED'`) without calling the gate. Since 2026-09-24 the gate accepts
  `effect/unknown` only from the party that **claimed** the hold, the hold's owner, or an admin — and the agent is
  none of them, so the call was always refused. The executing service reports it with
  `@metamynd/agentsafe-mcp-guard`'s `markAuthorizationUnknown({ authorizationId, reason, claimToken })` (signed as its
  `serviceDid`, or with the `claimToken` its claim returned), or the owner does. An agent that needs to follow the
  outcome polls `guard.effectStatus(authorizationId)`. The export stays so existing imports keep working; remove the
  call from your code.

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

### Execution adapters (dry-run / sandbox) — SAFR §19

By default a permitted (`allow`/`observe`) tool runs its real handler. An **ExecutionAdapter**
interposes between the verdict and the side-effect, so the *same* governed decision can be run
live, **simulated (dry-run)**, or routed to a sandbox — without changing the handler or the gate.
A blocked/escalated action still throws `GovernanceBlocked` before any adapter is consulted.

```js
import { dryRunExecutionAdapter } from '@metamynd/agentsafe-guard';

// Guard-wide (or set AGENTSAFE_EXECUTION_MODE=dry-run):
const guard = createGuard({ api, agentDid, agentKey, executionAdapter: dryRunExecutionAdapter });

// …or per tool (overrides the guard default):
const preview = guard.guardTool('flight-purchase', bookFlight, mapArgs, { executionAdapter: dryRunExecutionAdapter });
await preview({ amount: 100 }); // → { dryRun: true, action, decision, authorizationId, args } — bookFlight NEVER runs

// Custom adapter: run the real handler, or substitute it. `proceed()` invokes handler(args, decision).
const sandboxed = (ctx) => ctx.action === 'flight-purchase' ? sandboxBook(ctx.args) : ctx.proceed();
```

Contract: `async ({ action, args, decision, proceed }) => result`. Call `proceed()` to execute for
real; return without it to substitute the side-effect. Self-check: `node execution-adapter.smoke.mjs`.

Signed request fields (`amount`, `merchant`, `resource`) are always applied over the unsigned
`context`, so a forged context key can never shadow them (MAGP §6.4.2). Run the self-check:

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
const { sigA, handshakeId } = await hs.prove({ nonceA, challenge });  // verifies the Service, → send PROVE
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

Either way, every decision is Ed25519-authenticated and deterministic. A decision that round-trips
the gate — a sealed value action, or `mode:'remote'` — is also **anchored as evidence** (visible in
the dashboard's Regulator log and on HashScan). A purely local-first decision (the default mode's
block/escalate/non-value-allow — see "Enforcement mode" above) is NOT anchored, but is still
recorded for Activity Log / decision-mix visibility via a best-effort signed receipt (no hold, no
spend check, not evidence-grade) — `guardToolLocal()`'s pure-offline path has no server-side trail
at all, by design.

# create-metamynd-agent

Scaffold a **MetaMynd/AgentSafe-governed** AI agent in one command. It logs you in, provisions the
agent in a **single call** (identity + mandate + starter SOP + all enforced Standards), writes a
portable `agent.metamynd.json`, and drops a runnable agent that gates a tool through the
[`@metamynd/agentsafe-guard`](https://www.npmjs.com/package/@metamynd/agentsafe-guard) — **plus, by
default, a second `gateway/` process** built on
[`@metamynd/agentsafe-mcp-guard`](https://www.npmjs.com/package/@metamynd/agentsafe-mcp-guard) and
[`@metamynd/agentsafe-http-gateway`](https://www.npmjs.com/package/@metamynd/agentsafe-http-gateway).
The agent's own `guardTool()` call is a fast, local, client-side check; the gateway is the real
enforcement boundary — see [Separate tool gateway](#separate-tool-gateway-default) below.

> **Prerequisite:** an agent is always owned by a person/org with a **MetaMynd account**. The hosted
> flow provisions under your account's **verified principal** (KYC/KYB; on a beta deployment the
> platform can auto-approve one on first use) — if there is none, provisioning stops with "complete
> KYC/KYB first". That is all it needs: this CLI always provisions **Testnet** agents, so mainnet
> eligibility is not required. A mainnet agent is launched from the dashboard's **Launchpad**
> (`/dashboard/launchpad`) and needs a **mainnet-eligible** principal (verified by the identity
> provider, or reviewed by a person on the platform's team). `--harness` and `--sandbox` need no
> account or verification at all.

## Free local harness (no account, no network, `--harness`)

> **Without MetaMynd, you can be bypassed.** `--harness` proves your policy logic works — it does
> not enforce it against a caller trying to get around it. See [What this is not](#what-this-is-not)
> below before you rely on it for anything beyond testing rules.

```bash
npm create metamynd-agent@latest -- --harness   # or: npx create-metamynd-agent --harness
```

No login, no KYB, **no network call at all** — generates a local identity and a local rules file
(mandate + starter SOP), and scaffolds a project whose `guardTool()` calls are decided entirely on
your machine by the same deterministic evaluator ([`policy-core`](../agentsafe-guard/policy-core.mjs))
the hosted gate runs. An escalated action is held for **you** to approve at a small local dashboard
(`http://127.0.0.1:4400` by default) — there's no hosted owner queue in this mode, because there's
no hosted anything. Real gating, your own rules, free, forever.

```
my-agent/
├─ agent.metamynd.json      # a locally-generated identity — NOT anchored/verifiable
├─ metamynd-rules.json      # your rules — edit by hand, or at the dashboard
├─ metamynd-harness.log.jsonl  # every decision, append-only
├─ harness-server.mjs       # the local dashboard: rules, pending approvals, decision log
├─ index.mjs                # runnable example: ALLOW · BLOCK · ESCALATE (approve locally) · BLOCK
└─ package.json / .gitignore / README.md
```

### What this is not

**Without MetaMynd, you can be bypassed.** Everything below is why, precisely.

No anchored or cross-party-verifiable identity, no dashboard reachable when your machine is off, no
owner queue someone *else* can approve from, no anchored evidence, no enforced platform Standards.
That set of things is the hosted platform — and getting there later is a **config change, not a
rewrite**: the exact same `guardTool()` call your harness project already makes just needs a real
`bundleUrl`/`api` pointed at a real gate (provision normally, without `--harness`) instead of a rules
file you authored yourself. Nothing about how you wrote your agent changes.

It is also **not a separate enforcement boundary**, and this matters more than the list above.
`guardToolLocal()` is a cooperative library your own process embeds — call the raw handler directly
instead of the guarded one and nothing stops you, because there is no second party in the loop to
disagree with you. Confirmed by direct testing: a bypass attempt (skip the guard, call the tool
function underneath it) succeeds every time, structurally, not as a bug. What actually closes this
is a **counterparty** — a separate process holding the tool, that independently re-verifies the
agent's signed authority for itself rather than trusting that the agent's own guard ran. `--harness`
never has one, by design (there's no second party on one machine with no network). **Just dropping
`--harness` is not enough on its own to get one either** — see
[Separate tool gateway](#separate-tool-gateway-default) below for what actually provides it, and
`--no-gateway`'s own caveat for what happens if you opt out of it.

Works with `--config` too — its `rules` become the harness's starter rules file, same as the hosted
flow. See [Policy config file](#policy-config-file---config) below.

The dashboard's rules panel is a real editor, not just JSON with input boxes: edit an existing
rule's values, **delete** a rule, or **add a new one** from a form (predicate + its typed config
fields + decision) driven by the same atom catalog and validator
([`policy-core`](../agentsafe-guard/policy-core.mjs)) the hosted gate itself uses — so nothing you
add through it can be invalid. Hand-editing `metamynd-rules.json` still works too, if you prefer.

## Try it instantly — sandbox (no account, no KYB)

```bash
npm create metamynd-agent@latest -- --sandbox   # or: npx create-metamynd-agent --sandbox
```

Skips login and provisioning entirely — fetches a **shared sandbox agent** config from the public
`POST /onboarding/sandbox` endpoint and scaffolds a runnable example. Unlike `--harness`, this DOES
call the hosted API (a shared demo identity) — it's a first look at the *hosted* platform, not a
local/offline mode. Great for a first look; use the full flow below when you want your own governed
agent with your own limits.

`--sandbox` always scaffolds the single-process shape (no `gateway/`) — it's a shared identity never
meant to hold real credentials, so there's nothing here worth a separate enforcement boundary for.
Note this is a narrower gap than `--harness`'s: `--sandbox` DOES call MetaMynd for the decision, it
just still has nowhere else for the tool to live, so the same in-process bypass applies regardless.
The generated project's own README says so. The full flow below is what scaffolds one by default.

## Use

```bash
npm create metamynd-agent@latest
# or
npx create-metamynd-agent
```

Answer a few prompts (API, owner email/password, agent name, scope, per-transaction cap) and you get
**two** scaffolded projects — the agent, and its tool gateway:

```
my-agent/
├─ agent.metamynd.json   # portable guard config — HOLDS THE AGENT SECRET KEY (gitignored). This
│                         # is the freshly-minted key from THIS scaffold, not a re-download — the
│                         # dashboard's own "Redownload config" for an EXISTING agent never re-issues
│                         # the key into a downloaded file (it's excluded there by design). --byok /
│                         # --daemon-socket instead keep the key off this CLI's process entirely.
├─ index.mjs             # runnable example: signs + calls ./gateway; guardTool() here is a
│                         # fast local pre-check, NOT the enforcement boundary
├─ package.json          # depends on @metamynd/agentsafe-guard
├─ .gitignore
├─ README.md
└─ gateway/               # a SEPARATE process — the real enforcement boundary. Read its
    ├─ server.mjs         # README first if you only read one.
    ├─ package.json       # depends on @metamynd/agentsafe-mcp-guard + @metamynd/agentsafe-http-gateway
    ├─ .env.example       # real tool credentials go here, never in the agent directory
    ├─ .gitignore
    └─ README.md
```

Then, in **two terminals** — the gateway first:

```bash
cd my-agent/gateway
npm install
npm start
```

```bash
cd my-agent
npm install
npm start
```

### Separate tool gateway (default)

This is the other half of **without MetaMynd, you can be bypassed**: WITH it — specifically, with
`gateway/`, the second process this scaffolds by default — calling the tool directly instead of
through the check no longer works, the same way the hosted platform's own MCP counterparty can't
be talked around by a compromised agent. See [What this closes, precisely](#what-this-closes-precisely)
below for exactly what that covers, including the one gap found while building it that isn't
closed yet.

`guard.guardTool()` in `index.mjs` still runs — it's a fast, local, client-side pre-check that gives
good UX (fail fast on an obviously-blocked call, no round trip) — but it is **not** what stops a
bypass. It still calls its handler in the SAME process regardless of where the decision came from,
so anything able to call that handler directly gets the same result the gate would have given it.

What actually stops that bypass is that `bookFlight()` doesn't exist in the agent's process at all.
It exists only in `gateway/server.mjs` — a separate process, started separately, holding any real
tool credentials the agent process never sees — which independently re-verifies every request
against the agent's own published policy bundle before running it, **binds that request to the
actual body being executed** (`@metamynd/agentsafe-http-gateway` ≥ 0.4.0), and requires the
agent's `authorizationId` to atomically claim single-use execution against the real stateful gate
(`requireAuthorization`, `@metamynd/agentsafe-mcp-guard` ≥ 0.3.0) — closing a confused-deputy gap
and a replay/cumulative-spend gap, both found during independent testing. Same shape as the mutual
counterparty check in [`@metamynd/agentsafe-mcp-guard`](https://www.npmjs.com/package/@metamynd/agentsafe-mcp-guard),
built with [`@metamynd/agentsafe-http-gateway`](https://www.npmjs.com/package/@metamynd/agentsafe-http-gateway).
It's a minimal slice of the fuller pattern proven end to end in `demo/duffel-mcp-gateway` in the
AgentSafe repo (mutual handshake, x402 payment binding, capability tokens) — this scaffold gives
you the parts that close direct-call, confused-deputy, replay, and cumulative-spend bypasses, not
the whole protocol.

#### What this closes, precisely

Named precisely, not left implicit:

- **Direct call.** `bookFlight()` doesn't exist in the agent's process.
- **Payload binding is ON by default (0.11.0, MAGP §8.3.9).** The generated agent signs the COMPLETE body it sends as a payload, the
  authorization it gets from the gate is bound to that same body, and the generated gateway sets `requirePayloadBinding: true`: it
  digests the body it is about to run and the issuer refuses the claim unless that is the digest the agent signed. The eight
  signed fields only ever covered amount and merchant; this covers the value of every field the route allows (a payee, a passenger
  list you add). A request that bound no payload is refused (`PAYLOAD_BINDING_REQUIRED`) rather than run unbound. If you add a body
  field, add it to `allowedFields` **and** to the `payload` the agent signs (both sit next to each other in the generated files).
  A scaffold that signs through the signer daemon (`--byok --daemon-socket`) needs `@metamynd/agentsafe-signer` 0.15.0 or later. The
  hosted non-financial scaffold reads nothing from its body, so there is nothing for it to bind, and a scaffold with no gateway
  (`--no-gateway`, or `--sandbox`'s in-process demo) has no separate executor to hold to the digest, so it stays as it was.
- **Confused deputy (payload).** Signing a cheap request while executing an expensive one (a
  different amount/merchant in the body than what was signed) is refused before the tool runs —
  payload binding (`@metamynd/agentsafe-http-gateway` ≥ 0.4.0). The default binder requires
  `amount`/`merchant` to actually be found in the body whenever the signed request names a real
  value for them — not just "did the body offer at least one correct-looking field." A first
  attempt at this (0.3.0) checked the weaker version and was re-tested and closed the same day: a
  correct decoy in one field (e.g. a matching `merchant`) let the OTHER field hide anywhere —
  nested, renamed, an array, or an entirely empty/non-JSON body.
- **Replay.** A captured, resent request fails to atomically claim single-use execution the second
  time — `requireAuthorization`.
- **Cumulative spend.** The claimed authorization only exists because the real stateful gate
  already checked it against the mandate's TOTAL budget when minted, not just this one request's
  amount — so many small legal-looking calls can't add up past the cap this way.
- **Amount unknown.** Two separate places this matters, both actually authored, not just
  available: the platform's own custodial-signing tools (`@metamynd/agentsafe-guard` ≥ 0.6.0,
  `@metamynd/agentsafe-mcp-guard` ≥ 0.3.0) block by default when a signed-transaction tool's raw
  bytes or a nested x402 payload hide the amount from a naive spend cap — AND this agent's own
  starter SOP puts the same `amount-unknown` check ahead of its per-transaction cap (both the
  hosted default and `--harness`'s local one). The atom existing was not the gap: for a while
  this SOP still only ever authored `amount-over`, which silently does not fire on a missing or
  string amount (`typeof c.amount === 'number'` is false either way) — a real, live-confirmed way
  to slip a booking's cap untested. Fixed at the template, not just the atom registry.

The claim above also checks `agentDid`/`amount`/`currency`/`merchant` together against the
request being executed (`@metamynd/agentsafe-mcp-guard` ≥ 0.2.1) — a same-amount, same-currency
authorization legitimately obtained for one merchant cannot unlock a booking with a different
one. That gap was found while building this and closed, not left open; `gateway/README.md`'s own
"What this closes, precisely" section names it the same way.

Pass `--no-gateway` to opt out and get the old single-process scaffold instead — e.g. if you're
already running your own separate gateway and don't need this one. **You are back to being
bypassable if you do**, for the same structural reason `--harness` is; the generated project's own
README says so plainly.

## Non-interactive

Every prompt has a flag or environment-variable fallback, so it scripts cleanly in CI:

```bash
npx create-metamynd-agent \
  --api http://localhost:9926/api/v1 \
  --email owner@example.com \
  --name "Support Bot" \
  --scope flight-purchase \
  --per-txn-max 500 \
  --out ./support-bot \
  --yes
# password via env (never on the command line where it lands in shell history):
METAMYND_PASSWORD='…' npx create-metamynd-agent --yes …
```

| Flag | Env | Default |
|---|---|---|
| `--harness` | — | off (no login/KYB/network at all; free local governance — see above) |
| `--gateway` | — | off — `--harness` only; ALSO scaffold a second local process (still zero network, zero account) that independently re-verifies every request via the real `@metamynd/agentsafe-mcp-guard`. Does not close nonce replay/cumulative spend — see the generated `harness-gateway/README.md#--gateway`. |
| `--sandbox` | — | off (skips login/KYB; shared sandbox agent, still hosted) |
| `--config <file>` | — | a JSON policy file — see [Policy config file](#policy-config-file---config) |
| `--non-financial` | — | off — the agent does not move money: no spend limits, no payment demo, demo derived from your own rules. Works in every mode: `--harness`, the default hosted flow, `--sandbox`, and `--request` / `--claim`. Implied by a `--config` file with no spend limit, no `merchants` and no monetary rule; `--financial` opts back in. See [Non-financial agents](#non-financial-agents). |
| `--no-gateway` | — | off — hosted flow only; skips the default separate tool gateway (see above) |
| `--gateway-port <n>` | — | `4401` — hosted flow or `--harness --gateway`, the gateway process's port |
| `--force`, `-f` | — | off — scaffold into a non-empty directory, overwriting existing files |
| `--port <n>` | — | `4400` — `--harness` only, the local dashboard's port |
| `--api <url>` | `METAMYND_API` | `https://metamynd.ai/api/v1` |
| `--email <email>` | `METAMYND_EMAIL` | — (required) |
| `--password <pw>` | `METAMYND_PASSWORD` | interactive masked prompt |
| `--name <name>` | — | `Support Bot` |
| `--scope <scope>` | — | `flight-purchase` |
| `--per-txn-max <n>` | — | `500` |
| `--max-amount <n>` | — | `10000` |
| `--currency <cur>` | — | `USD` |
| `--merchants <a,b>` | — | any |
| `--byok` | — | generate the keypair locally, provision + prove control |
| `--public-key <hex>` | — | BYOK with a key you already hold (you prove control yourself) |
| `--daemon-socket <p>` | — | `--byok` via an already-running agentsafe-signer daemon instead of locally (needs `--daemon-admin-socket` too) |
| `--daemon-admin-socket <p>` | — | that daemon's admin socket, for `generate-key` |
| `--out <dir>` | — | `./<agent-slug>` |
| `--yes`, `-y` | — | non-interactive |

Run `npx create-metamynd-agent --help` for the full list.

## Policy config file (`--config`)

Everything above works from flags and prompts, which is fine for one agent but tedious to check
into source control or hand to a teammate. `--config <file>` reads a plain **JSON** file instead —
no YAML, no new dependency, so the CLI stays exactly as dependency-free as the guard it scaffolds:

```json
{
  "name": "Procurement Agent",
  "scope": "purchase-order",
  "currency": "USD",
  "maxAmount": 20000,
  "perTxnMax": 2000,
  "merchants": ["acme-supplies", "northwind-rail"],
  "rules": [
    { "when": { "predicate": "amount-over", "config": { "limit": 2000 } }, "then": "escalate" },
    { "when": { "predicate": "risk-at-or-above", "config": { "level": "high" } }, "then": "block" }
  ]
}
```

```bash
npx create-metamynd-agent --config ./procurement.policy.json --email you@example.com --yes
```

`rules` is sugar for the common one-atom-one-decision case — each entry compiles to a starter-SOP
molecule (`when.predicate` + `when.config` becomes the atom, `then` becomes the decision). See the
[protocol spec's atom catalog](https://metamynd.ai/developers/spec) for the full predicate list
(`amount-over`, `risk-at-or-above`, `jurisdiction-not-allowed`, `merchant`-style checks, and more).
If you need a real multi-atom/combinator molecule, supply `molecules` directly instead (the same
shape the dashboard's SOP editor produces) — `rules` is ignored when `molecules` is present.

Any CLI flag still overrides the matching field from the file (`--config base.json --name "Other
Bot"`), and login credentials are never read from the file — use `--email`/`METAMYND_EMAIL` and
`METAMYND_PASSWORD` as usual, so a policy file is safe to commit.

## Non-financial agents

Not every governed agent moves money. A customer-communications, healthcare-referral or
recruitment agent has no per-transaction cap and no currency, and a scaffold that invents them —
or demonstrates a flight booking — teaches the wrong policy. This works with `--harness` **and**
with the default hosted flow (login + provision):

- **A `--config` file is the whole policy.** If it sets no `perTxnMax` / `maxAmount` / `currency`,
  lists no `merchants`, and contains no `amount-over` / `amount-unknown` / `cumulative-over` rule,
  nothing money-shaped is added, and the scaffold says so. A file that only names a `rulePack` is
  never assumed non-financial. Set `"financial": true` in the file (or pass `--financial`) to opt
  back in; `"financial": false` or `--non-financial` forces the other way.
- **No spend constraint anywhere.** The mandate carries none and the default SOP has no amount rule
  (an `amount-unknown` block would refuse every action that carries no amount). Hosted: the
  provisioning call sends no `currency` / `maxAmount` / `perTxnMax` at all — the backend treats their
  absence as a non-financial mandate. A `rulePack` is built from spend limits, so it is ignored (and
  the CLI says so); list your rules under `rules` instead.
- **The demo is derived from your rules.** `npm start` runs one request that satisfies every rule,
  then one per rule that should trip it, then an action nobody delegated. Each step states what it
  expects and flags any surprise, so changing your rules visibly changes the outcome. Rules the demo
  cannot stage (monetary rules, the platform-derived trust score, `observe` decisions, rules that
  share an input with another rule) are listed in the scaffold output and the generated README —
  never faked, still enforced.
- **The generated README lists the request fields your rules read** (`consent`, `piiPresent`,
  `jurisdiction`, …). An allow-list, consent or PII rule does not fire when its field is absent, so
  your application must supply it. These fields are asserted by the calling agent — except
  `jurisdiction`, which is signed (see [Jurisdiction](#jurisdiction-signed-since-0130)).

**Hosted specifics.** The default shape is still agent + `gateway/`. The gateway runs with
`requireAuthorization: false` and a route with no value fields: the guard only seals a single-use
authorization for a value-bearing action, and this agent has no spending authority, so requiring one
would refuse every allowed request. The consequence — **replay of an identical signed request is not
refused** — is stated in the generated `gateway/README.md`, not glossed over. `npm test` runs
`agentsafe-guard verify --context ./verify-context.json`: the context is the request fields of a
compliant request, because a policy that *requires* an input blocks a request without it. Controls a
non-financial mandate does not set (a spend cap) are reported as "not configured", never as passed.

**Every mode honours it.**

- `--sandbox --non-financial` uses a shared sandbox agent that has **no spend authority** (it is its own agent,
  not a spend tier). The shared agent's rules are the platform's defaults, so the demo is derived from those; a
  `--config` file's rules cannot reach an agent you do not provision yourself, and the CLI says so.
- `--request --non-financial` asks the owner to approve **no spending authority**. The request says so
  explicitly (`financial: false`); the owner's approval screen reads "no spending authority — this agent does
  not move money" instead of a limit; and on approval the platform provisions the agent with no spend fields
  (it does not apply the defaults it applies to an ordinary request). `--claim` then scaffolds the payment-free
  project. `--claim` follows what was **issued**: an approved agent whose config says `financial: false` never
  gets a payment demo, and a mismatch either way (you asked for non-financial but the config does not say it is
  one; `--financial` on a non-financial agent) stops instead of scaffolding.
- **An older server cannot honour it, and the CLI will not pretend it did.** A server that predates this ignores the
  field: it would return the shared payment agent (`--sandbox`) or file the request with default spend limits
  (`--request`). The CLI checks the server's `financial: false` echo and stops with an explanation. For
  `--request` it also tells you which request now exists so the owner can deny it; no claim file is saved for it.

Flag-only scaffolds (no policy file) keep the historical payment defaults; when none of
`--per-txn-max` / `--max-amount` / `--currency` was given, the CLI now prints the defaults it used.

## Bring your own key (`--byok`)

```bash
npx create-metamynd-agent --byok --email you@example.com --name "Support Bot"
```

Generates an Ed25519 keypair **on your machine**, provisions the agent with only the public key, then
proves control (signs the one-time challenge → `verify-key`). MetaMynd never sees the private key. By
default the generated private key is written into `agent.metamynd.json` (gitignored) — the same
process this CLI runs in holds it, at least briefly. Pass `--public-key <hex>` instead to register a
key you already hold elsewhere — then you complete `verify-key` yourself (the CLI prints the challenge
+ endpoint).

### Keeping the key out of this process entirely (`--daemon-socket`)

If you already have an [agentsafe-signer](../agentsafe-signer/README.md) daemon running for this
agent (`agentsafe-signer start --admin`, per its own install guide), point `--byok` at it instead:

```bash
npx create-metamynd-agent --byok --daemon-socket ./.agentsafe-signer/signer.sock \
  --daemon-admin-socket ./.agentsafe-signer/signer-admin.sock \
  --email you@example.com --name "Support Bot"
```

The daemon generates the key and signs the `verify-key` challenge itself — the private key never
enters this CLI's process at all, not even briefly. `agent.metamynd.json` gets `keyProvider: 'daemon'`
+ `daemonSocketPath` instead of a plaintext key (see `@metamynd/agentsafe-guard`'s `key-providers.mjs`
for how the scaffolded guard resolves that). Requires both flags together, and only applies when no
`--public-key` is given (an external key has nothing for the daemon to generate).

## Delegated issuance (`--request` / `--claim`)

Request an agent for an owner's org when you're **not** the owner — no shared credentials:

```bash
npx create-metamynd-agent --request --owner owner@example.com --name "Support Bot"   # +--byok optional
# → saves metamynd-request.json (holds a one-time claim token — do not commit)
# → the owner approves in their dashboard (AgentSafe → Agent Requests), then:
npx create-metamynd-agent --claim --watch
```

`--request` submits the request (as your own authed user) and stores the claim token locally; `--claim`
polls until the owner approves, then scaffolds the project (the same default two-process shape as
the full flow above — `--no-gateway`/`--gateway-port` work here too). With `--byok` the keypair is
generated locally and control is proven on claim — MetaMynd never sees the private key.

## Jurisdiction (signed, since 0.13.0)

The scaffolded agents pass a request's `jurisdiction` (ISO 3166-1 alpha-2) as the guard's **signed** top-level field
(MAGP §8.3.12), not as context: the generated `mapArgs` is `({ jurisdiction, ...context }) => ({ jurisdiction, context })`,
and the gateway call signs it the same way. The gate (and the harness's local check) judges jurisdiction rules on the
signed value only and ignores one in the context. Scaffolds pin `@metamynd/agentsafe-guard` ^0.16.0,
`@metamynd/agentsafe-mcp-guard` ^0.16.0 and `@metamynd/agentsafe-http-gateway` ^0.14.0, which sign and verify it.

- A value that is not two ASCII letters is refused before anything is sent (`MALFORMED_REQUEST`).
- **A registered payee's country wins**: a signed value that differs is refused `JURISDICTION_MISMATCH`.
- A jurisdiction rule with none signed is refused `JURISDICTION_REQUIRED`; a value off the mandate's list is
  `JURISDICTION_NOT_ALLOWED`. The demo stages a jurisdiction rule with a user-assigned code (`ZZ`) off the list, and
  stages nothing when no two-letter code is on every jurisdiction allow-list (no passing request can exist).

## Risk: say it, or have your owner set it

The starter rules include a high-risk review. A request that sends **no** `riskLevel` (or an unrecognised one)
is no longer waved through: it is **escalated** (`CONTEXT_UNVERIFIABLE`) for a human, because an agent that omits
its risk is indistinguishable from one hiding it. The scaffolded financial examples send `riskLevel` (`'low'`
unless you say otherwise) — that default is a placeholder, not an assessment — and the neutral template passes
your own `args` as the context, so include it there. A real integration should send an honest one — or, better, not depend on the agent at all: a mandate
permission can carry an owner-set `riskTier` that no claim can lower, and a gateway route can derive the risk
itself with `route.trustedContext` (`@metamynd/agentsafe-http-gateway` 0.10.0). See MAGP §6.3.

## Security

`agent.metamynd.json` contains the agent's **secret key** (a managed key, or — with `--byok` — the one
generated locally). The scaffolded project gitignores it. Never commit it or paste it anywhere public.

Any REAL tool credential (an airline API key, a payment key, ...) belongs in `gateway/.env` — never
in the agent directory. That's the whole point of the default two-process shape: the agent process
should never be able to hold, or leak, a credential it doesn't have.

## Full guide

`docs/integration/INTEGRATE-WITH-METAMYND.md` — the complete integration front-door (payments,
handshake, edge evaluation, escalation).

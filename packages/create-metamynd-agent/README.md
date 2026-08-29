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

> **Prerequisite:** an agent is always owned by a **KYB-verified owner** — a person/org with a
> MetaMynd account. If that's you and you're verified, you're ready. Verify once in the dashboard if
> not; it's the only gate.

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
├─ agent.metamynd.json   # portable guard config — HOLDS THE AGENT SECRET KEY (gitignored)
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
actual body being executed** (`@metamynd/agentsafe-http-gateway` ≥ 0.3.0), and requires the
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
- **Confused deputy (payload).** Signing a cheap request while executing an expensive one (a
  different amount/currency/merchant in the body than what was signed) is refused before the tool
  runs — payload binding (`@metamynd/agentsafe-http-gateway` ≥ 0.3.0). The default binder fails
  the request CLOSED, not just when it finds a mismatched flat field, but also when it can't find
  the governed fields at all — nested JSON, an array, a renamed or differently-cased key. That
  gap was found and closed the same way: a signed $250/skyward-air request had previously been
  able to execute $5000/evil-corp via `{ booking: { amount, merchant } }`, because the flat
  matcher found nothing to compare and treated "nothing found" as "nothing to check."
- **Replay.** A captured, resent request fails to atomically claim single-use execution the second
  time — `requireAuthorization`.
- **Cumulative spend.** The claimed authorization only exists because the real stateful gate
  already checked it against the mandate's TOTAL budget when minted, not just this one request's
  amount — so many small legal-looking calls can't add up past the cap this way.
- **Amount unknown.** A signed-transaction tool (raw bytes) or a nested x402 payload carries its
  amount somewhere a naive spend cap never looks — `amount-unknown` (`@metamynd/agentsafe-guard`
  ≥ 0.6.0, `@metamynd/agentsafe-mcp-guard` ≥ 0.3.0) blocks by default when the gate can't
  determine the value, instead of letting it slip past the cap untested.

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
| `--sandbox` | — | off (skips login/KYB; shared sandbox agent, still hosted) |
| `--config <file>` | — | a JSON policy file — see [Policy config file](#policy-config-file---config) |
| `--no-gateway` | — | off — hosted flow only; skips the default separate tool gateway (see above) |
| `--gateway-port <n>` | — | `4401` — hosted flow only, the gateway process's port |
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

## Bring your own key (`--byok`)

```bash
npx create-metamynd-agent --byok --email you@example.com --name "Support Bot"
```

Generates an Ed25519 keypair **on your machine**, provisions the agent with only the public key, then
proves control (signs the one-time challenge → `verify-key`). MetaMynd never sees the private key. The
generated private key is written into `agent.metamynd.json` (gitignored). Pass `--public-key <hex>`
instead to register a key you already hold elsewhere — then you complete `verify-key` yourself (the CLI
prints the challenge + endpoint).

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

## Security

`agent.metamynd.json` contains the agent's **secret key** (a managed key, or — with `--byok` — the one
generated locally). The scaffolded project gitignores it. Never commit it or paste it anywhere public.

Any REAL tool credential (an airline API key, a payment key, ...) belongs in `gateway/.env` — never
in the agent directory. That's the whole point of the default two-process shape: the agent process
should never be able to hold, or leak, a credential it doesn't have.

## Full guide

`docs/integration/INTEGRATE-WITH-METAMYND.md` — the complete integration front-door (payments,
handshake, edge evaluation, escalation).

# create-metamynd-agent

Scaffold a **MetaMynd/AgentSafe-governed** AI agent in one command. It logs you in, provisions the
agent in a **single call** (identity + mandate + starter SOP + all enforced Standards), writes a
portable `agent.metamynd.json`, and drops a runnable example that gates a tool through the
[`@metamynd/agentsafe-guard`](https://www.npmjs.com/package/@metamynd/agentsafe-guard).

> **Prerequisite:** an agent is always owned by a **KYB-verified owner** — a person/org with a
> MetaMynd account. If that's you and you're verified, you're ready. Verify once in the dashboard if
> not; it's the only gate.

## Free local harness (no account, no network, `--harness`)

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

No anchored or cross-party-verifiable identity, no dashboard reachable when your machine is off, no
owner queue someone *else* can approve from, no anchored evidence, no enforced platform Standards.
That set of things is the hosted platform — and getting there later is a **config change, not a
rewrite**: the exact same `guardTool()` call your harness project already makes just needs a real
`bundleUrl`/`api` pointed at a real gate (provision normally, without `--harness`) instead of a rules
file you authored yourself. Nothing about how you wrote your agent changes.

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

## Use

```bash
npm create metamynd-agent@latest
# or
npx create-metamynd-agent
```

Answer a few prompts (API, owner email/password, agent name, scope, per-transaction cap) and you get:

```
my-agent/
├─ agent.metamynd.json   # portable guard config — HOLDS THE AGENT SECRET KEY (gitignored)
├─ index.mjs             # runnable example: ALLOW · BLOCK (over cap) · ESCALATE (high risk)
├─ package.json          # depends on @metamynd/agentsafe-guard
├─ .gitignore
└─ README.md
```

Then:

```bash
cd my-agent
npm install
npm start
```

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
polls until the owner approves, then scaffolds the project. With `--byok` the keypair is generated
locally and control is proven on claim — MetaMynd never sees the private key.

## Security

`agent.metamynd.json` contains the agent's **secret key** (a managed key, or — with `--byok` — the one
generated locally). The scaffolded project gitignores it. Never commit it or paste it anywhere public.

## Full guide

`docs/integration/INTEGRATE-WITH-METAMYND.md` — the complete integration front-door (payments,
handshake, edge evaluation, escalation).

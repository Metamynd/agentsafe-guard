# create-metamynd-agent

Scaffold a **MetaMynd/AgentSafe-governed** AI agent in one command. It logs you in, provisions the
agent in a **single call** (identity + mandate + starter SOP + all enforced Standards), writes a
portable `agent.metamynd.json`, and drops a runnable example that gates a tool through the
[`@metamynd/agentsafe-guard`](https://www.npmjs.com/package/@metamynd/agentsafe-guard).

> **Prerequisite:** an agent is always owned by a **KYB-verified owner** — a person/org with a
> MetaMynd account. If that's you and you're verified, you're ready. Verify once in the dashboard if
> not; it's the only gate.

## Try it instantly — sandbox (no account, no KYB)

```bash
npm create metamynd-agent@latest -- --sandbox   # or: npx create-metamynd-agent --sandbox
```

Skips login and provisioning entirely — fetches a **shared sandbox agent** config from the public
`POST /onboarding/sandbox` endpoint and scaffolds a runnable example. Great for a first look; use
the full flow below when you want your own governed agent with your own limits.

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
| `--sandbox` | — | off (skips login/KYB; shared sandbox agent) |
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

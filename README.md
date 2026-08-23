# AgentSafe Guard

**Runtime governance for AI agents.** Wrap a tool in three lines; every call is signed and
decided outside your process. Blocked calls never reach your code.

[![npm](https://img.shields.io/npm/v/@metamynd/agentsafe-guard?label=%40metamynd%2Fagentsafe-guard)](https://www.npmjs.com/package/@metamynd/agentsafe-guard)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

```bash
npx create-metamynd-agent --sandbox   # no account, no KYB
npm install && npm start
```

```
Step 1 of 3 - a $250 booking, low risk.
   ALLOWED    your tool ran and returned PNR-DEMO
Step 2 of 3 - a $600 booking, deliberately over the cap.
   BLOCKED    SOP_SPEND_CAP
   your tool never ran - the gate refused before execution.
Step 3 of 3 - a $250 booking, but flagged high risk.
   ESCALATED  held for a human - RISK_REVIEW
```

---

## Why this exists

You can tell an agent to stay under $10,000 and use approved vendors. It will usually comply.
But *usually* is not a control you can show an auditor, and an agent that can be argued out of
a rule was never bounded by it — it was only asked.

A prompt is a request. This is a decision made somewhere the agent does not control, against
authority someone issued it deliberately, before the tool runs.

The property that matters most is not the spend cap — that one you could write yourself. It is
this: **an agent cannot widen its own authority, because it cannot name an action nobody
delegated to it.** Ask the gate for `permissions.update` and you get
`NO_PERMISSION_FOR_ACTION`, at $1 and at $100,000, with no anti-self-escalation rule anywhere.
Default-deny by scope gets you that for free.

## What is in here

| Package | What it does |
|---|---|
| [`packages/policy-core`](packages/policy-core) | The deterministic evaluator. Zero dependencies, no IO, no clock, no LLM. Atoms → molecules → mandate, combined most-restrictive-wins. |
| [`packages/agentsafe-guard`](packages/agentsafe-guard) | The agent-side guard. `guardTool()` wraps a function and refuses to run it unless the verdict permits. [npm](https://www.npmjs.com/package/@metamynd/agentsafe-guard) |
| [`packages/agentsafe-mcp-guard`](packages/agentsafe-mcp-guard) | The counterparty-side guard. An MCP server re-evaluates the agent's authority *independently*, so a compromised agent still cannot make an honest service act. [npm](https://www.npmjs.com/package/@metamynd/agentsafe-mcp-guard) |

Both guards ship with **zero runtime dependencies** — Node's built-in Ed25519 (`node:crypto`)
and `fetch`, nothing else. For something in the execution path of every privileged action,
that matters more than features.

## Verdicts are reproducible, on purpose

`policy-core` is a pure function of `(rules, mandate, request)`. Given identical inputs, every
conformant implementation returns an identical verdict — that is
[MAGP §6.3](https://metamynd.ai/developers/spec), and it is what makes edge and cross-party
evaluation trustworthy rather than something you take on faith.

It is published here so you can check that claim rather than believe it. The evaluator runs
**locally, in your process** by default: a block or an escalate is decided with no network call
at all. Only a permitted value-bearing action is sealed by the remote gate, because holds,
cumulative spend and anchored evidence are inherently stateful.

## Be clear about what is not here

This repository is the **client half**. The authorize gate is a hosted service at
`metamynd.ai`, and that is where mandate issuance, the two-phase spend hold, escalation
queues, containment state and anchored evidence live. You can read every line of what runs in
your process; you cannot read the server.

Three consequences worth knowing before you adopt it:

- **The gate is a dependency.** The guard fails **closed** — an unreachable gate blocks rather
  than allows. That is the right default and it means our availability is your availability
  for value-bearing actions. There is no self-host story today.
- **Local evaluation reduces but does not remove the round trip.** Blocks and escalates are
  decided in-process against a signed policy bundle. Permitted value actions still call out.
- **Identity, policy and evidence sit with one provider.** That is a real concentration
  question and we would rather you weigh it than discover it.

The protocol is fully specified, so none of this is a lock-in of the *format*: the canonical
signing string, all 59 reason codes and the atom catalog are published in the
[MAGP v1.0 spec](https://metamynd.ai/developers/spec), and a
[Python reference client](https://metamynd.ai/developers/python) exists precisely to prove the
protocol is not JavaScript-specific.

## Using it

```js
import { createGuardFromConfig } from "@metamynd/agentsafe-guard";

const guard = await createGuardFromConfig("./agent.metamynd.json");

// Your existing function. Unchanged, and unaware it is governed.
async function rawBookFlight({ amount, merchant }) { /* ... */ }

// The governed one. It runs only on a permit; a block or an escalate throws.
export const bookFlight = guard.guardTool("flight-purchase", rawBookFlight, (a) => ({
  amount: a.amount,
  merchant: a.merchant,
}));
```

No prompt changes, no tool changes, one config file.

## Running the tests

```bash
npm install          # vitest, for the evaluator's TypeScript suite
npm test             # evaluator suite + both guards' smoke suites
```

The smoke suites need no network and no account — they evaluate a policy bundle in-process and
assert the verdicts match what the gate returns for the same inputs.

## Where this is developed

These packages are developed in MetaMynd's main repository and published here on each release,
so the history you see is the real history rather than a squashed import. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how patches get in — the short version is that they are
welcome and they take a manual step on our side, and we would rather say that than pretend
otherwise.

Security issues: please read [SECURITY.md](SECURITY.md) first — do not open a public issue.

## Links

- [MAGP v1.0 protocol specification](https://metamynd.ai/developers/spec) — 16 gate stages, 59 reason codes, the canonical signing format
- [Quickstart](https://metamynd.ai/developers/quickstart) — a live signed verdict in your browser, no account
- [Python reference client](https://metamynd.ai/developers/python)
- [A governed procurement agent, end to end](https://metamynd.ai/developers/procurement)

## License

[MIT](LICENSE). Both packages have been MIT since first publication.

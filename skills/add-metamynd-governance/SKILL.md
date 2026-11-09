---
name: add-metamynd-governance
description: Add MetaMynd runtime governance to a Node agent project, so that tool calls are allowed, refused or held for a person before they run. Use when the user wants spend caps, allow-lists, human approval or an audit trail on what their AI agent can do, or asks to add AgentSafe Guard or MetaMynd to a project.
---

# Add MetaMynd governance to an agent

Wrap the tools an agent can call with `@metamynd/agentsafe-guard`. Each call is checked against
the agent's mandate before the tool runs. A refused call never reaches the tool.

Work through these steps in order. Ask before changing anything the user did not point you at.

## 1. Find the tools that matter

Read the project and list every function the agent can call. Note for each one:

- whether it moves money or changes something outside the process;
- which arguments carry the amount and the counterparty, if any;
- where the real API keys for it are read.

Show the user the list and agree which tools to govern. This package targets Node 18 or later.
For a Python agent, use the `metamynd-client` package from PyPI instead and stop here.

## 2. Choose how the agent gets its identity

Ask the user which of these fits. Each one is a mode of the official scaffolder.

| Command | Account | Who decides | Use it for |
|---|---|---|---|
| `npx create-metamynd-agent --harness` | None | A local evaluator, no network | Trying out rules on one machine |
| `npx create-metamynd-agent --sandbox` | None | The hosted gate, as a shared demo identity | A first look. Never give it real credentials |
| `npx create-metamynd-agent` | MetaMynd account with a verified principal | The hosted gate, as the user's own agent | Real use. It provisions a Testnet agent and a separate `gateway/` process |

The user runs the login for the full flow themselves. Never ask for their password in chat, and
never pass it on a command line.

The scaffolder writes `agent.metamynd.json`. **That file holds the agent's secret key.** Confirm
it is listed in `.gitignore`, never print its contents, and never commit it.

## 3. Wrap each tool

```js
import { createGuardFromConfig } from "@metamynd/agentsafe-guard";

const guard = await createGuardFromConfig("./agent.metamynd.json");

export const bookFlight = guard.guardTool("flight-purchase", rawBookFlight, (args) => ({
  amount: args.amount,
  merchant: args.merchant,
}));
```

The first argument names the action and must be one the mandate grants, or the call is refused
with `NO_PERMISSION_FOR_ACTION`. The third argument maps the tool's arguments to what the gate
checks. Map the real values: do not hardcode an amount or let the model supply a separate one.

Replace every place the agent calls the raw function, then confirm nothing else still imports it.

## 4. Handle a refusal or a hold

A wrapped tool throws when it is not permitted, with the verdict in `err.governance`.

```js
try {
  return await bookFlight(args);
} catch (err) {
  if (err.governance?.decision === "escalate") {
    // Held for a person. Tell the agent it is waiting; do not retry with changed arguments.
    return await bookFlight.resume(err.governance.escalationId, args);
  }
  throw err;
}
```

`.resume()` waits for the approval and only runs the tool with the arguments that were approved.
Return a refusal to the agent as a plain failure, including the reason code. Never catch it and
call the raw function instead.

## 5. Check it

Run the agent and show the user one allowed call and one refused call. Then run:

```bash
npx @metamynd/agentsafe-guard verify
```

It exits non-zero if the agent can exceed its mandate, and reports any control the mandate does
not set as not configured. Offer to add it to CI. Add `--require merchants,perTxn,cumulative` if
the user wants a missing control to fail the build.

## 6. Tell the user what this does not cover

Say this plainly when you finish.

- `guardTool()` runs in the agent's own process. Code that can call the raw function directly gets
  around it. The real boundary is the separate `gateway/` process from the full scaffolder flow,
  which holds the tool and its credentials and re-verifies every request. `--harness` and
  `--sandbox` do not have one.
- The guard fails closed. If the hosted gate is unreachable, permitted value-bearing calls are
  refused.
- The full flow provisions Testnet agents. Mainnet agents are launched from the MetaMynd dashboard.

Documentation: https://docs.metamynd.ai

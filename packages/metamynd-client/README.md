# metamynd-client

The MetaMynd/AgentSafe authorize-gate client for Python — the supported reference
implementation. MAGP is language-agnostic by design: the gate verifies an Ed25519
signature over a canonical string, and nothing about that is JavaScript-specific. This
is the proof, and the shortest path for a Python team that doesn't want to read the
[Node guard](https://www.npmjs.com/package/@metamynd/agentsafe-guard) to find out what
the protocol actually expects.

```bash
pip install metamynd-client
```

> **Upgrading from 0.1.0?** Do. 0.1.0 signs a *seven*-field message; the gate requires
> *eight* (`resource` was added), so every request from 0.1.0 is refused with
> `CLIENT_PROTOCOL_VERSION_UNSUPPORTED`. This release signs the eight-field message and is
> tested against the gate's own vectors and the real guard (see [Tests](#tests)).

```python
from metamynd_client import MetaMyndClient

client = MetaMyndClient.from_env()  # reads METAMYND_API / AGENT_DID / AGENT_KEY

verdict = client.authorize(
    "flight-purchase", 150,
    merchant="skyward-air",
    context={"tool": "book-flight", "riskLevel": "low"},
)

if verdict.permitted:
    ...  # run the action
elif verdict.decision == "escalate":
    # ESCALATE is a HOLD, not a denial. Wait for a human; act ONLY on may_proceed.
    state = client.wait_for_escalation(verdict.escalation_id, timeout=600)
    if state.may_proceed:
        ...
else:
    raise RuntimeError(f"refused: {verdict.reason_code}")
```

### Send an honest `riskLevel`

A rule that judges risk **escalates a request that carries none** (or an unrecognised one),
instead of allowing it: an agent that omits its risk is indistinguishable from one hiding it.
`guard_tool` never invents a risk for you, and the `"low"` in the examples is a **placeholder,
not an assessment**. A real integration states an honest one — or, better, doesn't depend on
the agent: the mandate's owner can set a `riskTier` no claim can lower (MAGP §6.3).

## Guard a tool

```python
from metamynd_client import MetaMyndClient, guard_tool, GovernanceBlocked

client = MetaMyndClient.from_env()

def book_flight(amount, merchant):
    ...  # your real implementation

governed_book_flight = guard_tool(
    client, "flight-purchase", book_flight,
    lambda amount, merchant: {
        "amount": amount, "merchant": merchant,
        "context": {"tool": "book-flight", "riskLevel": "low"},  # state an honest risk
    },
)

try:
    governed_book_flight(amount=150, merchant="skyward-air")
except GovernanceBlocked as refused:
    print(f"refused: {refused.verdict.reason_code}")
    # refused.verdict.escalation_id, for a hold: client.wait_for_escalation(...)
```

`map_args` returns `amount`, `currency`, `merchant`, `resource` and `context`. **Async tools are
supported**: hand `guard_tool` an `async def` and you get an `async def` back (the gate call runs in
a worker thread, so it never stalls your event loop). The original signature is preserved, so a
framework that builds the tool schema from it — the OpenAI Agents SDK, PydanticAI — sees exactly
the unguarded function. If the awaiting task is cancelled (a timeout) while the gate is answering, and
the gate permits, the hold that call created is voided rather than left reserving the budget.
Async generator tools are refused when you wrap them: one authorization covers one action.

An escalation can also end as `modified` — a reviewer changed the action instead of approving it as
asked. That stops the wait too, is never `may_proceed`, and `status.next_escalation_id` is the
follow-up hold for the modified action.

## Behind a gateway or MCP server

A service protected by [`@metamynd/agentsafe-http-gateway`](https://www.npmjs.com/package/@metamynd/agentsafe-http-gateway)
or an MCP server using `agentsafe-mcp-guard` doesn't take the agent's word: it re-verifies the
signed request against the agent's own policy. The client hands it over:

```python
import requests
from metamynd_client import governance_headers, guard_tool

def book_via_gateway(amount, merchant):
    # inside a guarded tool, governance_headers() is the x-magp-request header for THIS call
    return requests.post("https://gateway.example/book",
                         json={"amount": amount, "merchant": merchant},
                         headers=governance_headers()).json()

book = guard_tool(client, "flight-purchase", book_via_gateway, map_args)
```

Outside a guarded tool: `verdict.signed.headers()`. It is not a parameter of your function, so the
tool's signature is unchanged. Without the header the service refuses (`MISSING_GOVERNANCE`) — the
safe failure. The gateway also refuses arguments that differ from what was signed
(`PAYLOAD_NOT_BOUND`), so the amount you authorized is the amount that executes.

**After a human approves a held action**, the request you first signed is stale (a service refuses
one more than a few minutes old). Sign a fresh one carrying the approved authorization:

```python
signed = client.sign_request("flight-purchase", 150, merchant="skyward-air",
                             context={"riskLevel": "low"},
                             authorization_id=state.authorization_id)
requests.post(url, json=body, headers=signed.headers())
```

### Bind the WHOLE payload, not just eight fields (0.2.0 / 0.3.0, MAGP §8.3.9, §8.3.11)

The signature covers the agent, action, amount, currency, merchant and resource — not a payee or an account number. Pass
`payload=` and the client also signs a digest of the complete payload (RFC 8785 canonical JSON), bound to that one authorization;
the service that executes it is held to exactly that payload, and a claim with a different one is refused:

```python
verdict = client.authorize("wire", 250, merchant="acme", context={"riskLevel": "low"},
                           payload={"payee": {"iban": "NL91ABNA0417164300"}, "reference": "INV-1042"})
# or from guard_tool: have map_args return "payload"
```

Pass the payload exactly as the service will receive it as JSON. A payload JSON cannot carry (NaN, bytes, a `datetime`) raises
`PayloadNotCanonicalizable` before anything is sent. The gate echoes the digest it stored, and `authorize` **refuses a permit that
does not** (`PAYLOAD_BINDING_NOT_CONFIRMED`, releasing the hold) — so a proxy that strips the fields, or a gate that predates the
feature, is a loud failure rather than a silently unbound request.

**0.4.0 — a genuine JSON `null` payload can now be bound.** `payload=` used to default to `None`, so there was no way to say
"bind the literal value `null`" — it meant "no payload" either way. The default is now the sentinel `NO_PAYLOAD` (also what
omitting `"payload"` from `map_args`'s return means); `payload=None` — explicitly, or `map_args` returning `{"payload": None}` —
now binds `null`. Existing code that never passes `payload=None` explicitly is unaffected.

**After a reviewer MODIFIES a held action**, the hold it mints carries no digest (the action you signed is not the one that was
approved). Bind the payload of the action that WILL run, then hand the service a fresh signed request:

```python
bound = client.bind_payload(status.authorization_id, "wire", payload)     # 0.3.0
if not bound.bound:
    raise RuntimeError(f"payload not bound: {bound.reason_code}")
signed = client.sign_request("wire", amount, payload=payload, authorization_id=status.authorization_id)
```

The gate applies it only while the hold is live, unclaimed and unbound, and never overwrites a digest.

## Remote signer daemon — the key never enters this process (0.5.0)

`agentsafe-signer` (`integrations/agentsafe-signer`, Node) is a separate local process that holds the
agent's key and signs on request, over a Unix domain socket (a Windows named pipe there). Point the
client at it instead of a key:

```python
client = MetaMyndClient("https://metamynd.ai/api/v1", agent_did, daemon_socket="/path/to/signer.sock")
# or from_env(): set AGENT_DAEMON_SOCKET instead of AGENT_KEY
```

Every signature this client makes — the authorize request, a payload binding — is asked of the daemon
instead of computed with a key held in this process; nothing else about the client changes; `sign_request`,
`authorize`, `guard_tool`, `bind_payload` all work exactly as before. Same protocol the Node guards' own
daemon key providers speak (`agentsafe-guard`'s `key-providers.mjs`): the daemon reconstructs the exact
canonical message itself from structured fields, so this client never hands it — or is asked to hand it —
bytes to blind-sign. `DaemonError` (`.code`) reports `DAEMON_UNREACHABLE`, `PAYLOAD_BINDING_UNSUPPORTED`
(the daemon predates `sign-payload`, signer < 0.15.0 — upgrade it, or don't bind a payload against it) and
the daemon's own refusal codes. Stdlib only: `socket.AF_UNIX` on Linux/macOS, raw `ctypes` calls into
`kernel32` for the named pipe on Windows — no extra dependency either way. Verified against the real
`agentsafe-signer` daemon (`tests/test_daemon_signer.py`), on both transports (CI runs the POSIX path;
Windows was run and confirmed directly, not merely reasoned about — the named-pipe transport has genuine
platform-specific failure modes a mock would not have caught).

## Settle, release, look up

```python
client.capture(verdict.authorization_id, 150, booking_ref="PNR1")   # commit at the FULL amount
client.void(verdict.authorization_id, reason="not needed")           # release an UNCLAIMED hold
out = client.outcome(verdict.authorization_id)                       # did it happen? may I retry?
```

**Who settles.** The *service* that executed the action settles or releases the hold it claimed;
an agent normally doesn't. Once a service has claimed a hold, only that service can settle it
below the authorized amount or release it — the gate refuses the agent's attempt (`ok=False`,
with the reason), on purpose: otherwise an agent could wait for a purchase to happen and then take
its budget back. An agent can `capture` at the full amount, and `void` a hold nobody has claimed.

**Settling below the authorization (0.5.2).** A service that charged less passes `pay_to`, the account it paid
(a Hedera account id or an EVM address): `client.capture(auth_id, 120, pay_to="0.0.5005")`. If the owner lists
that merchant's accounts (MAGP 8.7.14), a lowered capture without a listed `pay_to` is refused
(`PAYEE_NOT_REGISTERED`), and the settlement observer only counts a credit to the account named.

**What was authorized, what was settled, and how far to trust it.** `Outcome` reports `authorized_amount`
(kept after settlement — `None` means unknown, not zero), `settled_amount`, and `settlement_evidence`:
`unattested` (the full authorization, counted for a caller that is not the claiming service),
`unclaimed_lowered` (released below the authorization before anyone claimed it),
`counterparty_attested` (the claiming service said so), `independently_confirmed` (the payment facilitator
reported the same amount), `operator_resolved`, or `reconciled_at_authorized`. Where a facilitator is
configured, a service settling *below* the authorization must be confirmed by it — an unreachable or
silent facilitator refuses the lower figure rather than believing it (the service can still settle in full).

**Retry only when it is safe.** `Outcome` carries two flags: `nothing_executed` (nothing has run
*so far*) and `retry_safe` (nothing can run *later* either — only `expired` and `not_executed`).
Retry a purchase **only** on `retry_safe`. A `not_started` hold is not yet retry-safe (a service
queued behind a slow gateway can still claim it — `void` it first); `unknown` and `in_flight` are
ambiguous and are reconciled, never retried blindly.

**Proving a decision happened (0.5.1).** `verdict.event_id` is the id the anchored evidence event
for THIS decision was recorded under — what `GET /magp/evidence/{event_id}/proof` (§10.3) needs to
serve its Merkle inclusion proof. It is a *different* id from `verdict.authorization_id` (the
mandate hold); that id does not work there. `None` only when the gate's own best-effort evidence
write failed.

## Examples

Six runnable examples in
[`docs/integration/examples`](https://github.com/Metamynd/agentsafe-guard) — each runs offline
against a test gate, and CI runs them: `langgraph_agent.py`, `openai_agents_agent.py`,
`crewai_agent.py`, `langchain_agent.py`, `pydantic_ai_agent.py`, and `plain_python_agent.py` (no
framework: the whole lifecycle — authorize, hold, gateway handoff, capture, void, outcome — in one
file). Frameworks are imported lazily, so an example still runs the governance without its
framework installed.

## Scope

This is the entry price, not a full SDK: it signs and submits authorize requests, returns the
verdict, wraps a tool (`guard_tool`, sync or async), hands the signed request to a gateway, follows
up an `escalate`, and settles or looks up a hold. Local bundle evaluation (deciding at the edge,
no network) and evidence inclusion-proof fetch exist in the protocol and in the
[Node guard](https://www.npmjs.com/package/@metamynd/agentsafe-guard) and are deliberately not
reimplemented here — see [the full comparison](https://metamynd.ai/developers/python).

## Tests

```bash
python -m metamynd_client --selftest        # offline: the details that cost a day each,
                                            # plus the whole client against an in-process gate stub
```

The repository's CI additionally checks the client against the **shared protocol vectors**
(`docs/protocol/authorize-vectors.json`, generated from the gate's own message builder and read by both
the gate's tests and this client's — so the two cannot drift apart again), runs every example, has
the **real** `agentsafe-mcp-guard` and `agentsafe-http-gateway` verify what the client signs, and drives
a **real** `agentsafe-signer` daemon over its actual socket/pipe transport for the daemon-backed signer.

## Links

- [Full guide](https://metamynd.ai/developers/python)
- [Protocol spec](https://metamynd.ai/developers/spec) — the signed message is §8.3
- [Source](https://github.com/Metamynd/agentsafe-guard)

MIT licensed.

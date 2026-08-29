# AgentSafe HTTP interception gateway (SAFR §17)

A **generic reverse proxy** that governs *arbitrary* HTTP calls — not just MCP. Put it in front of
any upstream service; requests matching a **protected route** are re-evaluated through the AgentSafe
gate before they are forwarded, and everything else passes through untouched. Zero dependencies
(`node:http` + built-in `fetch` + the zero-dep `agentsafe-mcp-guard`).

This closes the gap where governance only sat at the MCP boundary + hand-written demo gateways — now
a legacy or third-party agent that speaks plain HTTP can be governed at the network edge.

## How it works

```
agent → [ HTTP gateway ] → upstream service
              │
              ├─ route not protected      → forward as-is
              └─ route protected:
                    no signed request      → 401
                    payload ≠ signed value → 403 PAYLOAD_NOT_BOUND (verifyRequest never called)
                    verifyRequest(signed)  → allow/observe → forward upstream (+ x-agentsafe-decision)
                                           → block/escalate → 403 (upstream never called)
                                           → gate error       → 502 (fail closed)
```

Protected routes are declared in `agentsafe-routes.json` (path patterns: `*` = one segment, `**` =
the rest). The route **pins the governed action**, so a client cannot relabel a purchase as a cheap
read. The agent presents its signed MAGP request in the `x-magp-request` header (the same object the
guard already verifies); the gateway forwards only on `allow`/`observe`.

```json
[
  { "method": "POST", "path": "/book/*",     "action": "flight-purchase" },
  { "method": "POST", "path": "/payments/**", "action": "payment-execute" }
]
```

## Run

```bash
AGENTSAFE_UPSTREAM=https://api.example.com \
MAGP_API=https://metamynd.ai/api/v1 \
SERVICE_DID=did:hedera:testnet:... SERVICE_KEY=<hex> \
AGENTSAFE_ROUTES=agentsafe-routes.json \
node server.mjs   # listens on PORT (default 4000)
```

`denyByDefault: true` (in `createHttpGateway`) switches to an **allow-list** posture — an unmatched
route is blocked (`ROUTE_NOT_ALLOWED`) instead of forwarded. `server.mjs` defaults this **off**
(a proxy fronting a wider API legitimately wants most routes to pass through), but warns loudly
at startup that it's off, and reads `AGENTSAFE_DENY_BY_DEFAULT=true` to flip it — found live: an
unsigned `POST /transfer-funds` on an undeclared route passed straight through, HTTP 200.

`server.mjs` also defaults `requireAuthorization: true` on its guard (env
`AGENTSAFE_REQUIRE_AUTHORIZATION=false` to opt out) — without it, the guard only does stateless
per-request re-verification, which cannot stop a captured request being replayed or catch many
separately-legal calls adding up past the mandate's TOTAL budget. Found live, both real: 5/5
replays of a captured request executed; 50×$250 with no authorization at all cleared a $10,000
mandate cap.

## Payload binding (confused deputy) — on by default since 0.2.0, fails CLOSED since 0.3.0

The signed request authorizes *specific values*; the bytes forwarded upstream are the request
body — a different object. Before 0.2.0, nothing compared them: an agent could sign a cheap,
in-policy request in the `x-magp-request` header while shipping an expensive, out-of-policy body,
and the gateway would verify the header, then forward the body unchanged. Signed $250, executed
$5000 — a real, confirmed finding, not a hypothetical.

`bind` (default `defaultBindPayload`) pulls `amount`/`currency`/`merchant` out of a **JSON** body
and compares each to the value that was actually signed — checked *before* `verifyRequest()`, so
a tampered request is refused locally: no issuer round trip, no nonce consumed. A mismatch
returns `403 PAYLOAD_NOT_BOUND` naming the offending field. A value the signature never mentioned
at all also counts as a mismatch — `verifyRequest()` defaults an absent `amount`/`merchant` to
`0`/`''`, so a body that introduces one against a signature covering neither is the same attack
wearing a different hat.

**This is secure by default, not opt-in** — the alternative leaves every existing deployment
carrying the gap, which is the vulnerability rather than a fix for it. Pass `bind: false`
(globally, or per route) only for a route whose body carries no value fields worth binding.

**0.3.0 — closed the follow-on gap.** Through 0.2.x, a body that WAS valid JSON but didn't carry
`amount`/`currency`/`merchant` at the *top level* — nested (`{ booking: { amount } }`), a JSON
array, a renamed field (`total`), or a differently-cased one (`Amount`) — bound nothing and
passed on the signature alone, same as a genuinely unparseable body. That was the unsafe default:
most real payloads nest, and this was a real, live-confirmed bypass — a signed $250/skyward-air
request executed $5000/evil-corp via `{ booking: { amount, merchant } }`, because the flat
matcher found nothing to compare and the gateway treated "found nothing" as "nothing to check."

The default binder now distinguishes the two cases. A body with **nothing in it at all** (empty,
absent, or not JSON — protobuf, multipart, form-encoded) still binds nothing and passes on the
signature alone; failing THAT closed would brick every proxy fronting a non-JSON upstream, which
is the one narrow exception this module still defends. A body that **is** valid JSON but simply
doesn't expose the governed fields where the flat matcher looks now fails CLOSED —
`403 PAYLOAD_UNBINDABLE` — because there is no way to rule out that the real values just moved
out of sight. Give such a route its own binder to keep it working correctly instead of blocked:

```js
routes: [{
  method: 'POST', path: '/book/*', action: 'flight-purchase',
  bind: (req) => { const b = JSON.parse(req.rawBody.toString('utf8')); return { amount: b.booking?.amount }; },
}]
```

## Embed the core

```js
import { createHttpGateway } from '@metamynd/agentsafe-http-gateway';
const handle = createHttpGateway({ guard, routes, forward });          // forward(req) → upstream
const result = await handle({ method, path, headers, body });          // { status, body, governance? }
```

Self-check: `node gateway.smoke.mjs` (route matching, pass-through, allow→forward, block→403,
missing-governance→401, fail-closed, action-pinning, allow-list posture) and
`node bind-payload.smoke.mjs` (tampered field detection, unmentioned-value detection, runs before
the guard, numeric-string coercion, empty/non-JSON bodies, nested-value binders, the `bind: false`
opt-out, a throwing binder failing closed).

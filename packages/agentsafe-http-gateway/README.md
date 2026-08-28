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
                    verifyRequest(signed)  → allow/observe → forward upstream (+ x-agentsafe-decision)
                                           → block/escalate → 403 (upstream never called)
                                           → no signed request → 401
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
route is blocked (`ROUTE_NOT_ALLOWED`) instead of forwarded.

## Embed the core

```js
import { createHttpGateway } from '@metamynd/agentsafe-http-gateway';
const handle = createHttpGateway({ guard, routes, forward });          // forward(req) → upstream
const result = await handle({ method, path, headers, body });          // { status, body, governance? }
```

Self-check: `node gateway.smoke.mjs` (route matching, pass-through, allow→forward, block→403,
missing-governance→401, fail-closed, action-pinning, allow-list posture).

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
`AGENTSAFE_REQUIRE_AUTHORIZATION=false` to opt out, which now also warns loudly at startup —
this was silent through 0.3.0) — without it, the guard only does stateless per-request
re-verification, which cannot stop a captured request being replayed or catch many
separately-legal calls adding up past the mandate's TOTAL budget. Found live, both real: 5/5
replays of a captured request executed; 50×$250 with no authorization at all cleared a $10,000
mandate cap.

## Payload binding (confused deputy) — on by default since 0.2.0, fails CLOSED since 0.4.0

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

**0.3.0 — first attempt, incomplete.** Treated "the flat matcher found NONE of amount/currency/
merchant" as the unsafe case (`403 PAYLOAD_UNBINDABLE`) and everything else — including a body
that offered even one correct-looking decoy field — as safe. Wrong: re-tested live and closed
same day. A correct top-level `merchant` decoy paired with the real amount nested one level down
(`{ merchant: 'skyward-air', booking: { amount: 5000 } }`) sailed through, because `merchant`
compared clean and `amount` being merely ABSENT — not present-and-wrong — was never itself
flagged. Same shape with the amount renamed (`total`) instead of nested. An entirely empty body,
and a form-encoded one, were both explicitly exempted as "nothing to compare" — also
live-exploitable, for the identical reason: a real signed amount with nothing in the body to
check it against is not evidence of safety, it's the same gap from the other side.

**0.4.0 — the actual fix.** The question is no longer "did the body offer *any* of the three
fields." It's "does the body expose `amount` and `merchant` specifically, whenever the SIGNED
request names a real value for them" (`currency` stays comparison-only — see below). Anything
short of that — nested, renamed, differently-cased, an array, empty, or non-JSON — now fails
CLOSED (`403 PAYLOAD_UNBINDABLE`), with no exceptions left standing. The **only** surviving
exception is a signed request that never names a real amount or merchant at all: nothing this
binder is entitled to require, so any body shape passes through unbound, same as always.

`currency` is deliberately left comparison-only (checked when the body includes it, never
required): plenty of real upstreams never repeat it in the body — single-currency APIs, currency
implied by the route or a header — and requiring it would brick those deployments for a field
that, alone, is rarely the attack. `amount` and `merchant` are the two fields an attacker
actually profits from moving: how much moves, and who it moves to.

**0.4.1 — the amount comparison is now a strict decimal parse.** Comparing `amount` used to
run both the signed and body values through plain `Number()`, which happily coerces strings a
canonical signer would never produce — hex (`"0xFA"` → `250`), scientific notation
(`"2.5e2"` → `250`), and whitespace-padded values (`" 250"` → `250`) — into the same number as
the plain decimal `"250"`. A body carrying one of those forms could match a signed `250` without
actually being a value a downstream system would parse the same way. The body value is now
accepted only as a bare integer or decimal string (or a JS `number`); anything else fails the
comparison, which — same as any other mismatch — resolves to `403 PAYLOAD_UNBINDABLE`.

**0.4.2 — route matching decodes percent-encoding; merchant/currency reject non-scalar payloads.**
Route matching used to compare raw, undecoded path bytes against the configured pattern —
`/%62ook-flight` ("book-flight" with the `b` percent-encoded) missed a configured
`/book-flight` route entirely, fell through as "unmatched," and — under the permissive
default posture (`denyByDefault: false`) — forwarded straight through with no signature
check, no policy evaluation, and no payload binding, while the upstream decoded it right
back to the governed path and executed it. Matching now decodes the path first (a
malformed escape falls back to comparing the raw bytes rather than throwing). Separately,
`merchant`/`currency` binding now rejects arrays and objects outright: `String(["acme"])
=== "acme"`, so a body carrying `"merchant": ["acme"]` used to pass as a match even though
it's a structurally different value than what was signed.

**0.4.3 — a signed amount of exactly 0 no longer drops amount out of the required set.**
`amount` used to be exempted from binding whenever the signed value was `0`, on the theory
that it meant "the caller never populated amount." It doesn't: the public authorize
endpoint's own schema accepts a genuine `$0` request as a real, deliberate authorization,
and `amount-unknown`/`amount-over` both treat `0` as known rather than absent. Exempting it
here meant a `$0`-authorized request to a real merchant dropped `amount` out of the required
set entirely — a matching top-level `merchant` satisfied the only remaining requirement, and
a real amount hidden elsewhere in the body (nested, renamed) rode through completely
unchecked. `amount` is now required whenever it was signed as any finite number, including
`0`. A route whose amount is genuinely never a concept should opt out via `bind: false` or
its own `bind(req, signed)`, per the pattern below — not rely on this heuristic guessing
which case it is.

**0.4.4 — the required-field set is no longer derived from the signed request at all.**
0.4.3 closed the explicit `amount: 0` case, but not an equivalent one: `verifyRequest()`
destructures `amount = 0` before rebuilding the canonical message, so a signed blob that
OMITS the `amount` key entirely verifies against the exact same signature an explicit `0`
would — an attacker gains nothing by choosing one form over the other, and either one still
dropped `amount` out of the required set under 0.4.3's fix. There is no signed-request-shaped
heuristic that can close both at once, because they are the same bytes. `defaultBindPayload`
now requires `route.valueFields` (default `['amount', 'merchant']`) unconditionally, ignoring
the signed request's content entirely — a genuinely value-less route must say so explicitly
with `valueFields: []` (or `bind: false`), not rely on the signed request implying it:

```js
routes: [{ method: 'POST', path: '/health-check', action: 'ping', valueFields: [] }]
```

Give a route its own binder — `(req, signed) => ({ amount, merchant, ... })` — when it genuinely
carries the value somewhere this flat matcher can't see, so it keeps working correctly instead of
being blocked:

```js
routes: [{
  method: 'POST', path: '/book/*', action: 'flight-purchase',
  bind: (req, signed) => { const b = JSON.parse(req.rawBody.toString('utf8')); return { amount: b.booking?.amount }; },
}]
```

**By default, this still can't do anything about:** a body whose amount/merchant genuinely
match what was signed, but which ALSO carries an extra key an upstream happens to honor (a
`surcharge` field that silently inflates the real charge past what the binder checked). A
generic three-field binder has no way to know which arbitrary extra keys a specific upstream
treats as meaningful BY DEFAULT — that's what `route.allowedFields` (0.4.7, below) is for.

**0.4.5 — raised the `agentsafe-mcp-guard` floor to `^0.3.3`.** This package's canonical
signed-message format must match the guard's exactly (both sides run policy-core's
`buildAuthMessage`) — 0.3.3 escapes `\`/`|` before joining fields, and a deployment that
resolves an older guard on one side (the previous `^0.3.0` floor allowed as far back as
0.3.0) would silently fail signature verification for any field containing one of those
characters, for reasons that would not be obvious in the field. The gateway also now logs
the guard version it actually resolved at startup, since a lockfile override can still
diverge from the declared floor.

**0.4.6 — deprecation warning for routes with no explicit binding decision.** A protected
route with an `action` but neither `valueFields` nor `bind` set has always used the default
heuristic (`DEFAULT_VALUE_FIELDS`, currently `['amount', 'merchant']`) — safe, but an operator
who never read this file had no way to know that's happening, or whether the default actually
describes their route's real value fields. `createHttpGateway` now logs a startup warning
naming any such route. Nothing about request handling changes — this is purely additional
visibility, and a **future major version will refuse to start** instead of warning. Silence it
by setting `route.valueFields` explicitly (even to the current default, to say "yes, I looked,
this is right"), `route.bind` (a function), or `route.bind: false`.

**0.4.7 — `route.allowedFields`: an opt-in strict allowlist, and currency-as-required.**
Two residual gaps the default binder is deliberately loose about, both closed by fields a
route can now declare explicitly:

- `route.allowedFields` (a list of top-level body keys) rejects any key not on it —
  `PAYLOAD_UNBINDABLE`, same as any other unconfirmable shape — closing the additive-hidden-
  field gap above. It also refuses an array body outright, and requires `amount` to actually
  be a JS number rather than a decimal-equal string (`"250"` still passes `boundValueMatches`
  by value, but forwards to the upstream as a different TYPE than was signed — fine generally,
  worth refusing on a route strict enough to opt into this).
- `currency` was never required by default (see `DEFAULT_VALUE_FIELDS` above) — but it always
  COULD be, by simply listing it: `valueFields: ['amount', 'currency', 'merchant']`. Do this on
  any route whose governing mandate carries a `unit`-bearing spend constraint (see
  `agentsafe-guard`'s mandate-currency fix), so a body that omits currency can't silently drift
  from what the cap was actually authorized in.

```js
routes: [{
  method: 'POST', path: '/book/*', action: 'flight-purchase',
  valueFields: ['amount', 'currency', 'merchant'], // currency now required too
  allowedFields: ['amount', 'currency', 'merchant', 'riskLevel'], // nothing else allowed
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

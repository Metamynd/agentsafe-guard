// gateway.mjs — the generic HTTP interception gateway (SAFR §17, Phase-5 PR-4). A reverse proxy
// that GOVERNS arbitrary HTTP calls (not just MCP): matched protected routes are re-evaluated
// through the guard before the request is forwarded upstream; everything else passes through.
//
// This is the framework-agnostic CORE — a pure-ish request handler with the guard + the upstream
// forwarder INJECTED, so it is testable with fakes. `server.mjs` binds it to node:http + fetch.
//
// A protected route: { method, path, action, extract?, bind? }. The gateway needs the agent's
// SIGNED MAGP request to govern the call — by default it reads header `x-magp-request` (JSON of
// { agentDid, amount, merchant, itinerary, nonce, issuedAt, signature }); a route may override
// with its own `extract(req)`. The route's `action` is authoritative (the client can't pick it).
//
// PAYLOAD BINDING (see `bind` below): the signed request authorizes SPECIFIC VALUES, but the
// bytes we forward upstream are the request body — a different object. Governing the header
// while executing the body is a confused-deputy gap: an agent signs a cheap, in-policy request
// and ships an expensive one. The gateway therefore refuses to forward a body that either
// disagrees with what was signed, OR cannot be shown to carry the signed amount/merchant at all
// (nested, renamed, differently-cased, absent, non-JSON) — judged against what the SIGNED
// request actually constrains, not against whatever shape the body happens to expose.

import { matchRoute } from './route-match.mjs';

/** Default extractor: parse the signed MAGP request from the `x-magp-request` header (JSON). */
export function defaultExtractGovernance(req) {
  const raw = req.headers?.['x-magp-request'] ?? req.headers?.['X-MAGP-Request'];
  if (!raw) return null;
  try {
    return typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch {
    return null;
  }
}

/**
 * The value fields the canonical signed message actually covers (policy-core buildAuthMessage:
 * `agentDid|action|amount|currency|merchant|nonce|issuedAt`). These — and only these — are the
 * fields a signature can be said to authorize, so these are what we bind the payload to.
 */
export const BOUND_FIELDS = ['amount', 'currency', 'merchant'];

/**
 * Sentinel returned by `defaultBindPayload` (and usable by a custom `bind(req)`) for "the signed
 * request constrains a real value here, and this body cannot be shown to carry it."
 *
 * `createHttpGateway` fails a route CLOSED on this sentinel (`PAYLOAD_UNBINDABLE`) unless the
 * route opts out (`bind: false`) or supplies its own `bind(req, signed)` that actually finds the
 * fields — the supported way to constrain a nested, renamed, or non-JSON payload.
 */
export const UNBINDABLE = Symbol('agentsafe-http-gateway:unbindable');

/**
 * Fields whose PRESENCE at the body's top level is REQUIRED whenever the signed request names a
 * real value for them — not just compared when they happen to show up.
 *
 * `currency` is deliberately excluded from this list: plenty of real upstreams never repeat it
 * in the body at all (single-currency APIs, currency implied by the route or a header), and
 * requiring it would brick those deployments for a field that, alone, is rarely the attack. It
 * is still COMPARED when the body does include it (see the loop in createHttpGateway) — just not
 * required. `amount` and `merchant` are exactly the two fields an attacker profits from moving:
 * how much moves, and who it moves to.
 */
const REQUIRED_IF_SIGNED = ['amount', 'merchant'];

/** Does the signed request name a REAL value for this field, as opposed to the default
 *  verifyRequest() itself would apply to an absent one (amount 0, merchant '')? A field the
 *  signer never cared about in the first place has nothing for the body to be required to echo. */
function isMeaningfulSignedValue(field, value) {
  if (value === undefined || value === null) return false;
  if (field === 'amount') { const n = Number(value); return Number.isFinite(n) && n !== 0; }
  return String(value) !== '';
}

/**
 * Default payload binder: pull the governed value fields out of a JSON body, and REQUIRE that
 * `amount`/`merchant` be found there whenever the signed request actually constrains them.
 *
 * The earlier version of this function only asked "does the body carry NONE of the governed
 * fields" — treating a body that offered even one correct-looking field (or none at all) as
 * either fully bound or safely inert. Verified live: none of that holds. A decoy top-level
 * `merchant` matching the signed one, paired with the real amount nested one level down
 * (`{ merchant: 'skyward-air', booking: { amount: 5000 } }`), passed every prior check — the
 * merchant compared clean, and `amount` being merely ABSENT from the top level (not present-and-
 * wrong) was never itself treated as suspicious. Same shape with the amount renamed (`total`)
 * instead of nested. An entirely empty body, or a form-encoded one, was explicitly exempted by
 * the earlier design as "nothing to compare" — also live-exploitable, for the same reason: a
 * signed real amount with nothing in the body to check it against is not evidence of safety.
 *
 * So the standard is no longer "found nothing → assume nothing to bind." It is "the signed
 * request names a real amount/merchant → the body MUST expose that field, present and matching,
 * or the request fails CLOSED (`UNBINDABLE`)" — including when the body is empty, non-JSON, or
 * an array. The one surviving exception: a signed request that never names a real amount OR
 * merchant at all (both absent/default) has nothing this binder is entitled to require, so any
 * body — any shape, or none — passes through this check unbound, same as always.
 */
export function defaultBindPayload(req, signed) {
  const required = REQUIRED_IF_SIGNED.filter((f) => isMeaningfulSignedValue(f, signed?.[f]));
  const whenUnconfirmed = required.length > 0 ? UNBINDABLE : null;

  const raw = req.rawBody ?? req.body;
  if (raw == null) return whenUnconfirmed;
  let parsed = raw;
  if (typeof raw === 'string' || raw instanceof Uint8Array) {
    const text = typeof raw === 'string' ? raw : Buffer.from(raw).toString('utf8');
    if (!text.trim()) return whenUnconfirmed;
    try { parsed = JSON.parse(text); } catch { return whenUnconfirmed; } // genuinely not JSON
  }
  if (!parsed || typeof parsed !== 'object') return whenUnconfirmed; // a JSON scalar/null

  const out = {};
  for (const f of BOUND_FIELDS) if (parsed[f] !== undefined) out[f] = parsed[f];
  if (required.some((f) => out[f] === undefined)) return UNBINDABLE;
  return Object.keys(out).length ? out : whenUnconfirmed;
}

/**
 * Parse a value as a canonical decimal amount — a JS number, or a string matching a plain
 * decimal (`-?123` or `-?123.45`). Deliberately NOT what `Number()` accepts: no hex (`"0xFA"`),
 * no exponent notation (`"2.5e2"`), no leading/trailing whitespace (`" 250"`). `Number()` coerces
 * all of those to the value JS computes, but the forwarded body reaches the upstream VERBATIM —
 * a strict decimal parser, `parseInt(_, 10)`, or literal string storage on that end can read the
 * exact same bytes differently. The bind check saying "matches" is only meaningful if every
 * reasonable reader agrees what the number is; returns NaN for anything that isn't unambiguous.
 */
function parseCanonicalAmount(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : NaN;
  if (typeof value !== 'string' || !/^-?\d+(\.\d+)?$/.test(value)) return NaN;
  return Number(value);
}

/**
 * Whether a payload value matches the value that was signed. `amount` is compared as a
 * canonical decimal (a JSON body may carry "500" where the signer sent 500, but not "0x1F4" or
 * "5e2" — see parseCanonicalAmount); the rest as strings. Note the signed defaults
 * verifyRequest() itself applies — amount 0, merchant '' — so a payload that introduces a value
 * the signed request never mentioned counts as a MISMATCH, which is the whole point.
 */
export function boundValueMatches(field, signedValue, payloadValue) {
  if (field === 'amount') {
    const a = parseCanonicalAmount(signedValue ?? 0);
    const b = parseCanonicalAmount(payloadValue);
    return Number.isFinite(a) && Number.isFinite(b) && a === b;
  }
  // A single-element array (or any non-scalar) stringifies identically to its scalar
  // content — String(["acme"]) === "acme" — so a body carrying `"merchant": ["acme"]`
  // would pass this check even though it is structurally a different value than what was
  // signed, and how a given upstream reads an array where a string was expected is exactly
  // the kind of divergence this binder exists to refuse rather than guess about.
  if (isNonScalar(signedValue) || isNonScalar(payloadValue)) return false;
  return String(signedValue ?? '') === String(payloadValue ?? '');
}

function isNonScalar(v) {
  return v !== null && typeof v === 'object';
}

/**
 * Build the governed request handler.
 *   guard   — anything with `verifyRequest(signed) => { decision, reasonCode, ... }` (an MCP guard).
 *   routes  — protected-route configs (see matchRoute). No match ⇒ pass through (unless denyByDefault).
 *   forward — async (req) => { status, headers, body }: performs the upstream call. Injected for tests.
 *   extractGovernance — override the signed-request extractor (default: x-magp-request header).
 *   denyByDefault — when true, an UNMATCHED route is blocked (allow-list posture) instead of forwarded.
 *   bind    — payload binder, called as `bind(req, signed)` (default: defaultBindPayload). A
 *             route's own `bind` wins. Pass `false` to disable binding entirely and restore
 *             pre-0.1.2 behaviour — do that only for routes that carry no value fields, since it
 *             reopens the confused-deputy gap. Returning `UNBINDABLE` (see defaultBindPayload)
 *             fails the route CLOSED — a route whose value fields are nested/renamed/differently-
 *             cased needs its own `bind(req, signed)` that actually finds them, not silent
 *             pass-through.
 *
 * Returns async (req) => { status, headers?, body, governance? }, where req is a normalized
 * { method, path, headers, body }.
 */
export function createHttpGateway({ guard, routes = [], forward, extractGovernance = defaultExtractGovernance, denyByDefault = false, bind = defaultBindPayload } = {}) {
  if (typeof forward !== 'function') throw new Error('createHttpGateway requires a forward(req) function');

  return async function handle(req) {
    const route = matchRoute(routes, req.method, req.path);

    // Unprotected route → pass through (or fail closed under an allow-list posture).
    if (!route) {
      if (denyByDefault) {
        return { status: 403, body: { decision: 'block', reasonCode: 'ROUTE_NOT_ALLOWED', path: req.path } };
      }
      return forward(req);
    }

    // Protected route → the caller must present a signed MAGP request to be governed.
    const signed = (route.extract ?? extractGovernance)(req);
    if (!signed) {
      return { status: 401, body: { decision: 'block', reasonCode: 'MISSING_GOVERNANCE', action: route.action } };
    }
    // The route pins the action — a client cannot relabel a governed call as something cheaper.
    const request = { ...signed, action: route.action ?? signed.action };

    // Bind the payload to the signature BEFORE asking the issuer anything: a request whose body
    // contradicts what was signed is refused here, so it costs no round trip and consumes no
    // nonce. A decision obtained for one set of values must not authorize another set.
    const binder = route.bind !== undefined ? route.bind : bind;
    if (binder) {
      let payload;
      try {
        payload = binder(req, request);
      } catch (err) {
        // Fail CLOSED: if we cannot read the payload, we cannot claim the signature covers it.
        return { status: 502, body: { decision: 'block', reasonCode: 'BIND_ERROR', error: String(err?.message ?? err) } };
      }
      if (payload === UNBINDABLE) {
        // Fail CLOSED: a JSON body is present but none of the governed fields are visible at
        // the top level — nested, renamed, differently-cased, or an array. We cannot rule out
        // that the real amount/merchant just moved out of sight, so we refuse rather than
        // silently forward a body the signature cannot be shown to cover.
        return {
          status: 403,
          body: { decision: 'block', reasonCode: 'PAYLOAD_UNBINDABLE', action: route.action },
        };
      }
      if (payload) {
        for (const field of BOUND_FIELDS) {
          if (payload[field] === undefined) continue;
          if (!boundValueMatches(field, request[field], payload[field])) {
            return {
              status: 403,
              body: { decision: 'block', reasonCode: 'PAYLOAD_NOT_BOUND', field, action: route.action },
            };
          }
        }
      }
    }

    let decision;
    try {
      decision = await guard.verifyRequest(request);
    } catch (err) {
      // Fail CLOSED: a governance error blocks the upstream call.
      return { status: 502, body: { decision: 'block', reasonCode: 'GOVERNANCE_ERROR', error: String(err?.message ?? err) } };
    }

    // allow + observe both PERMIT the upstream call (observe = permit-but-flag, SAFR §11).
    if (decision?.decision !== 'allow' && decision?.decision !== 'observe') {
      return { status: 403, body: { decision: decision?.decision ?? 'block', reasonCode: decision?.reasonCode ?? 'BLOCKED' }, governance: decision };
    }
    const upstream = await forward(req);
    return { ...upstream, governance: decision };
  };
}

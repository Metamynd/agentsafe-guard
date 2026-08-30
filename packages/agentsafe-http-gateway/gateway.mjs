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
 * Fields whose PRESENCE at the body's top level is REQUIRED BY DEFAULT for any route using
 * the default binder — unconditionally, regardless of anything the SIGNED request declares.
 * Override per-route with `route.valueFields` (an empty array for a route with no value
 * fields at all — though `bind: false` is the more direct way to say that).
 *
 * This used to be computed FROM the signed request instead: `amount`/`merchant` were only
 * required when the signed value looked "meaningful," which handed the requirement's own
 * on/off switch to the party the binder exists to distrust. Two equivalent ways were found
 * to flip it off: sign `amount: 0` (amount-unknown/amount-over already treat a genuine $0 as
 * a real, valid, non-blocking amount, and the public authorize endpoint's own schema accepts
 * it — this is not a contrived edge case), or omit `amount` from the signed JSON entirely —
 * cryptographically IDENTICAL to signing 0, since every verifier destructures `amount = 0`
 * before rebuilding the canonical message, so an absent key and an explicit zero verify
 * against the exact same signature. Either way, a matching top-level `merchant` then
 * satisfied the only remaining requirement, and a real amount hidden elsewhere in the body
 * (nested, renamed) rode through completely unchecked. There is no signed-request-shaped
 * heuristic that closes both forms at once, because they are the same bytes — the required
 * set has to come from something the signer does not control.
 *
 * `currency` is deliberately excluded from the default: plenty of real upstreams never
 * repeat it in the body at all (single-currency APIs, currency implied by the route or a
 * header), and requiring it would brick those deployments for a field that, alone, is
 * rarely the attack. It is still COMPARED when the body does include it (see the loop in
 * createHttpGateway) — just not required by default. `amount` and `merchant` are exactly
 * the two fields an attacker profits from moving: how much moves, and who it moves to.
 */
const DEFAULT_VALUE_FIELDS = ['amount', 'merchant'];

/**
 * Default payload binder: pull the governed value fields out of a JSON body, and REQUIRE
 * that every field in `route.valueFields` (default: `amount`, `merchant`) be found there,
 * present and matching — full stop, not conditioned on what the signed request happens to
 * declare (see DEFAULT_VALUE_FIELDS for why).
 *
 * Earlier versions of this function asked "does the body carry NONE of the governed
 * fields" (only fully-bound or safely-inert), then "does the SIGNED request name a real
 * value for this field" (see DEFAULT_VALUE_FIELDS above for why that was still exploitable).
 * Verified live at each stage: a decoy top-level `merchant` matching the signed one, paired
 * with the real amount nested one level down (`{ merchant: 'skyward-air', booking: { amount:
 * 5000 } }`) or renamed (`total`), passed every prior check. An entirely empty body, or a
 * form-encoded one, was also explicitly exempted at one point as "nothing to compare" — also
 * live-exploitable, for the same reason: a required field with nothing in the body to check
 * it against is not evidence of safety.
 *
 * So the standard is "every field this route declares as value-bearing MUST be present in
 * the body and match, or the request fails CLOSED (`UNBINDABLE`)" — including when the body
 * is empty, non-JSON, or an array. A route with no value fields at all sets
 * `valueFields: []` (or uses `bind: false`), so any body shape passes through this check
 * unbound — a decision the route operator makes explicitly, not one inferred from the
 * signed request.
 */
export function defaultBindPayload(req, signed, route) {
  const required = route?.valueFields ?? DEFAULT_VALUE_FIELDS;
  const allowedFields = route?.allowedFields; // optional strict allowlist — see below
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

  // Strict mode (opt-in via `route.allowedFields`): amount/merchant genuinely matching what
  // was signed is not, by itself, evidence the request is safe to forward — a body can carry
  // an ADDITIVE key (`surcharge`, `feeOverride`, ...) this generic binder has no way to know
  // an upstream also honors. Left off by default (a residual, documented limitation — see
  // README), because a fixed three-field binder cannot know a specific upstream's full schema
  // without being told. A route that declares its complete expected shape here gets that
  // extra key refused outright instead of silently forwarded.
  if (allowedFields) {
    if (Array.isArray(parsed)) return UNBINDABLE; // a strict route never expects an array body
    if (Object.keys(parsed).some((k) => !allowedFields.includes(k))) return UNBINDABLE;
    // A decimal-equal numeric string ("250") still matches boundValueMatches's canonical
    // comparison, but forwards to the upstream VERBATIM as a string — a different type than
    // was signed. Low-risk generally (still decimal-equal, not a hex/exponent divergence — see
    // parseCanonicalAmount), but a route that opted into strict typing via allowedFields is
    // exactly the tier where a type mismatch, not just a value mismatch, should be refused.
    if (typeof parsed.amount === 'string') return UNBINDABLE;
  }

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
 *   bind    — payload binder, called as `bind(req, signed, route)` (default: defaultBindPayload,
 *             which requires `route.valueFields` — default `['amount', 'merchant']` — present
 *             and matching in the body, regardless of what the SIGNED request itself declares;
 *             see defaultBindPayload/DEFAULT_VALUE_FIELDS for why the required set must not be
 *             derived from the signed request). A route's own `bind` wins; a route's own
 *             `valueFields: []` opts a genuinely value-less route out of the default's
 *             requirement without disabling binding entirely. Pass `bind: false` to disable
 *             binding altogether and restore pre-0.1.2 behaviour — do that only for routes that
 *             carry no value fields, since it reopens the confused-deputy gap. Returning
 *             `UNBINDABLE` (see defaultBindPayload) fails the route CLOSED — a route whose value
 *             fields are nested/renamed/differently-cased needs its own `bind(req, signed)` that
 *             actually finds them, not silent pass-through. `route.allowedFields` (optional) is
 *             a strict allowlist: any top-level body key not in it is UNBINDABLE, closing the
 *             residual gap where an upstream honors an extra key (e.g. `surcharge`) alongside
 *             an honestly-matching amount/merchant — see defaultBindPayload.
 *
 * DEPRECATION WINDOW: any route with an `action` and neither `bind` nor `valueFields` set logs
 * a loud startup warning naming the route — it still works (the default heuristic above is
 * safe), but a future version will refuse to start instead of silently guessing. Set
 * `valueFields` explicitly (even to the current default) to silence it.
 *
 * Returns async (req) => { status, headers?, body, governance? }, where req is a normalized
 * { method, path, headers, body }.
 */
export function createHttpGateway({ guard, routes = [], forward, extractGovernance = defaultExtractGovernance, denyByDefault = false, bind = defaultBindPayload } = {}) {
  if (typeof forward !== 'function') throw new Error('createHttpGateway requires a forward(req) function');

  // Deprecation window: a protected route with an `action` but no EXPLICIT binding decision
  // silently gets the default heuristic (DEFAULT_VALUE_FIELDS) — safe today (see
  // DEFAULT_VALUE_FIELDS/defaultBindPayload), but an operator who never read this file has no
  // way to know that's happening, or that the default's ['amount','merchant'] might not
  // describe THEIR route's actual value fields. Warn now, loudly, naming the route; a future
  // major version will refuse to start instead of guessing. Silence it by setting
  // `route.valueFields` (even to the current default, to say "yes, I looked, this is right"),
  // `route.bind` (a function), or `route.bind: false`.
  for (const route of routes) {
    if (route?.action && route.bind === undefined && route.valueFields === undefined) {
      console.warn(
        `[gateway] route "${route.method ?? '*'} ${route.path}" (action: "${route.action}") has no explicit ` +
        `payload-binding decision and is using the default heuristic (requires ${DEFAULT_VALUE_FIELDS.join('/')} ` +
        `present and matching in the body). Set route.valueFields (e.g. ['amount','merchant'], or [] if this ` +
        `route carries no value fields), route.bind:false, or a custom route.bind(req, signed, route) — a ` +
        `future version will refuse to start instead of guessing. See README "Payload binding".`,
      );
    }
  }

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
        payload = binder(req, request, route);
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

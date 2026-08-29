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
// and ships an expensive one. The gateway therefore refuses to forward a body whose governed
// value fields disagree with the ones that were signed.

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
 * Default payload binder: pull the governed value fields out of a JSON body.
 *
 * Returns null when there is nothing to bind — an empty body, a body that is not JSON, or JSON
 * that mentions none of the governed fields. That is deliberate: a reverse proxy fronts upstreams
 * whose payloads it cannot parse (protobuf, multipart, form-encoded), and failing those closed
 * would brick every such deployment. It also means an OPAQUE BODY IS NOT BOUND — if your governed
 * route carries the amount somewhere this cannot see (a non-JSON encoding, or nested JSON such as
 * `{ booking: { amount } }`), give the route its own `bind(req)` that digs it out. Without one,
 * the signature still gates the call but does not constrain that payload.
 */
export function defaultBindPayload(req) {
  const raw = req.rawBody ?? req.body;
  if (raw == null) return null;
  let parsed = raw;
  if (typeof raw === 'string' || raw instanceof Uint8Array) {
    const text = typeof raw === 'string' ? raw : Buffer.from(raw).toString('utf8');
    if (!text.trim()) return null;
    try { parsed = JSON.parse(text); } catch { return null; } // not JSON → nothing to bind
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const out = {};
  for (const f of BOUND_FIELDS) if (parsed[f] !== undefined) out[f] = parsed[f];
  return Object.keys(out).length ? out : null;
}

/**
 * Whether a payload value matches the value that was signed. `amount` is compared numerically
 * (a JSON body may carry "500" where the signer sent 500); the rest as strings. Note the signed
 * defaults verifyRequest() itself applies — amount 0, merchant '' — so a payload that introduces
 * a value the signed request never mentioned counts as a MISMATCH, which is the whole point.
 */
export function boundValueMatches(field, signedValue, payloadValue) {
  if (field === 'amount') {
    const a = Number(signedValue ?? 0);
    const b = Number(payloadValue);
    return Number.isFinite(a) && Number.isFinite(b) && a === b;
  }
  return String(signedValue ?? '') === String(payloadValue ?? '');
}

/**
 * Build the governed request handler.
 *   guard   — anything with `verifyRequest(signed) => { decision, reasonCode, ... }` (an MCP guard).
 *   routes  — protected-route configs (see matchRoute). No match ⇒ pass through (unless denyByDefault).
 *   forward — async (req) => { status, headers, body }: performs the upstream call. Injected for tests.
 *   extractGovernance — override the signed-request extractor (default: x-magp-request header).
 *   denyByDefault — when true, an UNMATCHED route is blocked (allow-list posture) instead of forwarded.
 *   bind    — payload binder (default: defaultBindPayload). A route's own `bind` wins. Pass
 *             `false` to disable binding entirely and restore pre-0.1.2 behaviour — do that only
 *             for routes that carry no value fields, since it reopens the confused-deputy gap.
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
        payload = binder(req);
      } catch (err) {
        // Fail CLOSED: if we cannot read the payload, we cannot claim the signature covers it.
        return { status: 502, body: { decision: 'block', reasonCode: 'BIND_ERROR', error: String(err?.message ?? err) } };
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

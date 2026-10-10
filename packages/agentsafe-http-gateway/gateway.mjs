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
import { payloadDigestOf, toWireJson } from './payload-binding.mjs';
/** A fetch() with a 60 s keep-alive (see keepalive-fetch.mjs) — e.g. for a `forward` that calls the upstream service. */
export { keepAliveFetch } from './keepalive-fetch.mjs';

/**
 * Parse the JSON body STRICTLY, for digesting. `JSON.parse` is lossy in ways an attacker between the agent and this gateway can
 * use: a repeated key is last-wins (an upstream that reads first-wins runs a different payee), an integer beyond 2^53 or a
 * 20-digit decimal collapses to the nearest double (two different ids or amounts share a digest), and invalid UTF-8 becomes
 * U+FFFD. The digest is only worth anything if every reader of the forwarded bytes agrees what they say, so a body that is
 * ambiguous in any of those ways is refused rather than digested:
 *   - a duplicate object key (compared after unescaping);
 *   - a number that a double cannot carry exactly: an integer at or beyond 2^53 (2^53 and 2^53+1 are the same double; send large identifiers and amounts as strings), or a
 *     non-integer with more than 15 significant digits, or one that overflows or underflows;
 *   - bytes that are not valid UTF-8, or a leading byte-order mark;
 *   - anything after the value, or a control character inside a string.
 */
const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const MAX_PARSE_DEPTH = 64;

export function parseStrictJson(text) {
  let i = 0;
  const fail = (why) => { throw new Error(`body is not strict JSON: ${why} (at ${i})`); };
  const ws = () => { while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++; };
  function string() {
    const start = i;
    i++;
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x22) { i++; return JSON.parse(text.slice(start, i)); } // JSON.parse validates the escapes
      if (c < 0x20) fail('a control character inside a string');
      i += c === 0x5c ? 2 : 1;
    }
    return fail('an unterminated string');
  }
  function number() {
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) fail('a malformed number');
    const lit = m[0];
    i += lit.length;
    const n = Number(lit);
    if (!Number.isFinite(n)) fail('a number out of range');
    const mantissa = lit.replace(/^-/, '').split(/[eE]/)[0].replace('.', '').replace(/^0+/, '').replace(/0+$/, '');
    if (/^-?\d+$/.test(lit)) {
      if (Math.abs(n) > Number.MAX_SAFE_INTEGER) fail('an integer at or beyond 2^53 (send large identifiers and amounts as strings)');
    } else if (mantissa.length > 15) {
      fail('a number with more than 15 significant digits, which a double cannot carry exactly');
    }
    if (n === 0 && mantissa.length > 0) fail('a number that underflows to zero');
    return n;
  }
  function value(depth) {
    if (depth > MAX_PARSE_DEPTH) fail('nesting too deep');
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      const out = {};
      const seen = new Set();
      ws();
      if (text[i] === '}') { i++; return out; }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('an object key must be a string');
        const key = string();
        if (seen.has(key)) fail(`a duplicate key "${key}"`);
        seen.add(key);
        ws();
        if (text[i] !== ':') fail('expected ":"');
        i++;
        // defineProperty, not assignment: a key named __proto__ is a key, never the prototype
        Object.defineProperty(out, key, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return out; }
        fail('expected "," or "}"');
      }
    }
    if (c === '[') {
      i++;
      const out = [];
      ws();
      if (text[i] === ']') { i++; return out; }
      for (;;) {
        out.push(value(depth + 1));
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return out; }
        fail('expected "," or "]"');
      }
    }
    if (c === '"') return string();
    if (c === '-' || (c >= '0' && c <= '9')) return number();
    for (const [literal, v] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(literal, i)) { i += literal.length; return v; }
    }
    return fail('an unexpected token');
  }
  const result = value(0);
  ws();
  if (i < text.length) fail('data after the value');
  return result;
}

const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * The digest (spec 8.3.9) of the payload this gateway is about to FORWARD: the JSON body it received, or whatever the route's
 * `payload(req)` picks (e.g. a body plus path parameters). `{ none: true }` when there is no body to digest; `{ error }` when
 * there is one JSON cannot carry (a non-JSON body, NaN, a lone surrogate) or one that is ambiguous between readers (a duplicate
 * key, a number a double cannot hold exactly, invalid UTF-8; see parseStrictJson) — the caller decides what that means, and it
 * never means "skip the check". The body is decoded and parsed from the SAME bytes that are forwarded.
 */
export function executedPayloadDigest(req, route) {
  try {
    let value;
    if (typeof route?.payload === 'function') {
      value = route.payload(req);
    } else {
      const raw = req.rawBody ?? req.body;
      if (raw == null) return { none: true };
      value = raw;
      if (typeof raw === 'string' || raw instanceof Uint8Array) {
        const text = typeof raw === 'string' ? raw : UTF8.decode(raw);
        if (!text.trim()) return { none: true };
        value = parseStrictJson(text);
      }
    }
    return { digest: payloadDigestOf(toWireJson(value)) };
  } catch (error) {
    return { error };
  }
}
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
 * `agentDid|action|amount|currency|merchant|resource|nonce|issuedAt`). These — and only these —
 * are the fields a signature can be said to authorize, so these are what we bind the payload to.
 * `resource` is deliberately excluded from BOUND_FIELDS below — payload binding is about the
 * HTTP body's value fields (amount/merchant), not resource scoping, which the mandate/resource-
 * grant layer already governs independently.
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
 * The top-level body keys a route accepts when it declares no `allowedFields`: exactly the governed
 * value fields (BOUND_FIELDS). Everything else is an agent-chosen key the signature does not cover.
 */
export const DEFAULT_ALLOWED_FIELDS = Object.freeze([...BOUND_FIELDS]);

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
  // The body allowlist is ON by default (0.7.0): a route that says nothing accepts only the governed
  // value fields. `route.allowedFields` widens it to the tool's real fields; `null` is the explicit,
  // discouraged opt-out that permits any top-level key.
  const allowedFields = route?.allowedFields === undefined ? DEFAULT_ALLOWED_FIELDS : route.allowedFields;
  const whenUnconfirmed = required.length > 0 ? UNBINDABLE : null;

  const raw = req.rawBody ?? req.body;
  if (raw == null) return whenUnconfirmed;
  let parsed = raw;
  if (typeof raw === 'string' || raw instanceof Uint8Array) {
    // The SAME strict reader the payload digest uses (parseStrictJson, fatal UTF-8): a body with a duplicate key, a number a
    // double cannot hold, or invalid UTF-8 has no single meaning, so amount/merchant cannot be shown to be what the upstream
    // will read — it is refused (UNBINDABLE where a value field is required), never resolved last-wins.
    try {
      const text = typeof raw === 'string' ? raw : UTF8.decode(raw);
      if (!text.trim()) return whenUnconfirmed;
      parsed = parseStrictJson(text);
    } catch { return whenUnconfirmed; } // not JSON, or ambiguous
  }
  if (!parsed || typeof parsed !== 'object') return whenUnconfirmed; // a JSON scalar/null

  // Strict body (ON by default since 0.7.0, `route.allowedFields` to widen, `null` to opt out):
  // amount/merchant genuinely matching what was signed is not, by itself, evidence the request is
  // safe to forward — a body can carry an ADDITIVE key (`surcharge`, `feeOverride`, ...) this
  // generic binder has no way to know an upstream also honors. Through 0.6.x this was opt-in, which
  // left every route that did not think about it forwarding whatever extra keys the agent chose to
  // add (a documented residual gap that was reproduced: `surcharge` reached the upstream). Now an
  // unknown key is refused unless the route declares its complete expected shape.
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
 * Percent-decode every `%XX` (byte-wise, never throwing) until the string stops changing, at most 4 rounds — so a
 * double- or triple-encoded `%253F` is seen for what an upstream that decodes more than once would read.
 */
function decodeFully(s) {
  let cur = s;
  for (let round = 0; round < 4; round++) {
    const next = cur.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

/** A query key a route may list in `allowedQuery`: plain, unencoded, and never one of the signed value fields. */
const QUERY_KEY = /^[A-Za-z0-9_.~-]+$/;

/**
 * Check the request target of a GOVERNED route for anything the agent's signature does not cover (M-7). The signed request
 * and the payload binding cover the BODY; the URL query string reaches the upstream verbatim, so an upstream that reads
 * `?amount=4000&merchant=attacker-llc` would act on values nobody signed. Returns null when the target is clean, or a short
 * reason string when it must be refused (`QUERY_NOT_BOUND`):
 *   - a fragment (`#`), raw or percent-encoded at any depth;
 *   - a query (`?`), a path parameter (`;`), or a fragment encoded into the PATH (`%3F`, `%253F`, `;`, `%3B`, `%23`);
 *   - any query at all — even an empty `?` — unless the route lists `allowedQuery`;
 *   - with `allowedQuery`: a parameter whose key is not listed EXACTLY (no encoded, renamed or differently-cased key), a
 *     key that appears twice (first-wins and last-wins readers disagree, like a duplicate JSON key), an empty `&&`
 *     segment, a `;` separator, or a value whose decoded form carries `& ; ? #` (a double-decoding upstream would read
 *     it as more parameters). An `=` in a value is allowed (0.17.3): on its own it cannot start a parameter — only a
 *     separator can — and base64 cursors and padded tokens (`cursor=abc==`) carry it.
 */
export function queryRefusal(path, route) {
  const target = String(path ?? '');
  if (decodeFully(target).includes('#')) return 'a URL fragment';
  const qi = target.indexOf('?');
  const pathPart = qi < 0 ? target : target.slice(0, qi);
  if (/[?;]/.test(decodeFully(pathPart))) return 'a query or path parameter encoded into the path';
  if (qi < 0) return null;
  const allowed = route?.allowedQuery;
  if (!Array.isArray(allowed)) return 'a query string on a governed route that declares no allowedQuery';
  const query = target.slice(qi + 1);
  if (query === '') return null;
  if (query.includes(';')) return 'a ";" query separator';
  const seen = new Set();
  for (const part of query.split('&')) {
    if (part === '') return 'an empty query parameter';
    const eq = part.indexOf('=');
    const key = eq < 0 ? part : part.slice(0, eq);
    const value = eq < 0 ? '' : part.slice(eq + 1);
    if (!allowed.includes(key)) return `query parameter "${key}" is not in allowedQuery`;
    if (seen.has(key)) return `query parameter "${key}" appears more than once`;
    seen.add(key);
    if (/[&;?#]/.test(decodeFully(value.replace(/\+/g, ' ')))) return `query parameter "${key}" carries an encoded separator`;
  }
  return null;
}

/** Validate a route's `allowedQuery` at construction time; throws on a misconfiguration (never guesses). */
function assertAllowedQuery(route) {
  if (route?.allowedQuery === undefined) return;
  const where = `route "${route.method ?? '*'} ${route.path}"`;
  if (!Array.isArray(route.allowedQuery)) throw new Error(`allowedQuery for ${where} must be an array of query keys`);
  // Compared case-insensitively (0.17.3): an upstream that reads query keys case-insensitively would take `Amount` for
  // the signed `amount`, so listing any casing of a signed value field is refused.
  const valueFields = new Set([...BOUND_FIELDS, ...(route.valueFields ?? DEFAULT_VALUE_FIELDS)].map((f) => String(f).toLowerCase()));
  for (const k of route.allowedQuery) {
    if (typeof k !== 'string' || !QUERY_KEY.test(k)) throw new Error(`allowedQuery for ${where} has an invalid key ${JSON.stringify(k)} (letters, digits, _ . ~ - only)`);
    if (valueFields.has(k.toLowerCase())) throw new Error(`allowedQuery for ${where} may not list "${k}": it is (a casing of) a signed value field, and a query parameter is not covered by the signature`);
  }
}

const RISK_LEVELS = new Set(['low', 'medium', 'high', 'critical']);

/**
 * A route's `trustedContext`, once resolved, must be a real object, and any `riskLevel` in it a real level (read
 * case- and whitespace-tolerantly, as policy-core does). Anything else means the deriver is broken; throwing here
 * fails the request closed (502 GOVERNANCE_ERROR, nothing forwarded).
 */
function assertTrustedContext(tc, route) {
  const where = `route "${route?.method ?? '*'} ${route?.path}"`;
  if (tc === null || typeof tc !== 'object' || Array.isArray(tc)) throw new Error(`trustedContext for ${where} must be an object (got ${tc === null ? 'null' : Array.isArray(tc) ? 'an array' : typeof tc})`);
  if (Object.prototype.hasOwnProperty.call(tc, 'riskLevel') && !(typeof tc.riskLevel === 'string' && RISK_LEVELS.has(tc.riskLevel.trim().toLowerCase()))) {
    throw new Error(`trustedContext.riskLevel for ${where} is not one of low|medium|high|critical`);
  }
}

/** A copy of `headers` with every spelling of `name` removed, then `name` set to `value` when there is one. */
function withHeader(headers, name, value) {
  const out = {};
  for (const [k, v] of Object.entries(headers ?? {})) if (k.toLowerCase() !== name) out[k] = v;
  if (value) out[name] = value;
  return out;
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
 * settle / releaseOnStatus — OPTIONAL: what the gateway does with the HOLD it claimed once the
 * upstream has answered (needs agentsafe-mcp-guard >= 0.7.0 and `requireAuthorization`). `settle`
 * (default true) captures a 2xx at the authorized amount, releases a status listed in
 * `releaseOnStatus` (default `[]` — see closeHold for why releasing is opt-in), and otherwise
 * marks the effect UNKNOWN so the spend stays committed. Per-route `route.releaseOnStatus`
 * overrides. `settle: false` restores the old behaviour of never touching the hold.
 *
 * settleInBackground — OPTIONAL (default true, since 0.16.0): the upstream's response is returned to the caller first and
 * the hold is settled after, so the settlement's round trip to the issuer is no longer part of every governed call. A
 * transient settlement failure (issuer unreachable, 5xx, 429) is retried after each of `settleRetryDelaysMs` (default
 * [500, 2000]); a refusal is final and logged. A settlement that never lands (the process killed first) leaves the
 * claimed hold committed to the cap — over-counting, never under-counting — for the owner to reconcile. On shutdown,
 * `await handle.drainSettlements(ms)` waits for the ones still running (server.mjs does). `false` settles before
 * answering, as before.
 *
 * resolveCredential — OPTIONAL: `({ request, route, decision }) => Promise<{header, value} | null>`,
 * called ONLY on a PERMIT (after the guard already returned allow/observe), right before
 * `forward(req)`. When it resolves a `{header, value}` pair, that header is spliced into a
 * SHALLOW-CLONED copy of `req.headers` before forwarding — the original `req` object passed to
 * `handle()` is never mutated. This is the Trusted Execution Gateway hook (MetaMynd Governed
 * Execution scope, Module G — Credential Vault): it lets an operator inject an upstream
 * credential the AGENT never sees, resolved server-side from `request.authorizationId` (the
 * signed request's own claimed authorization — see agentsafe-mcp-guard's `requireAuthorization`
 * doc for where that field comes from). Omitted (the default) → today's exact behavior, zero
 * change for every existing consumer of this package. FAILS CLOSED (since 0.13.0): when the hook
 * throws, resolves null/undefined (the vault refused), or resolves anything that is not a
 * non-empty string `{header, value}`, the call is NOT forwarded — the caller gets
 * `502 { decision: 'block', reasonCode: 'CREDENTIAL_UNAVAILABLE' }`, and a hold this request
 * claimed is released (nothing was sent upstream, so nothing executed; skipped with
 * `settle: false`). Earlier versions logged the failure and forwarded WITHOUT a credential,
 * which relied on every upstream rejecting an unauthenticated call. A route that needs no
 * credential sets `route.credential: false` and the hook is not called for it.
 *
 * requireContextSignature — OPTIONAL (needs agentsafe-mcp-guard >= 0.17.0): true refuses a governed request that
 * carries no `envelopeSignature` (the agent's own signature over its itinerary/trace/materiality — context-claim
 * binding) with `403 CONTEXT_SIGNATURE_REQUIRED`, before any rule is evaluated; `route.requireContextSignature`
 * overrides it per route. Unset (the default) → the guard's own `requireContextSignature` (off unless the guard was
 * built with it). A PRESENT `envelopeSignature` is always verified by the guard either way — one that does not verify
 * over the request as it reached this gateway is `403 CONTEXT_SIGNATURE_INVALID`.
 *
 * route.allowedQuery — OPTIONAL (since 0.17.1): a governed route refuses any URL query string, and any query, fragment or
 * path parameter encoded into its path, with `403 QUERY_NOT_BOUND` before anything is claimed — the signature covers the
 * body, not the URL (see queryRefusal). `allowedQuery: ['page', 'sort']` forwards exactly those keys, each at most once,
 * UNBOUND (logged at startup); a signed value field (amount/currency/merchant, or one in `valueFields`) cannot be listed.
 * Unmatched routes are untouched.
 *
 * reportOutcomes — OPTIONAL (default false, since 0.20.0; needs agentsafe-mcp-guard >= 0.21.0 with a self-certifying
 * serviceDid and its key): report every governed request this gateway answers to the issuer, signed as this gateway, into the
 * audit trail of the owner of the agent it acts for (MAGP §16.4) — what it EXECUTED without claiming an authorization (a
 * bundle-only route: the issuer never sees those otherwise) and what it REFUSED itself (AGENT_NOT_ADMITTED, a rule, a binding
 * failure). An execution under a claimed authorization is not reported: the claim already put it on the effect chain. A
 * request refused before it named an agent (no signed request, a query string) has nobody to attribute it to and is not
 * reported. Reports run in the background like settlements (drainSettlements waits for both) and never change a response.
 *
 * Returns async (req) => { status, headers?, body, governance? }, where req is a normalized
 * { method, path, headers, body }.
 */
export function createHttpGateway({ guard, routes = [], forward, extractGovernance = defaultExtractGovernance, denyByDefault = false, bind = defaultBindPayload, resolveCredential, settle = true, releaseOnStatus = [], requirePayloadBinding = false, requireContextSignature, settleInBackground = true, settleRetryDelaysMs = [500, 2000], reportOutcomes = false, reportSpool, reportSpoolRetryMs = 30_000, refusalWindowMs = 60_000 } = {}) {
  if (typeof forward !== 'function') throw new Error('createHttpGateway requires a forward(req) function');
  if (reportOutcomes && typeof guard?.reportOutcome !== 'function') {
    console.warn('[gateway] reportOutcomes is set, but this guard cannot report (needs @metamynd/agentsafe-mcp-guard >= 0.21.0) — nothing will be reported');
  }

  /** Hold close-outs running after their response was returned (settleInBackground). */
  const pendingSettlements = new Set();

  /**
   * One settlement call to the issuer, retried on a TRANSIENT failure: the issuer unreachable, or a 5xx/429. A refusal
   * (any other 4xx, or `success: false` — e.g. NOT_HELD because an earlier attempt already landed) is final. The guard
   * reports failures by RESULT (`{ ok: false, ... }`), not by throwing, so the result is what is judged — a failed
   * capture used to be dropped here without a trace.
   */
  async function settleCall(label, authorizationId, call) {
    for (let attempt = 0; ; attempt++) {
      let result;
      try {
        result = await call();
      } catch (err) {
        result = { ok: false, reasonCode: 'SETTLEMENT_THREW', error: String(err?.message ?? err) };
      }
      if (!result || result.ok !== false) return result;
      const transient = result.reasonCode === 'ISSUER_UNREACHABLE' || result.reasonCode === 'SETTLEMENT_THREW' || result.status === 429 || (typeof result.status === 'number' && result.status >= 500);
      if (!transient || attempt >= settleRetryDelaysMs.length) {
        console.warn(`[gateway] ${label} of ${authorizationId} not applied (${result.reasonCode}${result.status ? `, HTTP ${result.status}` : ''}${transient ? `, after ${attempt + 1} attempts` : ''}) — the claimed hold stays committed to the cap`);
        return result;
      }
      await new Promise((r) => setTimeout(r, settleRetryDelaysMs[attempt]));
    }
  }

  /**
   * Close the hold without holding up the caller. The upstream has answered; the settlement is bookkeeping about that
   * answer and never changes it (closeHold is non-throwing), so waiting for it only added one round trip to the issuer to
   * every governed call. A settlement that never lands — the process killed first — leaves the claimed hold committed to
   * the cap (over-counts, never under-counts) for the owner to reconcile; a clean shutdown waits for them
   * (drainSettlements). `settleInBackground: false` restores settling before the response is returned.
   */
  function settleHold(decision, request, route, status) {
    if (!settleInBackground) return closeHold(decision, request, route, status);
    const p = closeHold(decision, request, route, status).catch(() => {});
    pendingSettlements.add(p);
    p.finally(() => pendingSettlements.delete(p));
    return undefined;
  }

  /**
   * Close out the hold this request CLAIMED, now that the upstream has answered. The issuer treats a
   * claimed hold as a commitment: it stays against the mandate's cap until settled, and can be
   * settled below its amount or released only with the claim token the successful claim returned
   * (`decision.claimToken`, relayed by agentsafe-mcp-guard >= 0.7.0). This gateway is the party that
   * holds that token, so it is the party that closes the hold:
   *
   *   2xx                      → capture at the authorized amount (the body was bound to it)
   *   status in releaseOnStatus → RELEASE: the upstream declined, nothing happened, the budget returns
   *   anything else / a throw   → mark UNKNOWN: the outcome is ambiguous, so the spend stays committed
   *
   * `releaseOnStatus` defaults to [] on purpose. Releasing hands the budget back, so it is only
   * correct when a given status GUARANTEES the upstream did not execute; a 4xx from an upstream that
   * runs the action and then fails its own response validation would otherwise let an agent recover
   * the budget of something that happened. List the statuses your upstream honours that guarantee
   * for (e.g. [400, 401, 403, 404, 422]) — per gateway here, or per route with `route.releaseOnStatus`.
   * With the default a rejected call keeps its budget committed (over-counts, never under-counts).
   *
   * Best-effort and non-throwing: closing a hold never changes the response the caller gets. A no-op
   * when `settle: false`, when the guard predates the settlement helpers, or when the request made no
   * claim (a value-less action, or `requireAuthorization` off) — there is no token then.
   */
  async function closeHold(decision, request, route, status) {
    // Two ways to be the party that may close this hold: the issuer handed this Service a claim token
    // (anonymous claim), or the claim was signed as this Service's own identity (`counterpartyAuthenticated`,
    // agentsafe-mcp-guard >= 0.8.0) — in which case there is no token and every call below is signed instead.
    if (!settle || !decision?.authorizationId || !(decision.claimToken || decision.counterpartyAuthenticated)) return;
    const claim = { authorizationId: decision.authorizationId, claimToken: decision.claimToken };
    const id = decision.authorizationId;
    if (status >= 200 && status < 300) {
      if (typeof guard.captureAuthorization === 'function') await settleCall('capture', id, () => guard.captureAuthorization({ ...claim, amountCharged: Number(request.amount ?? 0) }));
    } else if (status !== undefined && (route.releaseOnStatus ?? releaseOnStatus).includes(status)) {
      if (typeof guard.releaseAuthorization === 'function') await settleCall('release', id, () => guard.releaseAuthorization({ ...claim, reason: `UPSTREAM_HTTP_${status}` }));
    } else if (typeof guard.markAuthorizationUnknown === 'function') {
      await settleCall('mark-unknown', id, () => guard.markAuthorizationUnknown({ ...claim, reason: status === undefined ? 'UPSTREAM_ERROR' : `UPSTREAM_HTTP_${status}` }));
    }
  }

  /**
   * Release the hold this request claimed when the gateway itself refused to forward it (the upstream was
   * never called, so nothing can have executed). Same gating and best-effort posture as closeHold.
   */
  async function releaseUnexecuted(decision, reason) {
    if (!settle || !decision?.authorizationId || !(decision.claimToken || decision.counterpartyAuthenticated)) return;
    if (typeof guard.releaseAuthorization !== 'function') return;
    try {
      await guard.releaseAuthorization({ authorizationId: decision.authorizationId, claimToken: decision.claimToken, reason });
    } catch (err) {
      console.warn('[gateway] could not release the claimed hold (it stays committed to the cap):', err?.message ?? err);
    }
  }

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

  // Since 0.7.0 a governed route refuses any top-level body key it has not been told about. Say so at
  // startup for a route relying on the default, because that is the moment an operator whose tool
  // legitimately takes more fields (`items`, `riskLevel`, ...) needs to declare them.
  for (const route of routes) {
    if (route?.action && route.bind === undefined && route.allowedFields === undefined) {
      console.warn(
        `[gateway] route "${route.method ?? '*'} ${route.path}" (action: "${route.action}") declares no ` +
        `allowedFields, so its body may carry only ${DEFAULT_ALLOWED_FIELDS.join('/')} — any other top-level key is ` +
        `refused (PAYLOAD_UNBINDABLE). Set route.allowedFields to the fields your tool actually reads (or [] for a ` +
        `tool that reads none); null permits any key and is not recommended. See README "Payload binding".`,
      );
    }
  }

  // Since 0.17.1 a governed route refuses a query string (QUERY_NOT_BOUND) unless it lists `allowedQuery`. A listed
  // key is forwarded but NOT covered by the agent's signature — say so at startup, once per route.
  // A route's own admitted agents (a credential profile, §16.3): narrower than the gateway's, checked by the guard after the
  // signature and before anything is fetched or claimed. A malformed list fails startup; so does one the guard cannot enforce.
  for (const route of routes) {
    if (route?.allowedAgents === undefined) continue;
    if (!Array.isArray(route.allowedAgents) || route.allowedAgents.length === 0 || route.allowedAgents.some((d) => typeof d !== 'string' || d.trim() === '')) {
      throw new Error(`route "${route.method ?? '*'} ${route.path}": allowedAgents must be a non-empty array of agent DIDs`);
    }
    if (guard?.gatewayOwnerPrincipal === undefined) {
      throw new Error(`route "${route.method ?? '*'} ${route.path}" sets allowedAgents, but this guard cannot enforce it (needs @metamynd/agentsafe-mcp-guard >= 0.22.0)`);
    }
  }

  for (const route of routes) {
    assertAllowedQuery(route);
    if (Array.isArray(route?.allowedQuery) && route.allowedQuery.length > 0) {
      console.warn(
        `[gateway] route "${route.method ?? '*'} ${route.path}" forwards query parameter(s) ${route.allowedQuery.join(', ')} ` +
        `UNBOUND: the agent's signature and payload binding cover the body, not the URL query. List only keys whose value ` +
        `the upstream may take from the caller unchecked (paging, sorting), or bind them with a route.payload(req) that ` +
        `includes them and that the agent signs. See README "Query strings".`,
      );
    }
  }

  /**
   * Report one governed request in the background (reportOutcomes, MAGP §16.4). Never throws, never awaited by the caller.
   */
  const reportWarned = new Set();
  /** Run a report in the background (drainSettlements waits for it); never throws, never changes a response. */
  function background(promise) {
    const p = Promise.resolve(promise).catch(() => {});
    pendingSettlements.add(p);
    p.finally(() => pendingSettlements.delete(p));
  }
  /** A failure worth retrying later: the issuer unreachable or overloaded, or the local signer briefly away. */
  const transientReportFailure = (r) => r?.reasonCode === 'REPORT_UNREACHABLE' || r?.reasonCode === 'SERVICE_SIGNING_FAILED' || r?.status === 429 || (typeof r?.status === 'number' && r.status >= 500);

  // Durable reporting (refinement plan phase 3): a report that fails for a transient reason is appended to `reportSpool` (a
  // JSON-lines file) with its reportId, and re-sent — re-signed with a fresh nonce, the same reportId, so the issuer records
  // it once — every `reportSpoolRetryMs` and at startup. A report the issuer REFUSED (unregistered gateway, bad request) is
  // not retried. The spool is capped; past the cap the newest report is dropped and that is said once.
  const SPOOL_CAP = 10_000;
  let flushing = null;
  async function spoolReport(params) {
    if (!reportSpool) return false;
    try {
      const fsp = await import('node:fs/promises');
      const existing = await fsp.readFile(reportSpool, 'utf8').catch(() => '');
      if (existing.split('\n').filter(Boolean).length >= SPOOL_CAP) {
        if (!reportWarned.has('SPOOL_FULL')) { reportWarned.add('SPOOL_FULL'); console.warn(`[gateway] report spool ${reportSpool} is full (${SPOOL_CAP}); further failed reports are dropped until it drains`); }
        return false;
      }
      await fsp.appendFile(reportSpool, JSON.stringify(params) + '\n', 'utf8');
      return true;
    } catch (err) {
      if (!reportWarned.has('SPOOL_WRITE')) { reportWarned.add('SPOOL_WRITE'); console.warn(`[gateway] could not write the report spool ${reportSpool}: ${err?.message ?? err}`); }
      return false;
    }
  }
  async function sendReport(params, { fromSpool = false } = {}) {
    const r = await guard.reportOutcome(params);
    if (r && r.ok === false && transientReportFailure(r)) {
      if (!fromSpool) await spoolReport({ ...params, reportId: r.reportId ?? params.reportId });
      return r;
    }
    // Once per reason: a gateway with no signing identity, or one its owner never registered, would otherwise say so on every request.
    if (r && r.ok === false && r.reasonCode !== 'NOTHING_TO_REPORT' && !reportWarned.has(r.reasonCode)) {
      reportWarned.add(r.reasonCode);
      console.warn(`[gateway] outcome reports are not being recorded (${r.reasonCode}${r.status ? `, HTTP ${r.status}` : ''}) — see README "Reporting outcomes"`);
    }
    return r;
  }
  /** Re-send every spooled report once; those that fail transiently again go back to the spool. */
  async function flushSpool() {
    if (!reportSpool || typeof guard?.reportOutcome !== 'function') return 0;
    if (flushing) return flushing;
    flushing = (async () => {
      const fsp = await import('node:fs/promises');
      const work = `${reportSpool}.flushing`;
      try { await fsp.rename(reportSpool, work); } catch { return 0; } // nothing spooled
      const lines = (await fsp.readFile(work, 'utf8').catch(() => '')).split('\n').filter(Boolean);
      let sent = 0;
      for (const line of lines) {
        let params; try { params = JSON.parse(line); } catch { continue; }
        const r = await sendReport(params, { fromSpool: true }).catch(() => ({ ok: false, reasonCode: 'REPORT_UNREACHABLE' }));
        if (r?.ok !== false) sent++;
        else if (transientReportFailure(r)) await fsp.appendFile(reportSpool, line + '\n', 'utf8').catch(() => {});
      }
      await fsp.unlink(work).catch(() => {});
      return sent;
    })().finally(() => { flushing = null; });
    return flushing;
  }
  if (reportOutcomes && reportSpool) {
    background(flushSpool()); // what an earlier run left behind
    const t = setInterval(() => background(flushSpool()), reportSpoolRetryMs);
    t.unref?.();
  }

  // Refusals are aggregated (refinement plan phase 3; A-1 review, M2): the first refusal of a caller for a reason is reported
  // at once, and the repeats within `refusalWindowMs` become ONE report carrying their count when the window closes —
  // nothing is dropped, and a flood of junk to a governed route cannot bury the owner's log. Executions are never coalesced.
  const refusalWindows = new Map(); // `${callerDid}|${reasonCode}` -> { until, extra, latest, timer }
  function closeWindow(key) {
    const w = refusalWindows.get(key);
    if (!w) return;
    clearTimeout(w.timer);
    refusalWindows.delete(key);
    // Carried by the LATEST repeat's signed request, so the aggregate shows the most recent attempt, not a copy of the
    // first refusal (already reported on its own).
    if (w.extra > 0) background(sendReport({ ...w.latest, occurrences: w.extra }));
  }
  function queueReport(trace, result, thrown) {
    if (!reportOutcomes || typeof guard?.reportOutcome !== 'function' || !trace.route || !trace.request) return;
    const executed = trace.forwarded === true;
    // A claimed authorization is on the effect chain already (claim → capture); reporting it again would only duplicate.
    const claimed = trace.decision?.authorizationId && (trace.decision.claimToken || trace.decision.counterpartyAuthenticated) ? trace.decision.authorizationId : undefined;
    if (executed && claimed) return;
    const status = Number(result?.status);
    const httpStatus = Number.isInteger(status) ? status : null;
    const reasonCode = executed ? (thrown ? 'UPSTREAM_ERROR' : 'EXECUTED') : (result?.body?.reasonCode ?? trace.decision?.reasonCode ?? 'BLOCKED');
    // Only an authorization this gateway CLAIMED is reported as the one the request ran under; one the request merely named
    // (a low-risk call allowed on its own merits, carrying an approved escalation's id) is reported as presented, never
    // attributed (0.26.1, pre-beta rerun 6 FW6-3).
    const params = { signed: trace.request, outcome: executed ? 'executed' : 'refused', reasonCode, httpStatus, ...(claimed ? { claimedAuthorizationId: claimed } : {}) };
    if (!executed) {
      const key = `${trace.request.agentDid}|${reasonCode}`;
      const open = refusalWindows.get(key);
      if (open && open.until > Date.now()) { open.extra++; open.latest = params; return; }
      if (open) closeWindow(key);
      if (refusalWindows.size >= 5000) for (const k of [...refusalWindows.keys()].slice(0, 500)) closeWindow(k); // bound memory
      const w = { until: Date.now() + refusalWindowMs, extra: 0, latest: null, timer: null };
      w.timer = setTimeout(() => closeWindow(key), refusalWindowMs);
      w.timer.unref?.();
      refusalWindows.set(key, w);
    }
    background(sendReport(params));
  }

  async function handle(req) {
    const trace = {};
    let result;
    try {
      result = await decide(req, trace);
    } catch (err) {
      queueReport(trace, undefined, true);
      throw err;
    }
    queueReport(trace, result, false);
    return result;
  }

  async function decide(req, trace) {
    const route = matchRoute(routes, req.method, req.path);
    trace.route = route;

    // Unprotected route → pass through (or fail closed under an allow-list posture).
    if (!route) {
      if (denyByDefault) {
        return { status: 403, body: { decision: 'block', reasonCode: 'ROUTE_NOT_ALLOWED', path: req.path } };
      }
      return forward(req);
    }

    // The signature and the payload binding cover the BODY; the URL query reaches the upstream verbatim. Refuse a query
    // (or one smuggled into the path) the route has not explicitly allowed — before anything is claimed or consumed.
    const queryProblem = queryRefusal(req.path, route);
    if (queryProblem) {
      // Reported like every other refusal of a signed request (0.30.1, pre-beta 2026-10-09 L1): it used to return before
      // the request was read, so the owner's Activity Log never saw it. Reading the header claims and consumes nothing; a
      // call with no signed request (or one that cannot be read) names no agent and stays unreported, as MISSING_GOVERNANCE.
      try {
        const presented = (route.extract ?? extractGovernance)(req);
        if (presented && typeof presented.agentDid === 'string') trace.request = presented;
      } catch {
        // unreadable: nobody to attribute the refusal to
      }
      return { status: 403, body: { decision: 'block', reasonCode: 'QUERY_NOT_BOUND', action: route.action, error: `refused: ${queryProblem}` } };
    }

    // Protected route → the caller must present a signed MAGP request to be governed.
    const signed = (route.extract ?? extractGovernance)(req);
    if (!signed) {
      return { status: 401, body: { decision: 'block', reasonCode: 'MISSING_GOVERNANCE', action: route.action } };
    }
    // The route pins the action — a client cannot relabel a governed call as something cheaper. A request signed for another
    // action is refused here, by name: substituting the route's action made the signature fail, and the agent was told
    // SIGNATURE_INVALID — a key problem — for calling the wrong route (pre-beta evaluation 2026-10-09, M2). Nothing is claimed
    // and no nonce consumed; the refusal is reported under the request as the agent signed it, so it still verifies.
    if (route.action && typeof signed.action === 'string' && signed.action !== route.action) {
      trace.request = signed;
      return { status: 403, body: { decision: 'block', reasonCode: 'GATEWAY_ACTION_MISMATCH', action: route.action, signedAction: signed.action } };
    }
    const request = { ...signed, action: route.action ?? signed.action };
    trace.request = request;

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

    // Payload binding (spec 8.3.9): digest the payload this gateway is about to forward and hand it to the guard, which refuses
    // a mismatch with what the agent signed and states it in the CLAIM — where the issuer compares it with the digest IT stored
    // at authorize time. `requirePayloadBinding` (per route or gateway-wide) refuses a request whose authorization binds none.
    // A body that JSON cannot carry, for a request that DID bind a payload, is refused: it cannot be shown to be the one signed.
    const requireBinding = route.requirePayloadBinding ?? requirePayloadBinding;
    let payloadDigest;
    if (request.payloadDigest !== undefined || request.payloadSignature !== undefined || requireBinding) {
      const executed = executedPayloadDigest(req, route);
      if (executed.digest) {
        payloadDigest = executed.digest;
      } else if (request.payloadDigest !== undefined) {
        return { status: 403, body: { decision: 'block', reasonCode: 'PAYLOAD_NOT_BOUND', field: 'payload', action: route.action } };
      } else if (requireBinding) {
        return { status: 403, body: { decision: 'block', reasonCode: 'PAYLOAD_BINDING_REQUIRED', action: route.action } };
      }
    }

    let decision;
    try {
      // What THIS route knows about its own action (`route.trustedContext`: an object, or
      // `(request, req) => object`) is context the gateway DERIVED, not the agent's claim — most usefully
      // `{ riskLevel: 'high' }` for a wire-transfer route. The guard applies it over whatever the agent said and
      // labels it `gateway_derived` (spec §6.4.3): the agent can raise its risk, never lower it below this. A
      // throwing deriver fails the request closed (below), never silently down to the agent's word.
      const configured = route?.trustedContext !== undefined;
      const trustedContext = typeof route?.trustedContext === 'function' ? await route.trustedContext(request, req) : route?.trustedContext;
      // A route that CONFIGURES a deriver but gets nothing usable back (a lookup that missed and returned undefined,
      // a non-object, a riskLevel that is not a level) has a broken deriver. Refuse it — never fall back to the
      // agent's word, which is exactly what the deriver was there to avoid.
      if (configured) assertTrustedContext(trustedContext, route);
      // What is passed on is only what is set, so a guard that predates an option is called exactly as it always was.
      const requireContext = route.requireContextSignature ?? requireContextSignature;
      const verifyOptions = {
        ...(typeof requireContext === 'boolean' ? { requireContextSignature: requireContext } : {}),
        ...(trustedContext !== undefined ? { trustedContext } : {}),
        ...(payloadDigest !== undefined ? { payloadDigest } : {}),
        ...(requireBinding ? { requirePayloadBinding: true } : {}),
        // A route whose upstream is paid by x402 marks its claims x402-bound (agentsafe-mcp-guard >= 0.14.0): the issuer then
        // has an independent observer confirm any settlement below the authorization, or a release after the claim.
        ...(route.x402 === true ? { x402: true } : {}),
        ...(route.allowedAgents !== undefined ? { allowedAgents: route.allowedAgents } : {}),
      };
      decision = Object.keys(verifyOptions).length ? await guard.verifyRequest(request, verifyOptions) : await guard.verifyRequest(request);
      trace.decision = decision;
    } catch (err) {
      // Fail CLOSED: a governance error blocks the upstream call.
      return { status: 502, body: { decision: 'block', reasonCode: 'GOVERNANCE_ERROR', error: String(err?.message ?? err) } };
    }

    // allow + observe both PERMIT the upstream call (observe = permit-but-flag, SAFR §11).
    if (decision?.decision !== 'allow' && decision?.decision !== 'observe') {
      // The issuer's sentence for a refused claim rides along (0.28.0, pre-beta rerun 6 FW6-1): the bare code was all the agent
      // saw of, say, AUTHORIZATION_CONTEXT_REQUIRED. Only the issuer's own `detail` — never a stack or an internal error.
      const detail = typeof decision?.detail === 'string' && decision.detail ? decision.detail : undefined;
      return { status: 403, body: { decision: decision?.decision ?? 'block', reasonCode: decision?.reasonCode ?? 'BLOCKED', ...(detail ? { detail } : {}) }, governance: decision };
    }

    // The authorization is the effect's natural idempotency key: one authorization is one execution. Hand it
    // to the upstream as `Idempotency-Key` so an upstream that dedupes on it makes the effect exactly-once
    // even if this gateway is ever asked to run the same call twice (a crash between execute and settle, an
    // operator replay). An `Idempotency-Key` the AGENT sent is NEVER forwarded, whatever its casing and whether or
    // not a hold was claimed: an upstream that de-dupes on it could otherwise be made to replay a cached response
    // (or skip a real execution) with a key the agent chose. It is replaced by the authorization id when a hold
    // was claimed, and simply removed when none was (there is nothing to key on).
    let forwardReq = { ...req, headers: withHeader(req.headers, 'idempotency-key', decision?.authorizationId) };
    // Trusted Execution Gateway hook (Module G): resolve an upstream credential the agent
    // never sees, and inject it into a CLONE of the outbound headers — never the original req.
    // FAIL CLOSED: once a vault is configured, a call it did not release a credential for is never
    // forwarded (it used to go upstream with no credential, which is only "safe" if every upstream
    // rejects an unauthenticated call — an assumption this package cannot check). A route that
    // genuinely needs no credential opts out with `route.credential: false`.
    if (typeof resolveCredential === 'function' && route.credential !== false) {
      let cred;
      let failure;
      try {
        cred = await resolveCredential({ request, route, decision });
      } catch (err) {
        failure = err;
      }
      if (failure || !cred || typeof cred.header !== 'string' || !cred.header || typeof cred.value !== 'string' || !cred.value) {
        console.warn(`[gateway] no credential released for "${route.method ?? '*'} ${route.path}" — refusing to forward:`, failure ? (failure?.message ?? failure) : 'the vault returned no credential');
        // Nothing was sent upstream, so nothing executed: release the hold this request claimed (the
        // budget returns), the same close-out closeHold applies to a status that guarantees non-execution.
        await releaseUnexecuted(decision, 'CREDENTIAL_UNAVAILABLE');
        return { status: 502, body: { decision: 'block', reasonCode: 'CREDENTIAL_UNAVAILABLE', action: route.action } };
      }
      forwardReq = { ...forwardReq, headers: { ...(forwardReq.headers ?? {}), [cred.header]: cred.value } };
    }

    let upstream;
    trace.forwarded = true;
    try {
      upstream = await forward(forwardReq);
    } catch (err) {
      // A throw does not prove the upstream did nothing (the request may have been sent and the
      // response lost) — park the hold as UNKNOWN rather than releasing it, then let the error
      // propagate exactly as it did before.
      await settleHold(decision, request, route, undefined);
      throw err;
    }
    const upstreamStatus = Number(upstream?.status);
    // The caller is answered now; the hold is closed after (settleHold).
    await settleHold(decision, request, route, Number.isFinite(upstreamStatus) ? upstreamStatus : undefined);
    return { ...upstream, governance: decision };
  }

  /** Re-send what the report spool holds now (also runs on a timer and at startup). Resolves how many were recorded. */
  handle.flushReports = () => flushSpool();
  /** How many hold close-outs (and outcome reports) are still running after their response went back. */
  handle.pendingSettlements = () => pendingSettlements.size;
  /**
   * Wait for background hold close-outs to finish, for at most `timeoutMs`; resolves with how many were still running
   * when it gave up (0 = all done). Call it on shutdown so a restart does not strand settlements already owed.
   */
  handle.drainSettlements = async (timeoutMs = 5000) => {
    // Close every open refusal window first, so the counts it holds are reported (or spooled) before shutdown.
    for (const key of [...refusalWindows.keys()]) closeWindow(key);
    const deadline = Date.now() + timeoutMs;
    while (pendingSettlements.size > 0 && Date.now() < deadline) {
      await Promise.race([Promise.allSettled([...pendingSettlements]), new Promise((r) => setTimeout(r, deadline - Date.now()))]);
    }
    return pendingSettlements.size;
  };
  return handle;
}

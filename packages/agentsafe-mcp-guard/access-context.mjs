// access-context.mjs — the access check on what a tool or an upstream returns to an agent (`access`).
//
// An agent acting for one tenant and one user must not be handed another's records, whatever it asked for: a query built
// from injected text, an upstream filter that is wrong, or a shared index can each return rows that belong to someone
// else. The operator names, per tool or route, where the tenant and the user appear in the answer, and how to learn
// which tenant and user the call is served for from something the operator trusts. The answer is then released only
// when every one of those fields names that tenant and that user.
//
// It fails closed: a field the operator named that is missing, a value that is not a string or number, or an answer
// that is not JSON is withheld as uncheckable, never released unchecked. ZKBC's access family states the same relation
// (identity match over the observed context fields); this is its plaintext pre-check.
//
// Used by guardIncomingTool's `access` option here, by agentsafe-http-gateway's `route.access`, and by the OpenShell
// adapter's response stage. Zero dependencies. The two packages ship identical copies (the gateway imports nothing from
// the guard at runtime); agentsafe-http-gateway/access-context.smoke.mjs fails if they differ.

const KEYS = new Set(['tenant', 'user', 'principal']);
const MAX_NODES = 100_000;

/**
 * An RFC 6901 JSON Pointer as its segments, `*` matching any key or index; null when it is not one. The root ("") is not
 * a field and is refused.
 */
export function parseAccessPointer(pointer) {
  if (typeof pointer !== 'string' || !pointer.startsWith('/') || /~[^01]|~$/.test(pointer)) return null;
  return pointer.slice(1).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
}

const escape = (seg) => String(seg).replace(/~/g, '~0').replace(/\//g, '~1');

/**
 * The values at a pointer in `body`: { values: [{ path, value }] }, { missing: path } for the first place the pointer
 * cannot be followed, or { tooLarge: true } past MAX_NODES. A `*` over an empty array or object matches nothing, so a
 * response with no records passes; a named key absent from any record it should be on is missing.
 *
 * The paths returned are shown to the agent, so they are built from the configured pointer, never from the answer: a `*`
 * that matched an object key stays `*` (the key may be another tenant's name), and only an array index is filled in.
 */
export function valuesAt(body, segments) {
  let nodes = [{ node: body, path: '' }];
  let visited = 0;
  for (const seg of segments) {
    const next = [];
    for (const { node, path } of nodes) {
      if (node === null || typeof node !== 'object') return { missing: path || '/' };
      if (seg === '*') {
        if (Array.isArray(node)) node.forEach((v, i) => next.push({ node: v, path: `${path}/${i}` }));
        else for (const v of Object.values(node)) next.push({ node: v, path: `${path}/*` });
      } else if (Array.isArray(node) ? /^(0|[1-9]\d*)$/.test(seg) && Number(seg) < node.length : Object.prototype.hasOwnProperty.call(node, seg)) {
        next.push({ node: node[seg], path: `${path}/${escape(seg)}` });
      } else {
        return { missing: `${path}/${escape(seg)}` };
      }
      visited += 1;
      if (visited + next.length > MAX_NODES) return { tooLarge: true };
    }
    nodes = next;
  }
  return { values: nodes.map(({ node, path }) => ({ path, value: node })) };
}

/**
 * An `access` policy (a route's or a tool's), checked at startup: throws on anything that could not be enforced as
 * written. `holder` carries it as `holder.access`; `where` names the holder in the error (a route by method and path).
 */
export function assertAccessPolicy(holder, where = `route "${holder?.method ?? '*'} ${holder?.path}"`) {
  const access = holder?.access;
  if (access === undefined) return;
  if (access === null || typeof access !== 'object' || Array.isArray(access)) throw new Error(`access for ${where} must be an object`);
  for (const k of Object.keys(access)) if (!KEYS.has(k)) throw new Error(`access for ${where} has an unknown key "${k}" (tenant, user, principal)`);
  for (const kind of ['tenant', 'user']) {
    const list = access[kind];
    if (list === undefined) continue;
    if (!Array.isArray(list) || list.length === 0) throw new Error(`access.${kind} for ${where} must be a non-empty array of JSON Pointers`);
    for (const p of list) if (!parseAccessPointer(p)) throw new Error(`access.${kind} for ${where} has an invalid JSON Pointer ${JSON.stringify(p)}`);
  }
  if (access.tenant === undefined && access.user === undefined) throw new Error(`access for ${where} names no tenant or user field`);
  const p = access.principal;
  if (typeof p !== 'function' && (p === null || typeof p !== 'object' || Array.isArray(p))) {
    throw new Error(`access.principal for ${where} must be a function returning { tenantId, userId }, or a fixed { tenantId, userId }`);
  }
  if (typeof p !== 'function') {
    if (access.tenant && !idOk(p.tenantId)) throw new Error(`access.principal for ${where} names no tenantId`);
    if (access.user && !idOk(p.userId)) throw new Error(`access.principal for ${where} names no userId`);
  }
}

const canonicalId = (v) => String(v).normalize('NFC');
const idOk = (v) => (typeof v === 'string' && v.trim() !== '') || (typeof v === 'number' && Number.isFinite(v));

/**
 * The principal a call is served for, from the holder's resolver (called with `args`: a route's `(request, req)`, a
 * tool's `(signed, ...rest)`), checked: an id for each kind the policy compares. Throws when the resolver throws or gives
 * nothing usable, so the call is refused before anything runs.
 */
export async function resolveAccessPrincipal(holder, ...args) {
  const { access } = holder;
  const p = typeof access.principal === 'function' ? await access.principal(...args) : access.principal;
  if (p === null || typeof p !== 'object') throw new Error('the access principal resolver returned no principal');
  if (access.tenant && !idOk(p.tenantId)) throw new Error('the access principal resolver returned no tenantId');
  if (access.user && !idOk(p.userId)) throw new Error('the access principal resolver returned no userId');
  return { tenantId: p.tenantId, userId: p.userId };
}

/** The reason codes an access check can give; a withheld answer is reported under one of these. */
export const ACCESS_REASON_CODES = Object.freeze(['ACCESS_PRINCIPAL_UNAVAILABLE', 'ACCESS_CONTEXT_MISMATCH', 'ACCESS_CONTEXT_UNCHECKABLE']);

/**
 * Whether a response body may be released to a request served for `principal`. Null when every named field matches;
 * otherwise { reasonCode, path, kind? }:
 *   ACCESS_CONTEXT_MISMATCH     a tenant or user field names someone else
 *   ACCESS_CONTEXT_UNCHECKABLE  a named field is missing or not a string/number
 * Values are compared as text after NFC, so 42 and "42" match, and a decomposed and composed é match.
 */
export function checkAccessContext(body, access, principal) {
  for (const kind of ['tenant', 'user']) {
    const expected = canonicalId(kind === 'tenant' ? principal.tenantId : principal.userId);
    for (const pointer of access[kind] ?? []) {
      const found = valuesAt(body, parseAccessPointer(pointer));
      if (found.tooLarge) return { reasonCode: 'ACCESS_CONTEXT_UNCHECKABLE', path: pointer, kind, detail: `more than ${MAX_NODES} fields to check` };
      if (found.missing !== undefined) return { reasonCode: 'ACCESS_CONTEXT_UNCHECKABLE', path: found.missing, kind };
      for (const { path, value } of found.values) {
        if (!(typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value)))) return { reasonCode: 'ACCESS_CONTEXT_UNCHECKABLE', path, kind };
        if (canonicalId(value) !== expected) return { reasonCode: 'ACCESS_CONTEXT_MISMATCH', path, kind };
      }
    }
  }
  return null;
}

/**
 * `checkAccessContext` over what a tool handler returned: a JavaScript value. It is checked as a JSON snapshot (its
 * `toJSON`, no functions or undefined), and the snapshot is what the caller returns, so a getter or a later change
 * cannot show the check one thing and the agent another. Returns { refusal, value }: `refusal` null to release
 * `value`. `undefined` and `null` carry no records and are released as they are. A value JSON cannot carry (a BigInt,
 * a cycle) cannot be checked and is refused.
 */
export function checkAccessValue(value, access, principal) {
  if (value === undefined || value === null) return { refusal: null, value };
  let snapshot;
  try {
    const text = JSON.stringify(value);
    if (text === undefined) return { refusal: null, value: undefined };
    snapshot = JSON.parse(text);
  } catch {
    return { refusal: { reasonCode: 'ACCESS_CONTEXT_UNCHECKABLE', path: '', detail: 'the answer cannot be written as JSON' } };
  }
  return { refusal: checkAccessContext(snapshot, access, principal), value: snapshot };
}

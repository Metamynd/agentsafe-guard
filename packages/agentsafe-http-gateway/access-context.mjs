// access-context.mjs — the access check on what an upstream returns to an agent (route.access).
//
// An agent acting for one tenant and one user must not be handed another's records, whatever it asked for: a query built
// from injected text, an upstream filter that is wrong, or a shared index can each return rows that belong to someone
// else. The operator names, per route, where the tenant and the user appear in the upstream's JSON response, and how
// to learn which tenant and user the request is served for from something the operator trusts. The gateway then
// releases a response only when every one of those fields names that tenant and that user.
//
// It fails closed: a field the operator named that is missing, a value that is not a string or number, or a response
// that is not JSON is withheld as uncheckable, never released unchecked. ZKBC's access family states the same relation
// (identity match over the observed context fields); this is its plaintext pre-check.
//
// Zero dependencies.

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

/** A route's `access`, checked at startup: throws on anything the gateway could not enforce as written. */
export function assertAccessPolicy(route) {
  const access = route?.access;
  if (access === undefined) return;
  const where = `route "${route.method ?? '*'} ${route.path}"`;
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
    throw new Error(`access.principal for ${where} must be a function (request, req) => { tenantId, userId }, or a fixed { tenantId, userId }`);
  }
  if (typeof p !== 'function') {
    if (access.tenant && !idOk(p.tenantId)) throw new Error(`access.principal for ${where} names no tenantId`);
    if (access.user && !idOk(p.userId)) throw new Error(`access.principal for ${where} names no userId`);
  }
}

const canonicalId = (v) => String(v).normalize('NFC');
const idOk = (v) => (typeof v === 'string' && v.trim() !== '') || (typeof v === 'number' && Number.isFinite(v));

/**
 * The principal a request is served for, from the route's resolver, checked: an id for each kind the route compares.
 * Throws when the resolver throws or gives nothing usable, so the request is refused before it is forwarded.
 */
export async function resolveAccessPrincipal(route, request, req) {
  const p = typeof route.access.principal === 'function' ? await route.access.principal(request, req) : route.access.principal;
  if (p === null || typeof p !== 'object') throw new Error('the access principal resolver returned no principal');
  if (route.access.tenant && !idOk(p.tenantId)) throw new Error('the access principal resolver returned no tenantId');
  if (route.access.user && !idOk(p.userId)) throw new Error('the access principal resolver returned no userId');
  return { tenantId: p.tenantId, userId: p.userId };
}

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

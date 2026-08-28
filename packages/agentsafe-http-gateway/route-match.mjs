// route-match.mjs — pure protected-route matching for the generic HTTP interception gateway
// (SAFR §17, Phase-5 PR-4). No IO, so the matching rules are deterministic + unit-testable.
//
// A protected route is { method, path, action, ... }. `method` is case-insensitive ('*' = any).
// `path` is a pattern where a `*` matches EXACTLY ONE segment and a trailing `**` matches the rest
// (one-or-more segments) — enough to express "/book/*", "/api/**", "/quote". An exact path with no
// wildcard matches only itself.

/** Split a URL path into non-empty segments (ignoring query + trailing slash). */
export function segments(path) {
  const p = String(path || '').split('?')[0];
  return p.split('/').filter(Boolean);
}

/**
 * Whether `path` matches `pattern`. `*` matches exactly one segment; a trailing `**` matches
 * one-or-more remaining segments. Otherwise segments must match 1:1 (and the lengths must be equal).
 */
export function pathMatches(pattern, path) {
  const pat = segments(pattern);
  const seg = segments(path);
  for (let i = 0; i < pat.length; i++) {
    const token = pat[i];
    if (token === '**') return seg.length >= pat.length; // tail wildcard: absorb the rest (≥1 segment)
    if (seg[i] === undefined) return false;
    if (token === '*') continue; // single-segment wildcard
    if (token !== seg[i]) return false;
  }
  return seg.length === pat.length; // exact length unless a tail wildcard consumed the remainder
}

/** Whether a route's method matches the request method ('*' or absent = any). */
export function methodMatches(routeMethod, reqMethod) {
  if (!routeMethod || routeMethod === '*') return true;
  return String(routeMethod).toUpperCase() === String(reqMethod || '').toUpperCase();
}

/**
 * The first protected route matching (method, path), or null. Order matters — put more specific
 * routes first. A matched route tells the gateway to GOVERN the request; no match ⇒ pass through.
 */
export function matchRoute(routes, method, path) {
  for (const r of routes || []) {
    if (methodMatches(r.method, method) && pathMatches(r.path, path)) return r;
  }
  return null;
}

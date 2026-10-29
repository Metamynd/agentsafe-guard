/**
 * Per-tool argument policy: which argument paths a tool call may carry, and which values must not leave in the clear.
 *
 * The rules above judge the SIGNED fields (amount, currency, merchant, resource…) and the context. The arguments a tool
 * actually executes with are a separate surface: a call within its cap can still carry a stray field the rules never see
 * (a `bcc`, a `webhookUrl`, a renamed amount). A permission's `arguments` closes that surface for the tool it covers:
 *
 *   - `allow` lists the JSON Pointer (RFC 6901) paths the arguments may contain. Every value in the arguments must sit at
 *     or below a listed path, or the call is refused (`ARGUMENT_NOT_ALLOWED`). A `*` segment matches any one key or array
 *     index. Membership fails closed: a renamed, re-cased or unlisted key is refused, never passed through.
 *   - `sensitive` lists paths whose values are rewritten before the call leaves the guard: `redact` replaces the value,
 *     `hmac` replaces it with a keyed hash (the guard's key), so the tool can still match equal values without reading them.
 *
 * It lives in policy-core so every guard enforces it identically, and in the signed mandate so the OWNER sets it, not the
 * operator of a guard. Pure: no IO, no crypto (the keyed hash is injected), no clock.
 */

import type { Mandate } from './mandate.types.js';

export interface SensitiveArgument {
  /** JSON Pointer to the value; `*` matches any one key or index. */
  path: string;
  /** `redact` (the value is replaced) is stronger than `hmac` (a keyed hash: equal values stay linkable). */
  mode: 'redact' | 'hmac';
}

export interface ArgumentPolicy {
  /** JSON Pointer paths the arguments may contain (a path permits everything below it). Never empty, never the root. */
  allow: string[];
  sensitive?: SensitiveArgument[];
}

export type ArgumentCheck =
  | { ok: true }
  | { ok: false; reasonCode: 'ARGUMENT_NOT_ALLOWED' | 'ARGUMENTS_UNCHECKABLE'; path?: string; detail?: string };

export type ArgumentSanitization =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; reasonCode: 'SENSITIVE_ARGUMENT_UNPROTECTED' | 'ARGUMENTS_UNCHECKABLE'; path?: string; detail?: string };

/** What a redacted value is replaced with. */
export const REDACTED_ARGUMENT = '[REDACTED]';
/** Prefix of a keyed-hash replacement: `hmac-sha256:<64 lowercase hex>`. */
export const HMAC_ARGUMENT_PREFIX = 'hmac-sha256:';

const MAX_DEPTH = 32;
const MAX_NODES = 10_000;
const MAX_PATHS = 256;

/** RFC 6901 pointer → segments. The root (`''`) and malformed escapes are refused (null). */
export function parseArgumentPointer(pointer: unknown): string[] | null {
  if (typeof pointer !== 'string' || !pointer.startsWith('/')) return null;
  const out: string[] = [];
  for (const raw of pointer.slice(1).split('/')) {
    if (/~[^01]|~$/.test(raw)) return null;
    out.push(raw.replace(/~1/g, '/').replace(/~0/g, '~'));
  }
  return out;
}

function toPointer(segments: string[]): string {
  return segments.map((s) => '/' + s.replace(/~/g, '~0').replace(/\//g, '~1')).join('');
}

/** Why a policy is unusable, or null when it is well formed. An unusable policy refuses the call; it never means "no policy". */
export function argumentPolicyProblem(policy: unknown): string | null {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return 'arguments must be an object';
  const { allow, sensitive } = policy as { allow?: unknown; sensitive?: unknown };
  if (!Array.isArray(allow) || allow.length === 0) return 'arguments.allow must list at least one path';
  if (allow.length > MAX_PATHS) return `arguments.allow lists more than ${MAX_PATHS} paths`;
  for (const p of allow) if (!parseArgumentPointer(p)) return `arguments.allow: ${JSON.stringify(p)} is not a JSON Pointer below the root`;
  if (sensitive !== undefined) {
    if (!Array.isArray(sensitive)) return 'arguments.sensitive must be a list';
    if (sensitive.length > MAX_PATHS) return `arguments.sensitive lists more than ${MAX_PATHS} paths`;
    for (const s of sensitive) {
      if (!s || typeof s !== 'object') return 'arguments.sensitive entries must be objects';
      const { path, mode } = s as { path?: unknown; mode?: unknown };
      if (!parseArgumentPointer(path)) return `arguments.sensitive: ${JSON.stringify(path)} is not a JSON Pointer below the root`;
      if (mode !== 'redact' && mode !== 'hmac') return `arguments.sensitive: mode must be "redact" or "hmac"`;
    }
  }
  return null;
}

/**
 * Every argument policy the mandate sets for this action. More than one permission may cover an action; the call must
 * satisfy each policy and is sanitized under all of them (most restrictive wins). Empty = this action has none.
 */
export function argumentPoliciesFor(mandate: Mandate | null | undefined, action: string): unknown[] {
  return (mandate?.permission ?? [])
    .filter((p) => (p.target ?? mandate?.target) === action && (p as { arguments?: unknown }).arguments !== undefined)
    .map((p) => (p as { arguments?: unknown }).arguments);
}

/** Does `pattern` (segments, `*` = any one) cover `path` — equal to it, or an ancestor of it? */
function covers(pattern: string[], path: string[]): boolean {
  if (pattern.length > path.length) return false;
  return pattern.every((seg, i) => seg === '*' || seg === path[i]);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

type Leaves = { ok: true; leaves: string[][] } | { ok: false; path: string; detail: string };

/**
 * Every value's path in a JSON-shaped object: primitives, and empty objects/arrays (which carry a key but no value).
 * Anything JSON cannot carry — a class instance, a function, undefined, a non-finite number — is refused, since a field
 * hidden inside it cannot be checked.
 */
function leavesOf(root: Record<string, unknown>): Leaves {
  const leaves: string[][] = [];
  let nodes = 0;
  const walk = (value: unknown, path: string[]): string | null => {
    if (++nodes > MAX_NODES) return `more than ${MAX_NODES} values`;
    if (path.length > MAX_DEPTH) return `nested deeper than ${MAX_DEPTH}`;
    if (value === null || typeof value === 'string' || typeof value === 'boolean') { leaves.push(path); return null; }
    if (typeof value === 'number') { if (!Number.isFinite(value)) return 'a non-finite number'; leaves.push(path); return null; }
    if (Array.isArray(value)) {
      if (value.length === 0 && path.length > 0) { leaves.push(path); return null; }
      for (let i = 0; i < value.length; i++) { const e = walk(value[i], [...path, String(i)]); if (e) return e; }
      return null;
    }
    if (isPlainObject(value)) {
      const keys = Object.keys(value);
      if (keys.length === 0 && path.length > 0) { leaves.push(path); return null; }
      for (const k of keys) { const e = walk(value[k], [...path, k]); if (e) return e; }
      return null;
    }
    return `a value JSON cannot carry (${typeof value})`;
  };
  if (!isPlainObject(root)) return { ok: false, path: '', detail: 'the arguments are not a single JSON object' };
  const err = walk(root, []);
  return err ? { ok: false, path: '', detail: err } : { ok: true, leaves };
}

/** Refuse arguments that carry any value outside the allowed paths of every policy. */
export function checkArguments(policies: unknown[], args: unknown): ArgumentCheck {
  if (policies.length === 0) return { ok: true };
  for (const p of policies) {
    const problem = argumentPolicyProblem(p);
    if (problem) return { ok: false, reasonCode: 'ARGUMENTS_UNCHECKABLE', detail: problem };
  }
  const found = leavesOf(args as Record<string, unknown>);
  if (!found.ok) return { ok: false, reasonCode: 'ARGUMENTS_UNCHECKABLE', detail: found.detail };
  for (const p of policies as ArgumentPolicy[]) {
    const allowed = p.allow.map((a) => parseArgumentPointer(a) as string[]);
    for (const leaf of found.leaves) {
      if (!allowed.some((a) => covers(a, leaf))) return { ok: false, reasonCode: 'ARGUMENT_NOT_ALLOWED', path: toPointer(leaf) };
    }
  }
  return { ok: true };
}

/** Canonical JSON (sorted keys) of a JSON value: what a keyed hash is taken over, so equal values hash equally. */
function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

/**
 * The arguments with every sensitive value rewritten, under all policies: `redact` wins over `hmac` at the same value.
 * Run after `checkArguments`. `hmac` is the guard's keyed hash over the value's canonical JSON, returning lowercase hex;
 * a policy that asks for one from a guard that has no key is refused (`SENSITIVE_ARGUMENT_UNPROTECTED`) — sending the value
 * in the clear is exactly what the owner said must not happen. A sensitive path the arguments do not carry is skipped.
 */
export function sanitizeArguments(
  policies: unknown[],
  args: Record<string, unknown>,
  { hmac }: { hmac?: (canonical: string) => string } = {},
): ArgumentSanitization {
  for (const p of policies) {
    const problem = argumentPolicyProblem(p);
    if (problem) return { ok: false, reasonCode: 'ARGUMENTS_UNCHECKABLE', detail: problem };
  }
  // Strongest mode per concrete path, collected first so the order policies list them in cannot matter.
  const modes = new Map<string, { segments: string[]; mode: 'redact' | 'hmac' }>();
  const visit = (value: unknown, pattern: string[], at: string[], mode: 'redact' | 'hmac') => {
    if (pattern.length === 0) {
      const key = toPointer(at);
      const prev = modes.get(key);
      if (!prev || (prev.mode === 'hmac' && mode === 'redact')) modes.set(key, { segments: at, mode });
      return;
    }
    if (value === null || typeof value !== 'object') return;
    const [head, ...rest] = pattern;
    // An array's members are its indices only: `length` is an own property of every array, and naming it (`/items/length`)
    // must match nothing, not try to overwrite the array's length.
    const keys =
      head === '*'
        ? Object.keys(value as object)
        : Array.isArray(value)
          ? /^(0|[1-9]\d*)$/.test(head) && Number(head) < value.length ? [head] : []
          : Object.prototype.hasOwnProperty.call(value, head) ? [head] : [];
    for (const k of keys) visit((value as Record<string, unknown>)[k], rest, [...at, k], mode);
  };
  for (const p of policies as ArgumentPolicy[]) {
    for (const s of p.sensitive ?? []) visit(args, parseArgumentPointer(s.path) as string[], [], s.mode);
  }
  if (modes.size === 0) return { ok: true, value: args };
  const out = clone(args);
  // Deepest first, so a redacted ancestor never hides a descendant it would otherwise have replaced first.
  for (const { segments, mode } of [...modes.values()].sort((a, b) => b.segments.length - a.segments.length)) {
    const parent = segments.slice(0, -1).reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], out) as Record<string, unknown> | undefined;
    const last = segments[segments.length - 1];
    if (!parent || typeof parent !== 'object' || !Object.prototype.hasOwnProperty.call(parent, last)) continue;
    if (mode === 'redact') {
      parent[last] = REDACTED_ARGUMENT;
      continue;
    }
    if (typeof hmac !== 'function') return { ok: false, reasonCode: 'SENSITIVE_ARGUMENT_UNPROTECTED', path: toPointer(segments), detail: 'the policy asks for a keyed hash and this guard has no key' };
    const digest = hmac(canonicalJson(parent[last]));
    if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
      return { ok: false, reasonCode: 'SENSITIVE_ARGUMENT_UNPROTECTED', path: toPointer(segments), detail: 'the keyed hash did not return 64 lowercase hex characters' };
    }
    parent[last] = HMAC_ARGUMENT_PREFIX + digest;
  }
  return { ok: true, value: out };
}

/**
 * Does a delegated child's argument policy narrow its parent's? Each child `allow` path must sit at or below a parent
 * path (a parent `*` covers anything; a child `*` only a parent `*`), and every parent sensitive path must appear in the
 * child with the same or a stronger mode. A parent with no policy places no restriction; a child may add one.
 * Returns null when it narrows, else the reason.
 */
export function argumentPolicyNarrowing(parent: unknown, child: unknown): { refusal: 'CONSTRAINT_DROPPED' | 'CONSTRAINT_WIDENED' | 'UNCOMPARABLE'; detail: string } | null {
  if (child !== undefined && argumentPolicyProblem(child)) return { refusal: 'UNCOMPARABLE', detail: 'arguments' };
  if (parent === undefined) return null;
  if (argumentPolicyProblem(parent)) return { refusal: 'UNCOMPARABLE', detail: 'arguments' };
  if (child === undefined) return { refusal: 'CONSTRAINT_DROPPED', detail: 'arguments' };
  const p = parent as ArgumentPolicy;
  const c = child as ArgumentPolicy;
  const patternCovers = (outer: string[], inner: string[]) =>
    outer.length <= inner.length && outer.every((seg, i) => seg === '*' || seg === inner[i]);
  const parentAllow = p.allow.map((a) => parseArgumentPointer(a) as string[]);
  for (const a of c.allow) {
    if (!parentAllow.some((pa) => patternCovers(pa, parseArgumentPointer(a) as string[]))) return { refusal: 'CONSTRAINT_WIDENED', detail: `arguments.allow ${a}` };
  }
  for (const ps of p.sensitive ?? []) {
    const match = (c.sensitive ?? []).find((cs) => cs.path === ps.path && (cs.mode === ps.mode || cs.mode === 'redact'));
    if (!match) return { refusal: 'CONSTRAINT_DROPPED', detail: `arguments.sensitive ${ps.path}` };
  }
  return null;
}

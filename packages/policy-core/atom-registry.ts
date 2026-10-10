import type { EvaluationContext } from './types.js';
import { normalizeRiskLevel } from './provenance.js';
import { expandJurisdictionGroups } from './jurisdiction-groups.js';

/**
 * Atom library — the code-defined predicates that DB policies compose by id.
 * Keeping implementations in code (vs storing executable rules) is the safe,
 * Sovereign-forward shape: tenants configure WHICH atoms apply, not arbitrary code.
 *
 * Every predicate is a PURE boolean check over (context, config): no clock, no
 * IO, no randomness. This is what makes a verdict reproducible and independently
 * verifiable at the edge (spec §6.3).
 */

const RISK_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Whether a `currency` config on `amount-over`/`cumulative-over` rules THIS request out of
 * the cap's scope — i.e. the numeric comparison below must not be trusted to decide.
 *
 * Unconfigured (`cfgCurrency` undefined/null, or an empty list) is unchanged, currency-blind
 * behavior — the atom's historical default, kept so every SOP authored before this field
 * existed keeps working exactly as it did (see atom-catalog.ts). Once an author DOES scope a
 * cap to specific currencies, this mirrors mandate-eval.ts's constraintSatisfied() unit
 * check, but for the PROHIBITION side of that logic: `amount-over`/`cumulative-over` FIRE to
 * BLOCK/ESCALATE, the same role a mandate prohibition plays, so a currency that doesn't
 * match — or can't be read at all — must resolve toward firing, not toward silently letting
 * the numeric comparison decide. Otherwise an SOP cap authored as "block over 200" is cleared
 * by naming a cheaper-looking currency (e.g. 200 JPY vs 200 USD) — the exact bypass class
 * mandate-eval.ts's currency check was written to close on the ODRL mandate layer. Compared
 * case-insensitively, same as mandate-eval.ts.
 */
export function currencyOutOfScope(ctx: EvaluationContext, cfgCurrency: unknown): boolean {
  if (cfgCurrency === undefined || cfgCurrency === null) return false;
  const allowed = (Array.isArray(cfgCurrency) ? cfgCurrency : [cfgCurrency]) as unknown[];
  if (allowed.length === 0) return false;
  const currency = ctx.currency;
  const matches =
    typeof currency === 'string' && allowed.some((u) => typeof u === 'string' && u.toUpperCase() === currency.toUpperCase());
  return !matches;
}

export const ATOM_REGISTRY: Record<string, (ctx: EvaluationContext, config?: any) => boolean> = {
  'data-source-not-approved': (c, cfg) =>
    !!c.dataSourceId && !(((cfg?.approved as string[]) ?? []).includes(String(c.dataSourceId))),
  'consent-missing': (c) => c.consent === false,
  'risk-at-or-above': (c, cfg) => {
    // Read tolerantly ("HIGH " is high). A value that is still not a risk level fires nothing HERE — the
    // atom is a pure predicate — but the molecule that holds it does not pass silently: risk-at-or-above
    // is in ATOM_DEFAULT_REQUIRED_CONTEXT, so a missing or unrecognised riskLevel ESCALATES at the rule
    // layer (standards-rules.ts) rather than reading as "not risky".
    const haveLevel = normalizeRiskLevel(c.riskLevel);
    const have = haveLevel === null ? undefined : RISK_RANK[haveLevel];
    const need = RISK_RANK[String(cfg?.level ?? 'high')];
    return have !== undefined && need !== undefined && have >= need;
  },
  'amount-over': (c, cfg) => {
    if (typeof c.amount !== 'number') return false;
    if (currencyOutOfScope(c, cfg?.currency)) return true; // unverifiable/mismatched -> fail closed, fire
    return c.amount > Number(cfg?.limit ?? 0);
  },
  // Deny-by-default primitive for value-moving actions. Fires on ABSENCE (like the
  // evidence atoms below, and unlike `amount-over`) OR on a NEGATIVE amount: true when
  // the context carries no usable amount, or one that cannot be trusted for capping —
  // the gate cannot tell how much value the call would move, so a spend cap authored
  // next to it would silently never fire. `amount-over` only ever fires on `> limit`,
  // so a negative amount clears every positive cap by construction, and on a system
  // that tracks committed spend ADDITIVELY (reserved += amount), a negative claim can
  // net-reduce what's already committed rather than add to it — the same "cap never
  // fires" failure as a missing amount, reached from the other side of zero. Zero
  // itself is NOT covered here: a genuine $0 action (a read, a no-op) is a valid,
  // known amount, not an unknown one. Author this with BLOCK as the FIRST rule of a
  // spend policy; the cap that follows then only ever judges a known, non-negative
  // number. Opt-in: only a rule that keys it runs it, so actions that carry no amount
  // by nature are unaffected. The public authorize endpoint's own schema already
  // rejects a negative amount before it reaches this atom (defense in depth, not the
  // only layer) — this is what closes the same gap for paths that schema doesn't
  // cover: the local/harness evaluator and the platform's own MCP tool policies.
  'amount-unknown': (c) => !(typeof c.amount === 'number' && Number.isFinite(c.amount) && c.amount >= 0),
  // Total budget: cumulativeSpend is a SERVER-derived, signed-last context field (never
  // shadowable by the agent's itinerary), so this compares already-spent + this amount.
  // See `currencyOutOfScope` above: a configured currency scope that this request's
  // currency doesn't match fires the cap outright, same fail-closed reasoning as `amount-over`.
  'cumulative-over': (c, cfg) => {
    if (currencyOutOfScope(c, cfg?.currency)) return true;
    return (Number(c.cumulativeSpend ?? 0) + Number(c.amount ?? 0)) > Number(cfg?.limit ?? 0);
  },
  // Fires if any configured term appears in the prompt and/or output text.
  // Used to govern agent responses on content (prohibited claims, sensitive advice).
  'text-matches': (c, cfg) => {
    const hay = `${c.prompt ?? ''}\n${c.output ?? ''}`.toLowerCase();
    const terms = ((cfg?.terms as string[]) ?? []).map((t) => String(t).toLowerCase());
    return terms.some((t) => t.length > 0 && hay.includes(t));
  },
  // --- Compliance atoms. Allow-list atoms fire when the context field is PRESENT
  //     and NOT allowed (consistent with data-source-not-approved: a missing field
  //     does not fire — the atom's requiredContext documents what to supply). ---
  // A group code in the list ("EU") stands for its members, as on the mandate (jurisdiction-groups.ts).
  'jurisdiction-not-allowed': (c, cfg) =>
    notInAllowList(c.jurisdiction, Array.isArray(cfg?.allowed) ? expandJurisdictionGroups(cfg.allowed) : cfg?.allowed),
  'data-residency-violation': (c, cfg) => notInAllowList(c.dataResidency, cfg?.allowedRegions),
  'model-not-allowed': (c, cfg) => notInAllowList(c.model, cfg?.allowed),
  'tool-not-allowed': (c, cfg) => notInAllowList(c.tool, cfg?.allowed),
  'pii-present': (c) => c.piiPresent === true,
  'rate-limit-exceeded': (c, cfg) => typeof c.callCount === 'number' && c.callCount > Number(cfg?.max ?? 0),
  // --- Evidence-quality atoms (SAFR §24). Unlike the allow-list atoms, these fire on ABSENCE:
  //     a REQUIRE semantic — "the action must be backed by this evidence; if it isn't, fire"
  //     (author with escalate/block). Opt-in: they only run when a rule keys them. ---
  // Fires when any REQUIRED evidence type is not among the attested `evidenceTypes` (missing
  // evidence — including none supplied at all → all required missing → fires).
  'evidence-requirement': (c, cfg) => {
    const required = ((cfg?.required as string[]) ?? []).map((t) => String(t).toLowerCase().trim()).filter(Boolean);
    if (required.length === 0) return false; // nothing required → nothing to enforce
    const have = new Set((Array.isArray(c.evidenceTypes) ? c.evidenceTypes : []).map((t) => String(t).toLowerCase().trim()));
    return required.some((r) => !have.has(r));
  },
  // Fires when a required minimum confidence (min > 0) is not met — the attested confidence is
  // below it, or absent (a required confidence that was never supplied fails the bar). A min of
  // 0 / unset is no requirement and never fires.
  'evidence-confidence-below': (c, cfg) => {
    const min = Number(cfg?.min ?? 0);
    if (!(min > 0)) return false;
    return typeof c.evidenceConfidence !== 'number' || c.evidenceConfidence < min;
  },
  // Trust guidance (MetaMynd Trust Index / HCS-28). Fires when the counterparty's trust score is
  // below a soft REVIEW line — intended to author an ESCALATE (route to a human), NOT a hard block.
  // The score is server-derived (signed-last) so the agent's itinerary can't fake it; when no score
  // is present (e.g. no counterparty resolved) the atom simply does not fire — no guidance.
  'hol-trust-below-review': (c, cfg) =>
    typeof c.holTrustScore === 'number' && c.holTrustScore < Number(cfg?.reviewBelow ?? 60),
  // --- Owner-keyed context atoms (pre-beta rerun 6, NF-RISK-SELF). For a non-financial action the only risk input
  //     used to be the riskLevel the agent declares about itself: {riskLevel:'low', op:'delete-all'} ran unreviewed.
  //     These let the owner key a rule on WHAT is being done — a field of the context the executor acts on — so the
  //     agent's label no longer decides. See contextValueMatch below for the matching and fail-closed rules. ---
  // Deny-list: fires when the field's value IS one of the owner's values ("deleting needs approval").
  'context-value-in': (c, cfg) => contextValueMatch(c, cfg, 'in') !== null,
  // Allow-list: fires when the field's value is NOT one of them ("anything but read/list needs approval"). The sound
  // choice when the set of safe operations is known: a spelling the owner did not foresee fires instead of passing.
  'context-value-not-in': (c, cfg) => contextValueMatch(c, cfg, 'not-in') !== null,
};

// ─── owner-keyed context values (NF-RISK-SELF) ──────────────────────────────────────────────────────────

/** Why a context-value atom fired: the value is listed / not listed, or the field could not be judged. */
export interface ContextValueMatch {
  field: string;
  /** The value that decided it, as the agent sent it (trimmed, at most 80 characters). Absent for `missing`. */
  value?: string;
  reason: 'listed' | 'unlisted' | 'missing' | 'malformed';
}

/**
 * Common look-alikes of Latin letters from Cyrillic and Greek. NFKC folds width and compatibility forms
 * ("ｄｅｌｅｔｅ" -> "delete") but NOT a Cyrillic "е" in "dеlete": that is a different letter, not a variant. A
 * deny-list that an agent can dodge with one look-alike letter is not a control, so both sides are folded through
 * this table before comparing. It is deliberately small (the letters that are visually identical in common fonts),
 * not the full Unicode confusables skeleton — which is why the allow-list atom (`context-value-not-in`) is the
 * recommended form when the safe values are known: there an unforeseen spelling fires instead of passing.
 */
const LOOKALIKE_FOLD: Readonly<Record<string, string>> = {
  // Cyrillic (lower case; upper case is lower-cased before folding)
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't',
  'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ԁ': 'd', 'ӏ': 'l', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u',
  'χ': 'x', 'ϲ': 'c',
};
const LOOKALIKE_RE = new RegExp(`[${Object.keys(LOOKALIKE_FOLD).join('')}]`, 'g');
/** Invisible / format characters (soft hyphen, zero-width, bidi controls, variation selectors, BOM). */
const INVISIBLE_RE = /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]/g;

/**
 * The comparison form of a value: Unicode NFKC, invisible characters removed, lower case, Cyrillic/Greek look-alikes
 * folded to Latin, and whitespace, hyphens and underscores removed — so "Delete-All", " delete_all ", "DELETE ALL",
 * "ｄｅｌｅｔｅ－ａｌｌ" and "dеlete-all" (Cyrillic е) all compare equal to "deleteall". Pure and locale-free (never
 * toLocaleLowerCase), so the gate and every guard bundle compute the same string.
 */
export function normalizeContextToken(s: string): string {
  return s
    .normalize('NFKC')
    .replace(INVISIBLE_RE, '')
    .toLowerCase()
    .normalize('NFKC')
    .replace(LOOKALIKE_RE, (ch) => LOOKALIKE_FOLD[ch] ?? ch)
    .replace(/[\s\-_‐-―−]+/g, '');
}

/**
 * The value at a dot path in the context (`op`, `params.op`), read through OWN properties only — a path segment named
 * `__proto__` or `constructor` reads nothing rather than something inherited. A key that itself contains a dot is not
 * addressable: the path is always split, so an agent cannot send `{"params.op": "read", params: {op: "delete-all"}}`
 * and choose which of the two the rule reads.
 */
export function contextValueAt(ctx: Record<string, unknown> | null | undefined, path: string): unknown {
  let cur: unknown = ctx;
  for (const seg of path.split('.')) {
    if (seg === '' || cur === null || typeof cur !== 'object' || Array.isArray(cur)) return undefined;
    if (!Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

const clip = (s: string) => (s.length > 80 ? `${s.slice(0, 77)}...` : s).replace(/[\u0000-\u001F\u007F]/g, '');

/**
 * Whether an owner-keyed context-value atom fires, and why — null when it does not. Config:
 *   field     dot path into the context (required)
 *   values    the owner's list
 *   match     'exact' (default) or 'contains' (the value contains a listed entry: "bulk_delete" contains "delete")
 *   missing   'pass' (default) or 'fire': what an absent field means. 'fire' is fail-closed: an agent cannot skip the
 *             rule by not sending the field
 *   actions   optional: only judge these actions (the signed `action`); any other action is out of the rule's scope
 *
 * Fail-closed shapes, whatever the mode: a value that is not a plain string/number/boolean (or a list of them) —
 * an object, a nested list — cannot be compared, so it FIRES (`malformed`); a list fires if ANY element would. An
 * empty string or empty list counts as absent.
 */
export function contextValueMatch(ctx: EvaluationContext, cfg: any, mode: 'in' | 'not-in'): ContextValueMatch | null {
  const field = typeof cfg?.field === 'string' ? cfg.field.trim() : '';
  if (field === '') return null; // validation rejects this at authoring; an unconfigured atom never fires
  const actions = Array.isArray(cfg?.actions) ? (cfg.actions as unknown[]).map((a) => String(a).trim()).filter(Boolean) : [];
  if (actions.length > 0 && !actions.includes(String(ctx.action ?? '').trim())) return null;
  const listed = (Array.isArray(cfg?.values) ? (cfg.values as unknown[]) : [])
    .map((v) => normalizeContextToken(String(v)))
    .filter((v) => v !== '');
  const contains = cfg?.match === 'contains';

  const raw = contextValueAt(ctx as Record<string, unknown>, field);
  const elements: unknown[] = Array.isArray(raw) ? raw : raw === undefined || raw === null ? [] : [raw];
  const present = elements.filter((e) => !(typeof e === 'string' && e.trim() === '') && e !== null && e !== undefined);
  if (present.length === 0) return cfg?.missing === 'fire' ? { field, reason: 'missing' } : null;

  for (const e of present) {
    if (typeof e !== 'string' && typeof e !== 'number' && typeof e !== 'boolean') return { field, reason: 'malformed' };
    const v = normalizeContextToken(String(e));
    const hit = listed.some((l) => (contains ? v.includes(l) : v === l));
    if (mode === 'in' && hit) return { field, value: clip(String(e).trim()), reason: 'listed' };
    if (mode === 'not-in' && !hit) return { field, value: clip(String(e).trim()), reason: 'unlisted' };
  }
  return null;
}

/**
 * True when `value` is a non-empty string that is NOT in the (case-insensitive) allow-list.
 *
 * An EMPTY allow-list fires on any non-empty value — "nothing is approved yet" — matching
 * `data-source-not-approved`'s own behavior and this file's own header comment above
 * ("Allow-list atoms fire when the context field is PRESENT and NOT allowed"). A previous
 * version required `allowed.length > 0` before firing at all, which silently inverted that:
 * an unconfigured allow-list meant EVERYTHING was permitted rather than nothing, for
 * `jurisdiction-not-allowed`, `data-residency-violation`, `model-not-allowed` and
 * `tool-not-allowed`. Confirmed via the real simulation engine against
 * `tool-boundary-baseline`'s own seeded config (`allowed: []`, deliberately empty per that
 * set's remediation text "so that nothing passes unexamined") that the old behavior let
 * every tool/model through — the opposite of what was promised.
 */
function notInAllowList(value: unknown, allowList: unknown): boolean {
  const v = value != null ? String(value).toLowerCase().trim() : '';
  if (v === '') return false;
  const allowed = (Array.isArray(allowList) ? allowList : []).map((x) => String(x).toLowerCase().trim());
  return !allowed.includes(v);
}

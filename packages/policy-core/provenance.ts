/**
 * Trusted context provenance (spec §6.4.3).
 *
 * The rule atoms judge the request CONTEXT, and until now that context was the union of the signed
 * request fields and an unsigned `itinerary` the agent writes itself. A rule that reads `riskLevel`
 * therefore judged what the agent said about its own risk — omit it, or send `"HIGH"`, and the rule
 * never fired. Signing the context does not fix that (a signature says WHO asserted a value, not that
 * it is TRUE), and the counterparty re-check re-reads the same claim.
 *
 * So every context field carries a PROVENANCE: where the value came from, ordered by how far it can be
 * relied on when the agent is the adversary.
 *
 *   agent_asserted   the agent's own unsigned claim (the `itinerary`)
 *   agent_signed     covered by the agent's signature: attributable to it, not verified
 *   gateway_derived  derived by the authenticated counterparty that is about to execute (it read the
 *                    real request, so it is not taking the agent's word)
 *   authoritative    derived by the issuer itself (server-derived spend, call count, trust) or set by the
 *                    mandate's owner (a mandate's `riskTier`)
 *   attested         backed by a verified attestation / credential
 *
 * Provenance is attached ONLY by `buildRuleContext`, by the party assembling the context, and is stored
 * under a symbol key: an agent's JSON can carry a string key called "provenance", but it cannot carry a
 * symbol, so it can never forge one.
 *
 * Two rules follow, and both fail CLOSED:
 *  - a value from a trusted source can only be RAISED by the agent, never lowered: for an ordered,
 *    restrictive field (`riskLevel`) the effective value is the maximum of every trusted floor and the
 *    agent's claim, so "I am low risk" cannot undo the owner saying "this action is high risk";
 *  - a rule that needs a field and cannot get a well-formed, sufficiently trusted value ESCALATES
 *    (standards-rules.ts) instead of quietly not firing.
 *
 * PURE and dependency-free, like everything in policy-core.
 */

export type ContextProvenance = 'agent_asserted' | 'agent_signed' | 'gateway_derived' | 'authoritative' | 'attested';

/** Lowest to highest trust. */
export const PROVENANCE_LEVELS: readonly ContextProvenance[] = ['agent_asserted', 'agent_signed', 'gateway_derived', 'authoritative', 'attested'];

export const PROVENANCE_RANK: Readonly<Record<ContextProvenance, number>> = {
  agent_asserted: 0,
  agent_signed: 1,
  gateway_derived: 2,
  authoritative: 3,
  attested: 4,
};

export function isProvenance(v: unknown): v is ContextProvenance {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(PROVENANCE_RANK, v);
}

/**
 * The key the provenance map hangs off a context under. A registry symbol, so a generated copy of this
 * module (each guard bundles its own) still agrees on it, and so JSON — which is all an agent can send —
 * cannot carry it.
 */
export const PROVENANCE_KEY: symbol = Symbol.for('magp.context.provenance');

export type ProvenanceMap = Record<string, ContextProvenance>;

/**
 * Where `field` came from. Anything not explicitly labelled by the assembler is `agent_asserted`: an
 * unlabelled context (a test, a legacy caller, a forgotten code path) can never read as more trusted
 * than the agent's own word.
 */
export function provenanceOf(ctx: object | null | undefined, field: string): ContextProvenance {
  const map = (ctx as Record<symbol, unknown> | null | undefined)?.[PROVENANCE_KEY];
  const p = map && typeof map === 'object' ? (map as Record<string, unknown>)[field] : undefined;
  return isProvenance(p) ? p : 'agent_asserted';
}

export function meetsProvenance(actual: ContextProvenance, minimum: ContextProvenance): boolean {
  return PROVENANCE_RANK[actual] >= PROVENANCE_RANK[minimum];
}

// ─── risk ────────────────────────────────────────────────────────────────────────────────────────────

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export const RISK_LEVELS: readonly RiskLevel[] = ['low', 'medium', 'high', 'critical'];
const RISK_ORDER: Readonly<Record<RiskLevel, number>> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * A risk level, read tolerantly (case and surrounding whitespace do not matter: `"HIGH "` is `high`), or
 * null for anything that is not one — including a non-string, an empty string and an unknown word. The one
 * place risk is parsed, so the atom, the assembler and the SUPERVISED-mode gate cannot disagree about it.
 */
export function normalizeRiskLevel(v: unknown): RiskLevel | null {
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(RISK_ORDER, s) ? (s as RiskLevel) : null;
}

export function maxRisk(...levels: (RiskLevel | null | undefined)[]): RiskLevel | null {
  let best: RiskLevel | null = null;
  for (const l of levels) if (l && (best === null || RISK_ORDER[l] > RISK_ORDER[best])) best = l;
  return best;
}

/**
 * The owner-configured risk tier for `target` in `mandate` (`permission[].riskTier`), or null. The highest
 * tier wins if a target is granted more than once. Read from the mandate document, so the gate and every
 * guard — which all hold the same signed mandate — apply the same floor.
 */
export function riskFloorFor(
  mandate: { target?: string; permission?: { target?: string; riskTier?: unknown }[] } | null | undefined,
  target: string,
): RiskLevel | null {
  if (!mandate) return null;
  let floor: RiskLevel | null = null;
  for (const p of mandate.permission ?? []) {
    if (!p || typeof p !== 'object') continue; // a hand-authored document may carry junk; never throw on it
    if ((p.target ?? mandate.target) !== target) continue;
    floor = maxRisk(floor, normalizeRiskLevel(p.riskTier));
  }
  return floor;
}

// ─── risk the agent cannot lower (MAGP §6.4.3) ───────────────────────────────────────────────────────

/**
 * A single payment at or above this share of the action's per-transaction cap is HIGH risk, whatever the agent claims.
 * The owner tunes it per grant (`permission[].riskSignals.amountShare`, a fraction in (0, 1], or `false` to turn it off).
 */
export const DEFAULT_AMOUNT_SHARE_HIGH = 0.7;

/** One reason the effective risk is what it is — recorded with the decision so it explains itself. */
export interface RiskSignal {
  signal: 'owner-tier' | 'amount-share' | 'new-merchant';
  level: RiskLevel;
  /** Human-readable, e.g. "82% of the 500 per-transaction cap". Never an amount the agent did not sign. */
  detail?: string;
}

type GrantLike = { target?: string; riskTier?: unknown; riskSignals?: unknown; constraint?: { leftOperand?: unknown; operator?: unknown; rightOperand?: unknown }[] };
type MandateLike = { target?: string; permission?: GrantLike[] } | null | undefined;

function grantsFor(mandate: MandateLike, target: string): GrantLike[] {
  return (mandate?.permission ?? []).filter((p) => !!p && typeof p === 'object' && (p.target ?? mandate?.target) === target);
}

/** The tightest per-transaction cap (`mm:payAmount`) the grants of `target` set, or null when none does. */
export function perTxnCapFor(mandate: MandateLike, target: string): number | null {
  let cap: number | null = null;
  for (const p of grantsFor(mandate, target)) {
    for (const c of p.constraint ?? []) {
      if (c?.leftOperand !== 'mm:payAmount') continue;
      const n = Number(c.rightOperand);
      if (Number.isFinite(n) && n > 0 && (cap === null || n < cap)) cap = n;
    }
  }
  return cap;
}

/** Whether the owner listed the merchants this action may pay (`mm:merchant`): a listed merchant is already vetted. */
export function hasMerchantAllowList(mandate: MandateLike, target: string): boolean {
  return grantsFor(mandate, target).some((p) => (p.constraint ?? []).some((c) => c?.leftOperand === 'mm:merchant'));
}

/**
 * The owner's settings for derived risk on `target`: `permission[].riskSignals` is `false` (no derived risk at all) or
 * `{ amountShare?: number | false, newMerchant?: boolean }`. Unset = the defaults (amount share 0.7, new merchant on). The
 * strictest grant wins: the smallest share, and new-merchant on if any grant leaves it on.
 */
export function riskSignalSettings(mandate: MandateLike, target: string): { amountShare: number | null; newMerchant: boolean } {
  const grants = grantsFor(mandate, target);
  if (grants.length === 0) return { amountShare: DEFAULT_AMOUNT_SHARE_HIGH, newMerchant: true };
  let amountShare: number | null = null;
  let newMerchant = false;
  for (const p of grants) {
    const s = p.riskSignals;
    if (s === false) continue; // this grant opts out entirely
    const cfg = s && typeof s === 'object' ? (s as { amountShare?: unknown; newMerchant?: unknown }) : {};
    const share = cfg.amountShare === false ? null : cfg.amountShare === undefined ? DEFAULT_AMOUNT_SHARE_HIGH : Number(cfg.amountShare);
    if (share !== null && Number.isFinite(share) && share > 0 && share <= 1 && (amountShare === null || share < amountShare)) amountShare = share;
    if (cfg.newMerchant !== false) newMerchant = true;
  }
  return { amountShare, newMerchant };
}

/**
 * Why `target`'s risk is at least what it is — every source the agent CANNOT lower:
 *   - `owner-tier`: the mandate owner's `riskTier` (riskFloorFor);
 *   - `amount-share`: a signed amount at or above the owner's share (default 70%) of the per-transaction cap is HIGH;
 *   - `new-merchant`: the first payment to an UNVETTED merchant is HIGH. Never where the mandate lists the merchants this
 *     action may pay (a listed merchant is already vetted). Only the issuer knows the rest — the owner's payee directory
 *     and the payment history — so only it passes `newMerchant: true`, and only for a merchant that is neither a registered
 *     payee nor paid before. A guard or gateway derives the other two from the same signed mandate and so agrees.
 * Pure. The agent's own `riskLevel` claim is then merged ABOVE these (buildRuleContext): it can raise risk, never lower it.
 */
export function riskSignalsFor(mandate: MandateLike, target: string, amount?: unknown, opts: { newMerchant?: boolean } = {}): RiskSignal[] {
  const out: RiskSignal[] = [];
  const tier = riskFloorFor(mandate as Parameters<typeof riskFloorFor>[0], target);
  if (tier) out.push({ signal: 'owner-tier', level: tier, detail: `the owner's risk tier for ${target}` });
  const settings = riskSignalSettings(mandate, target);
  const n = typeof amount === 'number' ? amount : Number(amount);
  const cap = perTxnCapFor(mandate, target);
  if (settings.amountShare !== null && cap !== null && Number.isFinite(n) && n > 0 && n >= settings.amountShare * cap) {
    out.push({ signal: 'amount-share', level: 'high', detail: `${Math.round((n / cap) * 100)}% of the ${cap} per-transaction cap (review from ${Math.round(settings.amountShare * 100)}%)` });
  }
  if (opts.newMerchant === true && settings.newMerchant && !hasMerchantAllowList(mandate, target)) {
    out.push({ signal: 'new-merchant', level: 'high', detail: 'the first payment to this merchant' });
  }
  return out;
}

/** The risk floor for `target` the agent cannot lower: the highest of `riskSignalsFor`, or null when none applies. */
export function effectiveRiskFloor(mandate: MandateLike, target: string, amount?: unknown, opts: { newMerchant?: boolean } = {}): RiskLevel | null {
  return maxRisk(...riskSignalsFor(mandate, target, amount, opts).map((s) => s.level));
}

/**
 * Does the owner require this action's payload to be bound (`permission[].requirePayloadBinding`)? True if ANY grant of the
 * target says so — the strict reading, like the highest-tier-wins rule above. Only a literal `true` counts: a hand-authored
 * document with `"yes"` or `1` in it is not silently read as either answer by anything that could throw on it.
 */
export function requiresPayloadBindingFor(
  mandate: { target?: string; permission?: { target?: string; requirePayloadBinding?: unknown }[] } | null | undefined,
  target: string,
): boolean {
  if (!mandate) return false;
  for (const p of mandate.permission ?? []) {
    if (!p || typeof p !== 'object') continue;
    if ((p.target ?? mandate.target) !== target) continue;
    if (p.requirePayloadBinding === true) return true;
  }
  return false;
}

// ─── field shapes ────────────────────────────────────────────────────────────────────────────────────

type FieldKind = 'risk' | 'boolean' | 'number' | 'string' | 'string[]';

/**
 * The shape each context field must have to be judged at all. A field not listed only has to be present.
 * Mirrors the field types in `EvaluationContext` and each atom's `requiredContext`.
 */
const FIELD_KINDS: Readonly<Record<string, FieldKind>> = {
  riskLevel: 'risk',
  consent: 'boolean',
  piiPresent: 'boolean',
  amount: 'number',
  cumulativeSpend: 'number',
  callCount: 'number',
  evidenceConfidence: 'number',
  holTrustScore: 'number',
  dataSourceId: 'string',
  jurisdiction: 'string',
  dataResidency: 'string',
  model: 'string',
  tool: 'string',
  currency: 'string',
  action: 'string',
  prompt: 'string',
  output: 'string',
  evidenceTypes: 'string[]',
};

/** Why a field cannot be judged: absent, or present but not a usable value of its kind. Null = usable. */
export function contextFieldProblem(ctx: Record<string, unknown> | null | undefined, field: string): 'missing' | 'malformed' | null {
  const v = ctx?.[field];
  if (v === undefined || v === null) return 'missing';
  if (typeof v === 'string' && v.trim() === '') return 'missing';
  switch (FIELD_KINDS[field]) {
    case 'risk':
      return normalizeRiskLevel(v) === null ? 'malformed' : null;
    case 'boolean':
      return typeof v === 'boolean' ? null : 'malformed';
    case 'number':
      return typeof v === 'number' && Number.isFinite(v) ? null : 'malformed';
    case 'string':
      return typeof v === 'string' ? null : 'malformed';
    case 'string[]':
      return Array.isArray(v) && v.every((x) => typeof x === 'string') ? null : 'malformed';
    default:
      return null;
  }
}

/**
 * The context fields an atom cannot be trusted to judge without, ALWAYS — no rule has to ask. Kept to the
 * atoms whose whole purpose is a risk gate, where "the field was not sent" is indistinguishable from an
 * agent hiding it. Every other atom keeps its documented absent-field behaviour (sop-compiler's
 * `onMissing`) unless a rule opts in with `requireProvenance`.
 */
export const ATOM_DEFAULT_REQUIRED_CONTEXT: Readonly<Record<string, readonly string[]>> = {
  'risk-at-or-above': ['riskLevel'],
};

// ─── assembling a context ────────────────────────────────────────────────────────────────────────────

export interface RuleContextSources {
  /** The agent's own unsigned context (`itinerary`). Every key is `agent_asserted`. */
  unsigned?: Record<string, unknown> | null;
  /** Fields covered by the agent's signature. `agent_signed`. */
  signed?: Record<string, unknown> | null;
  /** Fields the authenticated counterparty derived from the real request. `gateway_derived`. */
  gatewayDerived?: Record<string, unknown> | null;
  /** Fields the issuer derived itself (spend, call count, trust). `authoritative`. */
  serverDerived?: Record<string, unknown> | null;
  /** The mandate owner's risk tier for this action (`riskFloorFor`). `authoritative`. */
  riskFloor?: RiskLevel | null;
}

/**
 * Build the rule-evaluation context and label every field with where it came from.
 *
 * Precedence is by trust: unsigned < signed < gateway-derived < server-derived — each later source wins a
 * collision, which is the `applySignedLast` invariant (spec §6.4.2) extended to the new sources.
 *
 * `riskLevel` is the exception to "last wins": it is an ordered, restrictive field, so it is MERGED — the
 * maximum of the owner's tier, the gateway's and the server's values and the agent's own claim. The agent
 * can raise its risk, never lower it below what a trusted source says. It takes the provenance of the most
 * trusted floor present; with no floor it is just what the agent claimed (normalised), or left as it was —
 * malformed stays malformed, for `contextFieldProblem` to catch downstream.
 *
 * Pure: returns a new object, mutates no input.
 */
export function buildRuleContext(src: RuleContextSources): Record<string, unknown> {
  const ctx: Record<string, unknown> = {};
  // A prototype-less map, and own-property definitions for the context: an agent's JSON can carry a key called
  // "__proto__", and a plain `ctx[k] = v` would run that setter and swap the context's PROTOTYPE for attacker
  // data instead of adding a harmless own property (which is all the old `{ ...unsigned }` spread ever did).
  const prov = Object.create(null) as ProvenanceMap;
  const put = (k: string, v: unknown, level: ContextProvenance) => {
    Object.defineProperty(ctx, k, { value: v, enumerable: true, writable: true, configurable: true });
    prov[k] = level;
  };
  const layers: [Record<string, unknown> | null | undefined, ContextProvenance][] = [
    [src.unsigned, 'agent_asserted'],
    [src.signed, 'agent_signed'],
    [src.gatewayDerived, 'gateway_derived'],
    [src.serverDerived, 'authoritative'],
  ];
  for (const [layer, level] of layers) {
    for (const [k, v] of Object.entries(layer ?? {})) {
      // A TRUSTED source that states an unusable riskLevel (a lookup that missed and returned undefined, a typo)
      // has said nothing: it must neither overwrite the agent's claim nor lend it the trusted source's label.
      if (k === 'riskLevel' && (level === 'gateway_derived' || level === 'authoritative') && normalizeRiskLevel(v) === null) continue;
      put(k, v, level);
    }
  }

  // riskLevel: merge, never let the agent lower a trusted floor.
  const floors: { level: RiskLevel; source: ContextProvenance }[] = [];
  const addFloor = (v: unknown, source: ContextProvenance) => {
    const n = normalizeRiskLevel(v);
    if (n) floors.push({ level: n, source });
  };
  addFloor(src.riskFloor, 'authoritative');
  addFloor(src.gatewayDerived?.riskLevel, 'gateway_derived');
  addFloor(src.serverDerived?.riskLevel, 'authoritative');
  const assertedUnsigned = normalizeRiskLevel(src.unsigned?.riskLevel);
  const assertedSigned = normalizeRiskLevel(src.signed?.riskLevel);
  const asserted = maxRisk(assertedUnsigned, assertedSigned);
  if (floors.length > 0) {
    put('riskLevel', maxRisk(asserted, ...floors.map((f) => f.level)), floors.reduce<ContextProvenance>((best, f) => (PROVENANCE_RANK[f.source] > PROVENANCE_RANK[best] ? f.source : best), 'agent_asserted'));
  } else if (asserted) {
    // "HIGH " -> "high", and labelled by where the CLAIM came from — always recomputed here, never inherited from
    // whichever layer the raw value happened to be copied from above.
    put('riskLevel', asserted, assertedSigned ? 'agent_signed' : 'agent_asserted');
  }

  Object.defineProperty(ctx, PROVENANCE_KEY, { value: prov, enumerable: true, writable: false });
  return ctx;
}

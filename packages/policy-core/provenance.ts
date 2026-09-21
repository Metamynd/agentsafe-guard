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

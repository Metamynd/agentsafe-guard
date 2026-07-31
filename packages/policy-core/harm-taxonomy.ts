/**
 * Harm-linked controls (harm-assurance adoption #1) — a lightweight, RELATIONAL harm
 * vocabulary that lets a control (Standard/SOP rule) record the foreseeable harm it
 * mitigates and WHY that harm is foreseeable. This is the core idea of the Harm
 * Assurance Network without the graph database: harm as a controlled concept, attached
 * to the existing rule documents as authoring metadata.
 *
 * PURE + dependency-free, and deliberately NOT part of the deterministic runtime gate
 * (harm annotations never affect `evaluate` / `moleculeFires`). They are consumed only
 * at authoring (validation) and in the Compliance Artifact (the due-care narrative), so
 * this module is intentionally NOT re-exported from policy-core/index — the guard
 * mirrors do not carry it and never need regenerating for a harm change.
 */

/** The harm categories (Harm Assurance spec §9). */
export const HARM_CATEGORIES = [
  'physical',
  'financial',
  'privacy',
  'psychological',
  'reputational',
  'legal',
  'environmental',
  'societal',
  'systemic',
] as const;
export type HarmCategory = (typeof HARM_CATEGORIES)[number];

/** How strongly the harm was foreseeable (Harm Assurance spec — Hazard.foreseeability). */
export const FORESEEABILITY_LEVELS = ['known', 'reasonably-foreseeable', 'emerging', 'speculative'] as const;
export type ForeseeabilityLevel = (typeof FORESEEABILITY_LEVELS)[number];

/** Suggested foreseeability bases (spec §2.3) — advisory; free-text is allowed. */
export const SUGGESTED_FORESEEABILITY_BASES = [
  'known-incident',
  'domain-knowledge',
  'regulatory-guidance',
  'model-evaluation',
  'red-team',
  'historical-evidence',
  'similar-system',
  'expert-assessment',
  'complaint-pattern',
  'architecture',
  'inherent-capability',
  'anticipated-misuse',
] as const;

/** The foreseeable harm a control mitigates, with the evidence that it is foreseeable. */
export interface HarmAnnotation {
  category: HarmCategory;
  /** Free-text refinement, e.g. "unauthorized financial loss". */
  subtype?: string;
  /** Optional link to the specific rule (molecule id) that mitigates this harm. */
  moleculeId?: string;
  foreseeability: {
    level: ForeseeabilityLevel;
    /** WHY it is foreseeable — at least one basis (see SUGGESTED_FORESEEABILITY_BASES). */
    basis: string[];
  };
  note?: string;
}

export function isHarmCategory(v: unknown): v is HarmCategory {
  return typeof v === 'string' && (HARM_CATEGORIES as readonly string[]).includes(v);
}
export function isForeseeabilityLevel(v: unknown): v is ForeseeabilityLevel {
  return typeof v === 'string' && (FORESEEABILITY_LEVELS as readonly string[]).includes(v);
}

/** How severe/certain a foreseeability level is — higher = more certain the harm was foreseeable. */
const FORESEEABILITY_RANK: Record<ForeseeabilityLevel, number> = {
  speculative: 0,
  emerging: 1,
  'reasonably-foreseeable': 2,
  known: 3,
};

export interface HarmValidationIssue {
  index: number;
  message: string;
}

/**
 * Validate a document's harm annotations for publishing: a valid category, a valid
 * foreseeability level, and at least one non-empty foreseeability basis. Absent harms
 * are always valid (the annotation is optional / backward-compatible).
 */
export function validateHarms(harms: unknown): { ok: boolean; issues: HarmValidationIssue[] } {
  if (harms === undefined || harms === null) return { ok: true, issues: [] };
  const issues: HarmValidationIssue[] = [];
  if (!Array.isArray(harms)) return { ok: false, issues: [{ index: -1, message: 'harms must be an array' }] };
  harms.forEach((h, i) => {
    const a = h as Partial<HarmAnnotation> | null;
    if (!a || typeof a !== 'object') {
      issues.push({ index: i, message: 'harm annotation must be an object' });
      return;
    }
    if (!isHarmCategory(a.category)) {
      issues.push({ index: i, message: `invalid harm category '${String(a.category)}' (one of: ${HARM_CATEGORIES.join(', ')})` });
    }
    const level = a.foreseeability?.level;
    if (!isForeseeabilityLevel(level)) {
      issues.push({ index: i, message: `invalid foreseeability level '${String(level)}' (one of: ${FORESEEABILITY_LEVELS.join(', ')})` });
    }
    const basis = a.foreseeability?.basis;
    if (!Array.isArray(basis) || basis.length === 0 || !basis.every((b) => typeof b === 'string' && b.trim())) {
      issues.push({ index: i, message: 'foreseeability.basis must be a non-empty array of strings (why the harm is foreseeable)' });
    }
  });
  return { ok: issues.length === 0, issues };
}

/** Extract the VALID harm annotations from a rule document (defensive — drops malformed). */
export function harmsFromDocument(document: unknown): HarmAnnotation[] {
  const raw = (document as { harms?: unknown } | null | undefined)?.harms;
  if (!Array.isArray(raw)) return [];
  return raw.filter((h): h is HarmAnnotation => {
    const a = h as Partial<HarmAnnotation> | null;
    return (
      !!a &&
      typeof a === 'object' &&
      isHarmCategory(a.category) &&
      isForeseeabilityLevel(a.foreseeability?.level) &&
      Array.isArray(a.foreseeability?.basis) &&
      a.foreseeability!.basis.length > 0
    );
  });
}

export interface HarmCoverageEntry {
  category: HarmCategory;
  /** The strongest foreseeability across the controls addressing this category. */
  worstForeseeability: ForeseeabilityLevel;
  count: number;
  subtypes: string[];
}

/**
 * Aggregate harm annotations into per-category coverage for the assurance narrative:
 * which harm categories the in-force controls address, and how strongly foreseeable
 * (the worst / most-certain level) each category is.
 */
export function summarizeHarmCoverage(harms: HarmAnnotation[]): HarmCoverageEntry[] {
  const byCat = new Map<HarmCategory, { level: ForeseeabilityLevel; count: number; subtypes: Set<string> }>();
  for (const h of harms) {
    const cur = byCat.get(h.category);
    if (!cur) {
      byCat.set(h.category, { level: h.foreseeability.level, count: 1, subtypes: new Set(h.subtype ? [h.subtype] : []) });
    } else {
      cur.count += 1;
      if (FORESEEABILITY_RANK[h.foreseeability.level] > FORESEEABILITY_RANK[cur.level]) cur.level = h.foreseeability.level;
      if (h.subtype) cur.subtypes.add(h.subtype);
    }
  }
  // Stable order: by the taxonomy's declared order.
  return HARM_CATEGORIES.filter((c) => byCat.has(c)).map((c) => {
    const v = byCat.get(c)!;
    return { category: c, worstForeseeability: v.level, count: v.count, subtypes: [...v.subtypes] };
  });
}

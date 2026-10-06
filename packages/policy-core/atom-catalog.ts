import { ATOM_REGISTRY } from './atom-registry.js';

/**
 * Human/AI-facing metadata for each code-defined atom predicate. This catalog is
 * the single source of truth the rules configurator renders, the AI-draft
 * endpoint is grounded to, and the integration docs derive the authorize
 * "context contract" from (which fields an agent must send). The executable
 * predicates themselves live in ATOM_REGISTRY.
 */

export type AtomConfigType = 'string' | 'number' | 'string[]' | 'enum';

export interface AtomConfigField {
  key: string;
  type: AtomConfigType;
  required: boolean;
  description: string;
  options?: string[]; // for type 'enum'
}

export interface AtomSpec {
  predicate: string; // matches a key of ATOM_REGISTRY
  label: string;
  description: string;
  /** Config fields the author supplies. */
  config: AtomConfigField[];
  /** EvaluationContext fields the AGENT must supply at authorize time for this atom to evaluate. */
  requiredContext: string[];
}

export const ATOM_SPECS: AtomSpec[] = [
  {
    predicate: 'amount-over',
    label: 'Per-transaction amount over limit',
    description: 'Fires when a single action amount exceeds a configured limit (per-transaction cap).',
    config: [
      { key: 'limit', type: 'number', required: true, description: 'Maximum allowed amount for one transaction' },
      {
        key: 'currency',
        type: 'string[]',
        required: false,
        description:
          "Optional currency scope for the limit (e.g. ['USD'], or ['USD','GBP'] for several). Leave empty to " +
          'keep the limit currency-blind — the historical default: the raw number is compared regardless of ' +
          "currency. Once set, a request in a currency outside this list — or with none supplied at all — fires " +
          'this atom regardless of amount (unverifiable is treated as unsafe, not as "smaller"), so the cap ' +
          "can't be cleared by naming a cheaper-looking currency (e.g. 200 JPY vs 200 USD).",
      },
    ],
    // `currency` is NOT listed here even though the executable atom conditionally reads it:
    // unlike `limit`, the `currency` config is OPTIONAL per atom instance, so whether an agent
    // needs to supply it depends on how a given molecule configures this atom — something
    // `requiredContextFor`'s per-predicate (not per-instance) model can't express. Every
    // authorize request already carries `currency` unconditionally regardless (see
    // AuthorizeInput), so nothing is actually left unfed by omitting it here — this only
    // controls the Scenario Bank simulate form / docs "context contract" surfacing, and
    // forcing it onto every amount-over molecule would spuriously mark scenarios that never
    // configure a currency scope as unexercised (see cumulative-over-atom.test.ts's sibling
    // comment below for the same reasoning applied there).
    requiredContext: ['amount'],
  },
  {
    predicate: 'amount-unknown',
    label: 'Amount not determinable',
    description:
      'Fires when the action carries no usable amount, or a NEGATIVE one — the gate cannot trust ' +
      'either for capping. A deny-by-default control for value-moving actions: author it with ' +
      'BLOCK ahead of a spend cap, otherwise an amount that is missing, unparseable, or negative ' +
      'passes the cap untested (amount-over only ever fires above the limit, so a negative amount ' +
      'clears every positive cap). A genuine $0 amount does NOT fire this — only attach it to ' +
      'actions that must always carry a real, non-negative amount.',
    config: [],
    requiredContext: ['amount'],
  },
  {
    predicate: 'cumulative-over',
    label: 'Total budget over limit',
    description: 'Fires when cumulative spend (already-spent + this transaction) exceeds a configured total budget.',
    config: [
      { key: 'limit', type: 'number', required: true, description: 'Maximum total budget across all transactions' },
      {
        key: 'currency',
        type: 'string[]',
        required: false,
        description:
          "Optional currency scope for the budget (e.g. ['USD'], or ['USD','GBP'] for several). Leave empty to " +
          "keep it currency-blind — the historical default. Once set, a request in a currency outside this " +
          'list — or with none supplied at all — fires this atom regardless of amount, same fail-closed design ' +
          "as amount-over's currency scope.",
      },
    ],
    // The executable atom (atom-registry.ts) reads BOTH fields: `cumulativeSpend + amount >
    // limit`. Omitting `cumulativeSpend` here silently broke two downstream consumers this
    // catalog is the single source of truth for (see file header): the Scenario Bank's
    // simulate form never rendered an "already spent" field for any set using this atom —
    // including its own seeded preset, which supplied `cumulativeSpend` for a form field
    // that didn't exist — so the control could never actually be exercised from the UI; and
    // the integration docs' generated "context contract" told real SDK integrators this
    // atom only needs `amount`, so an agent that never sends `cumulativeSpend` gets it
    // silently treated as 0 and the total-budget cap never fires in production either.
    //
    // `currency`, by contrast, is deliberately NOT added here even though the executable atom
    // conditionally reads it — see the sibling comment on `amount-over`'s currency config
    // above: it is optional PER ATOM INSTANCE (only read when a molecule configures a
    // currency scope), so unlike `cumulativeSpend` (always read), a static per-predicate
    // requiredContext can't represent it without forcing every set using this atom to demand
    // a currency it may never need.
    requiredContext: ['amount', 'cumulativeSpend'],
  },
  {
    predicate: 'risk-at-or-above',
    label: 'Risk at or above level',
    description: 'Fires when the assessed risk level is at or above the configured threshold.',
    config: [
      {
        key: 'level',
        type: 'enum',
        required: true,
        description: 'Threshold risk level',
        options: ['low', 'medium', 'high', 'critical'],
      },
    ],
    requiredContext: ['riskLevel'],
  },
  {
    predicate: 'data-source-not-approved',
    label: 'Data source not approved',
    description: 'Fires when the action uses a data source not on the approved list.',
    config: [
      { key: 'approved', type: 'string[]', required: true, description: 'Allow-list of approved data source ids' },
    ],
    requiredContext: ['dataSourceId'],
  },
  {
    predicate: 'consent-missing',
    label: 'Consent missing',
    description: 'Fires when explicit consent is absent for the action.',
    config: [],
    requiredContext: ['consent'],
  },
  {
    predicate: 'text-matches',
    label: 'Text contains prohibited terms',
    description: 'Fires when the prompt or output contains any of the configured terms.',
    config: [{ key: 'terms', type: 'string[]', required: true, description: 'Terms that must not appear' }],
    requiredContext: ['prompt', 'output'],
  },
  {
    predicate: 'jurisdiction-not-allowed',
    label: 'Jurisdiction not allowed',
    description: "Fires when the action's jurisdiction is not on the allow-list.",
    config: [{ key: 'allowed', type: 'string[]', required: true, description: 'Allowed jurisdictions (e.g. US, MY, EU)' }],
    requiredContext: ['jurisdiction'],
  },
  {
    predicate: 'data-residency-violation',
    label: 'Data residency violation',
    description: 'Fires when data would be processed in a region not on the allow-list.',
    config: [{ key: 'allowedRegions', type: 'string[]', required: true, description: 'Allowed processing regions' }],
    requiredContext: ['dataResidency'],
  },
  {
    predicate: 'model-not-allowed',
    label: 'LLM model not allowed',
    description: 'Fires when the agent uses an LLM model not on the approved list.',
    config: [{ key: 'allowed', type: 'string[]', required: true, description: 'Approved model ids' }],
    requiredContext: ['model'],
  },
  {
    predicate: 'tool-not-allowed',
    label: 'Tool not allowed',
    description: 'Fires when the agent invokes a tool/function not on the approved list.',
    config: [{ key: 'allowed', type: 'string[]', required: true, description: 'Approved tool names' }],
    requiredContext: ['tool'],
  },
  {
    predicate: 'pii-present',
    label: 'PII present',
    description: 'Fires when the action is flagged as involving personal data (PII).',
    config: [],
    requiredContext: ['piiPresent'],
  },
  {
    predicate: 'rate-limit-exceeded',
    label: 'Rate limit exceeded',
    description: 'Fires when the rolling call count exceeds a configured maximum.',
    config: [{ key: 'max', type: 'number', required: true, description: 'Maximum allowed calls' }],
    requiredContext: ['callCount'],
  },
  {
    predicate: 'hol-trust-below-review',
    label: 'Counterparty trust below review line',
    description:
      "Routes to human review when the counterparty's MetaMynd Trust Index (HCS-28) score is below a " +
      'soft review line. Guidance, not a hard block — author it with an ESCALATE decision. The score ' +
      'is resolved server-side; no counterparty score → the atom does not fire.',
    config: [{ key: 'reviewBelow', type: 'number', required: true, description: 'Trust score (0–100) below which a human is asked to decide' }],
    requiredContext: ['holTrustScore'],
  },
  {
    predicate: 'evidence-requirement',
    label: 'Required evidence missing',
    description:
      'Fires when the action is not backed by every REQUIRED evidence type the agent attests to in ' +
      '`evidenceTypes` (missing evidence — including none supplied). A REQUIRE control (SAFR §24): ' +
      'author it with ESCALATE or BLOCK so an under-evidenced action is stopped or reviewed.',
    config: [{ key: 'required', type: 'string[]', required: true, description: 'Evidence types that must all be present (e.g. kyc, source-doc, signature)' }],
    requiredContext: ['evidenceTypes'],
  },
  {
    predicate: 'evidence-confidence-below',
    label: 'Evidence confidence below minimum',
    description:
      'Fires when the attested evidence confidence is below a required minimum — or absent (SAFR §24). ' +
      'A min of 0 / unset is no requirement. Author with ESCALATE to route low-confidence actions to review.',
    config: [{ key: 'min', type: 'number', required: true, description: 'Minimum evidence confidence (0–1) required' }],
    requiredContext: ['evidenceConfidence'],
  },
  // Owner-keyed context values (pre-beta rerun 6, NF-RISK-SELF). requiredContext is EMPTY on purpose: the field these
  // read is chosen per atom instance (`field`), which a per-predicate list cannot express — the same reason amount-over's
  // optional `currency` is not listed. sop-compiler.input-semantics.ts reads the configured field instead, so the
  // review screen still says what an absent one does.
  {
    predicate: 'context-value-in',
    label: 'Context value is on a list (owner-marked operation)',
    description:
      'Fires when a field of the request context (e.g. `op`, or `params.op`) has one of the listed values — key a rule on ' +
      'WHAT the agent is doing, not on the risk level it declares about itself. Author with ESCALATE ("deleting records ' +
      'needs approval") or BLOCK. Case, width, whitespace, hyphens/underscores, invisible characters and common ' +
      'Cyrillic/Greek look-alike letters are ignored when comparing. A deny-list cannot foresee every spelling: when the ' +
      'safe values are known, prefer context-value-not-in. When it fires, the verdict and the escalation carry a ' +
      '`context-value` risk signal naming the field and value.',
    config: [
      { key: 'field', type: 'string', required: true, description: 'Dot path of the context field to read, e.g. op or params.op' },
      { key: 'values', type: 'string[]', required: true, description: 'Values that make the rule fire, e.g. delete, delete-all, purge' },
      { key: 'match', type: 'enum', required: false, options: ['exact', 'contains'], description: "exact (default), or contains: the value contains a listed entry ('bulk_delete' contains 'delete')" },
      { key: 'missing', type: 'enum', required: false, options: ['pass', 'fire'], description: "What an absent field means: pass (default) or fire — set fire so an agent cannot skip the rule by not sending the field" },
      { key: 'actions', type: 'string[]', required: false, description: 'Optional: judge only these actions (mandate targets); other actions are out of scope' },
    ],
    requiredContext: [],
  },
  {
    predicate: 'context-value-not-in',
    label: 'Context value is not on an allow-list',
    description:
      'Fires when a field of the request context has a value that is NOT on the owner\'s allow-list ("anything other than ' +
      'read or list needs approval"). The sound form of an operation rule: a spelling or look-alike the owner did not ' +
      'foresee fires instead of passing. Same comparison rules, `missing` and `actions` options as context-value-in, and ' +
      'the same `context-value` risk signal when it fires.',
    config: [
      { key: 'field', type: 'string', required: true, description: 'Dot path of the context field to read, e.g. op or params.op' },
      { key: 'values', type: 'string[]', required: true, description: 'The allowed values, e.g. read, list' },
      { key: 'match', type: 'enum', required: false, options: ['exact', 'contains'], description: 'exact (default), or contains: the value contains an allowed entry' },
      { key: 'missing', type: 'enum', required: false, options: ['pass', 'fire'], description: 'What an absent field means: pass (default) or fire (fail closed)' },
      { key: 'actions', type: 'string[]', required: false, description: 'Optional: judge only these actions (mandate targets); other actions are out of scope' },
    ],
    requiredContext: [],
  },
];

/** All atom predicates that have both an executable implementation AND a spec (the publishable set). */
export const CATALOGUED_ATOMS = ATOM_SPECS.filter((s) => !!ATOM_REGISTRY[s.predicate]);

/** The union of context fields an agent must supply to satisfy a given set of atom predicates. */
export function requiredContextFor(predicates: string[]): string[] {
  const fields = new Set<string>();
  for (const p of predicates) {
    const spec = ATOM_SPECS.find((s) => s.predicate === p);
    for (const f of spec?.requiredContext ?? []) fields.add(f);
  }
  return [...fields].sort();
}

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
    label: 'Amount over limit',
    description: 'Fires when the action amount exceeds a configured limit.',
    config: [{ key: 'limit', type: 'number', required: true, description: 'Maximum allowed amount' }],
    requiredContext: ['amount'],
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

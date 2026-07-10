/**
 * Mandate = a policy expressed as DATA (an ODRL-style ruleset) and issued as a
 * Verifiable Credential. The rules are data; the evaluator (mandate-eval) is a
 * small fixed engine + a resolver registry. Adding a scenario = adding
 * constraints, never a schema/code change.
 *
 * Decision vocabulary matches the policy engine and evidence rail:
 * 'allow' | 'block' | 'escalate'.
 *
 * See docs/design/agent-mandates-and-standards-layer.md §3.
 */

export type MandateDecision = 'allow' | 'block' | 'escalate';

/** The fixed operator set. New scenarios add operands/resolvers, not operators. */
export type Operator =
  | 'eq'
  | 'neq'
  | 'lt'
  | 'lteq'
  | 'gt'
  | 'gteq'
  | 'isAnyOf'
  | 'isNoneOf'
  | 'isPartOf'
  | 'before'
  | 'after';

/**
 * A single rule: resolve `leftOperand` (from the request or replayed history),
 * apply `operator` against `rightOperand`.
 */
export interface Constraint {
  leftOperand: string; // e.g. 'mm:payAmount' — resolved via the resolver registry
  operator: Operator;
  rightOperand: unknown;
  unit?: string;
  /** Decision to emit when this constraint is the reason a permission is denied. Default 'block'. */
  onFail?: Exclude<MandateDecision, 'allow'>;
}

export interface Permission {
  target: string; // the action, e.g. 'mm:flight-purchase'
  action?: string; // ODRL action verb, default 'execute'
  constraint?: Constraint[];
}

export interface Prohibition {
  target: string;
  action?: string;
  constraint?: Constraint[]; // empty = always prohibited for this target
  reasonCode?: string;
  /** 'block' (default) or 'escalate' when the prohibition fires. */
  enforcement?: Exclude<MandateDecision, 'allow'>;
}

/** The ODRL policy carried inside the mandate VC's credentialSubject. */
export interface Mandate {
  uid?: string;
  profile?: string;
  target?: string; // default target when a permission/prohibition omits its own
  permission?: Permission[];
  prohibition?: Prohibition[];
  obligation?: { action: string }[];
  validFrom?: string; // ISO — evaluated against request.now
  validUntil?: string; // ISO
}

/**
 * A single authorization request. `values` holds the RESOLVED operand values
 * (stateless ones from the request, stateful ones like cumulative spend
 * pre-resolved from replayed events) so the evaluator stays pure and sync.
 * `now` is caller-supplied (Date.now() is unavailable in some runtimes).
 */
export interface MandateRequest {
  target: string;
  now: string; // ISO timestamp
  values: Record<string, unknown>;
}

export interface MandateResult {
  decision: MandateDecision;
  reasonCode: string;
  matched?: {
    kind: 'permission' | 'prohibition' | 'expiry' | 'no-permission';
    target?: string;
    constraint?: Constraint;
  };
}

/** Running budget for cumulative-spend rules. hold = authorized-but-not-yet-captured. */
export interface BudgetState {
  cap: number;
  spent: number;
  held: number;
}

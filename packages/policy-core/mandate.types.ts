/**
 * Mandate = a policy expressed as DATA (an ODRL-style ruleset) and issued as a
 * Verifiable Credential. The rules are data; the evaluator (mandate-eval) is a
 * small fixed engine + a resolver registry. Adding a scenario = adding
 * constraints, never a schema/code change.
 *
 * Decision vocabulary matches the policy engine and evidence rail:
 * 'allow' | 'observe' | 'block' | 'escalate' | 'suspend' | 'quarantine' | 'decommission'.
 * Two values PERMIT execution: 'allow' and 'observe' (the latter permits-but-flags,
 * SAFR §11). The rest deny (fail-safe). 'suspend'/'quarantine'/'decommission' are
 * containment effects (a terminal deny with a distinct audit signal). A mandate
 * prohibition or constraint can therefore be authored to CONTAIN the agent, not just
 * block one action, via its `enforcement` / `onFail`. 'decommission' is reserved for
 * the owner-initiated agent-identity containment state (never fired by a rule).
 *
 * See docs/design/agent-mandates-and-standards-layer.md §3.
 */

export type MandateDecision = 'allow' | 'observe' | 'block' | 'escalate' | 'suspend' | 'quarantine' | 'decommission';

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
  /**
   * One accepted unit, several, or omitted. For payAmount/cumulativeSpend this is the
   * currency (or currencies) the threshold is denominated in — see mandate-eval.ts's
   * constraintSatisfied for how a request's mm:currency is checked against it, and why
   * omitting `unit` (no currency restriction at all) is the least-safe option.
   */
  unit?: string | string[];
  /** Decision to emit when this constraint is the reason a permission is denied. Default 'block'. */
  onFail?: Exclude<MandateDecision, 'allow'>;
}

export interface Permission {
  target: string; // the action, e.g. 'mm:flight-purchase'
  action?: string; // ODRL action verb, default 'execute'
  constraint?: Constraint[];
  /**
   * The mandate OWNER's risk classification of this action: a floor no agent claim can lower (spec §6.4.3).
   * The rule layer judges `riskLevel` as the maximum of this and whatever the agent asserts, with
   * `authoritative` provenance — so an agent that says "low" about a wire transfer the owner classed `high`
   * is still judged `high`. Carried in the signed mandate, so the gate and every guard apply the same floor.
   * Not an ODRL constraint and never evaluated by `evaluateMandate`: it changes what the RULES see.
   */
  riskTier?: 'low' | 'medium' | 'high' | 'critical';
  /**
   * The mandate OWNER requires the agent to bind the payload it executes (spec §8.3.9): the gate refuses an authorization
   * that carries no signed payload digest (`PAYLOAD_BINDING_REQUIRED`), and refuses to let a hold with no digest — one a
   * reviewer's MODIFY produced, say — be claimed until the agent has bound one (§8.3.11). Without it, binding is the agent's
   * (or the executor's) choice, and an agent or a hop that strips the two fields simply leaves the hold unbound.
   * Not an ODRL constraint and never evaluated by `evaluateMandate`. A delegated child may not drop it.
   */
  requirePayloadBinding?: boolean;
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

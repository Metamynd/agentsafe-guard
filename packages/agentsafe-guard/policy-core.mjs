// GENERATED from backend/src/policy-core — do not edit. Regenerate: npm run build:guard-core

// src/policy-core/atom-registry.ts
var RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
var ATOM_REGISTRY = {
  "data-source-not-approved": (c, cfg) => !!c.dataSourceId && !(cfg?.approved ?? []).includes(String(c.dataSourceId)),
  "consent-missing": (c) => c.consent === false,
  "risk-at-or-above": (c, cfg) => {
    const have = RISK_RANK[String(c.riskLevel)];
    const need = RISK_RANK[String(cfg?.level ?? "high")];
    return have !== void 0 && need !== void 0 && have >= need;
  },
  "amount-over": (c, cfg) => typeof c.amount === "number" && c.amount > Number(cfg?.limit ?? 0),
  // Total budget: cumulativeSpend is a SERVER-derived, signed-last context field (never
  // shadowable by the agent's itinerary), so this compares already-spent + this amount.
  "cumulative-over": (c, cfg) => Number(c.cumulativeSpend ?? 0) + Number(c.amount ?? 0) > Number(cfg?.limit ?? 0),
  // Fires if any configured term appears in the prompt and/or output text.
  // Used to govern agent responses on content (prohibited claims, sensitive advice).
  "text-matches": (c, cfg) => {
    const hay = `${c.prompt ?? ""}
${c.output ?? ""}`.toLowerCase();
    const terms = (cfg?.terms ?? []).map((t) => String(t).toLowerCase());
    return terms.some((t) => t.length > 0 && hay.includes(t));
  },
  // --- Compliance atoms. Allow-list atoms fire when the context field is PRESENT
  //     and NOT allowed (consistent with data-source-not-approved: a missing field
  //     does not fire — the atom's requiredContext documents what to supply). ---
  "jurisdiction-not-allowed": (c, cfg) => notInAllowList(c.jurisdiction, cfg?.allowed),
  "data-residency-violation": (c, cfg) => notInAllowList(c.dataResidency, cfg?.allowedRegions),
  "model-not-allowed": (c, cfg) => notInAllowList(c.model, cfg?.allowed),
  "tool-not-allowed": (c, cfg) => notInAllowList(c.tool, cfg?.allowed),
  "pii-present": (c) => c.piiPresent === true,
  "rate-limit-exceeded": (c, cfg) => typeof c.callCount === "number" && c.callCount > Number(cfg?.max ?? 0)
};
function notInAllowList(value, allowList) {
  const v = value != null ? String(value).toLowerCase().trim() : "";
  const allowed = (Array.isArray(allowList) ? allowList : []).map((x) => String(x).toLowerCase().trim());
  return v !== "" && allowed.length > 0 && !allowed.includes(v);
}

// src/policy-core/atom-catalog.ts
var ATOM_SPECS = [
  {
    predicate: "amount-over",
    label: "Per-transaction amount over limit",
    description: "Fires when a single action amount exceeds a configured limit (per-transaction cap).",
    config: [{ key: "limit", type: "number", required: true, description: "Maximum allowed amount for one transaction" }],
    requiredContext: ["amount"]
  },
  {
    predicate: "cumulative-over",
    label: "Total budget over limit",
    description: "Fires when cumulative spend (already-spent + this transaction) exceeds a configured total budget.",
    config: [{ key: "limit", type: "number", required: true, description: "Maximum total budget across all transactions" }],
    requiredContext: ["amount"]
  },
  {
    predicate: "risk-at-or-above",
    label: "Risk at or above level",
    description: "Fires when the assessed risk level is at or above the configured threshold.",
    config: [
      {
        key: "level",
        type: "enum",
        required: true,
        description: "Threshold risk level",
        options: ["low", "medium", "high", "critical"]
      }
    ],
    requiredContext: ["riskLevel"]
  },
  {
    predicate: "data-source-not-approved",
    label: "Data source not approved",
    description: "Fires when the action uses a data source not on the approved list.",
    config: [
      { key: "approved", type: "string[]", required: true, description: "Allow-list of approved data source ids" }
    ],
    requiredContext: ["dataSourceId"]
  },
  {
    predicate: "consent-missing",
    label: "Consent missing",
    description: "Fires when explicit consent is absent for the action.",
    config: [],
    requiredContext: ["consent"]
  },
  {
    predicate: "text-matches",
    label: "Text contains prohibited terms",
    description: "Fires when the prompt or output contains any of the configured terms.",
    config: [{ key: "terms", type: "string[]", required: true, description: "Terms that must not appear" }],
    requiredContext: ["prompt", "output"]
  },
  {
    predicate: "jurisdiction-not-allowed",
    label: "Jurisdiction not allowed",
    description: "Fires when the action's jurisdiction is not on the allow-list.",
    config: [{ key: "allowed", type: "string[]", required: true, description: "Allowed jurisdictions (e.g. US, MY, EU)" }],
    requiredContext: ["jurisdiction"]
  },
  {
    predicate: "data-residency-violation",
    label: "Data residency violation",
    description: "Fires when data would be processed in a region not on the allow-list.",
    config: [{ key: "allowedRegions", type: "string[]", required: true, description: "Allowed processing regions" }],
    requiredContext: ["dataResidency"]
  },
  {
    predicate: "model-not-allowed",
    label: "LLM model not allowed",
    description: "Fires when the agent uses an LLM model not on the approved list.",
    config: [{ key: "allowed", type: "string[]", required: true, description: "Approved model ids" }],
    requiredContext: ["model"]
  },
  {
    predicate: "tool-not-allowed",
    label: "Tool not allowed",
    description: "Fires when the agent invokes a tool/function not on the approved list.",
    config: [{ key: "allowed", type: "string[]", required: true, description: "Approved tool names" }],
    requiredContext: ["tool"]
  },
  {
    predicate: "pii-present",
    label: "PII present",
    description: "Fires when the action is flagged as involving personal data (PII).",
    config: [],
    requiredContext: ["piiPresent"]
  },
  {
    predicate: "rate-limit-exceeded",
    label: "Rate limit exceeded",
    description: "Fires when the rolling call count exceeds a configured maximum.",
    config: [{ key: "max", type: "number", required: true, description: "Maximum allowed calls" }],
    requiredContext: ["callCount"]
  }
];
var CATALOGUED_ATOMS = ATOM_SPECS.filter((s) => !!ATOM_REGISTRY[s.predicate]);
function requiredContextFor(predicates) {
  const fields = /* @__PURE__ */ new Set();
  for (const p of predicates) {
    const spec = ATOM_SPECS.find((s) => s.predicate === p);
    for (const f of spec?.requiredContext ?? []) fields.add(f);
  }
  return [...fields].sort();
}

// src/policy-core/standards-rules.ts
var PRECEDENCE = { allow: 0, escalate: 1, block: 2 };
function atomFires(atom, ctx) {
  const pred = ATOM_REGISTRY[atom.predicate];
  if (!pred) return false;
  try {
    return !!pred(ctx, atom.config);
  } catch (err) {
    console.warn(
      `[standards] atom '${atom.predicate}' threw during evaluation (treated as not-firing):`,
      err instanceof Error ? err.message : err
    );
    return false;
  }
}
function moleculeFires(m, ctx) {
  if (!m.atoms || m.atoms.length === 0) return false;
  const results = m.atoms.map((a) => atomFires(a, ctx));
  switch (m.combinator) {
    case "all":
      return results.every(Boolean);
    case "any":
      return results.some(Boolean);
    case "none":
      return !results.some(Boolean);
    default:
      return false;
  }
}
function evaluateStandardRules(molecules, ctx, standardKey = null) {
  let best = null;
  for (const m of molecules ?? []) {
    if (moleculeFires(m, ctx)) {
      if (!best || PRECEDENCE[m.decision] > PRECEDENCE[best.decision]) {
        best = { decision: m.decision, reasonCode: m.reasonCode, id: m.id };
      }
    }
  }
  if (!best) return { decision: "allow", reasonCode: null, firedMoleculeId: null, standardKey };
  return { decision: best.decision, reasonCode: best.reasonCode, firedMoleculeId: best.id, standardKey };
}
function evaluateBoundStandards(standards, ctx) {
  let best = { decision: "allow", reasonCode: null, firedMoleculeId: null, standardKey: null };
  for (const s of standards) {
    const r = evaluateStandardRules(s.document?.molecules, ctx, s.standardKey);
    if (PRECEDENCE[r.decision] > PRECEDENCE[best.decision]) best = r;
  }
  return best;
}
function configValueValid(field, value) {
  switch (field.type) {
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "string":
      return typeof value === "string";
    case "string[]":
      return Array.isArray(value) && value.every((v) => typeof v === "string");
    case "enum":
      return typeof value === "string" && (field.options ?? []).includes(value);
    default:
      return true;
  }
}
function validateAtomConfig(predicate, config) {
  const spec = ATOM_SPECS.find((s) => s.predicate === predicate);
  if (!spec) return [];
  const errors = [];
  const cfg = config ?? {};
  for (const field of spec.config) {
    const present = cfg[field.key] !== void 0 && cfg[field.key] !== null;
    if (!present) {
      if (field.required) errors.push(`atom '${predicate}' missing required config '${field.key}'`);
      continue;
    }
    if (!configValueValid(field, cfg[field.key])) {
      errors.push(`atom '${predicate}' config '${field.key}' must be a ${field.type}`);
    }
  }
  return errors;
}
function validateMolecules(molecules) {
  const issues = [];
  for (const m of molecules ?? []) {
    if (!m.id) issues.push({ moleculeId: "(missing id)", message: "molecule is missing an id" });
    if (!["all", "any", "none"].includes(m.combinator)) {
      issues.push({ moleculeId: m.id, message: `invalid combinator '${m.combinator}' (all|any|none)` });
    }
    if (!["block", "escalate"].includes(m.decision)) {
      issues.push({ moleculeId: m.id, message: `invalid decision '${m.decision}' (block|escalate)` });
    }
    if (!m.reasonCode) issues.push({ moleculeId: m.id, message: "molecule is missing a reasonCode" });
    if (!m.atoms || m.atoms.length === 0) {
      issues.push({ moleculeId: m.id, message: "molecule has no atoms" });
    }
    for (const a of m.atoms ?? []) {
      if (!ATOM_REGISTRY[a.predicate]) {
        issues.push({ moleculeId: m.id, message: `unknown atom predicate '${a.predicate}'` });
        continue;
      }
      for (const err of validateAtomConfig(a.predicate, a.config)) {
        issues.push({ moleculeId: m.id, message: err });
      }
    }
  }
  return { ok: issues.length === 0, issues };
}

// src/policy-core/mandate-eval.ts
var toNum = (v) => typeof v === "number" ? v : Number(v);
var toArray = (v) => Array.isArray(v) ? v : v === void 0 || v === null ? [] : [v];
var toTime = (v) => Date.parse(String(v));
var OPERATORS = {
  eq: (l, r) => l === r,
  neq: (l, r) => l !== r,
  lt: (l, r) => toNum(l) < toNum(r),
  lteq: (l, r) => toNum(l) <= toNum(r),
  gt: (l, r) => toNum(l) > toNum(r),
  gteq: (l, r) => toNum(l) >= toNum(r),
  isAnyOf: (l, r) => toArray(r).includes(l),
  isNoneOf: (l, r) => !toArray(r).includes(l),
  isPartOf: (l, r) => toArray(r).includes(l),
  before: (l, r) => toTime(l) < toTime(r),
  after: (l, r) => toTime(l) > toTime(r)
};
var REASON_BY_OPERAND = {
  "mm:payAmount": "SPEND_LIMIT_EXCEEDED",
  "mm:cumulativeSpend": "SPEND_LIMIT_EXCEEDED",
  "mm:merchant": "MERCHANT_NOT_ALLOWED",
  "mm:route": "ROUTE_NOT_ALLOWED",
  "mm:counterparty": "COUNTERPARTY_NOT_ALLOWED"
};
function reasonFor(constraint) {
  if (!constraint) return "CONSTRAINT_FAILED";
  return REASON_BY_OPERAND[constraint.leftOperand] ?? `CONSTRAINT_FAILED:${constraint.leftOperand}`;
}
function constraintSatisfied(c, req) {
  const op = OPERATORS[c.operator];
  if (!op) return false;
  const left = Object.prototype.hasOwnProperty.call(req.values, c.leftOperand) ? req.values[c.leftOperand] : void 0;
  return op(left, c.rightOperand);
}
function targetOf(rule, mandate) {
  return rule.target ?? mandate.target;
}
function evaluateMandate(mandate, req) {
  const now = toTime(req.now);
  if (mandate.validFrom && now < toTime(mandate.validFrom)) {
    return { decision: "block", reasonCode: "MANDATE_NOT_YET_VALID", matched: { kind: "expiry" } };
  }
  if (mandate.validUntil && now > toTime(mandate.validUntil)) {
    return { decision: "block", reasonCode: "MANDATE_EXPIRED", matched: { kind: "expiry" } };
  }
  for (const p of mandate.prohibition ?? []) {
    if (targetOf(p, mandate) !== req.target) continue;
    const fires = (p.constraint ?? []).every((c) => constraintSatisfied(c, req));
    if (fires) {
      return {
        decision: p.enforcement ?? "block",
        reasonCode: p.reasonCode ?? "PROHIBITED",
        matched: { kind: "prohibition", target: p.target }
      };
    }
  }
  const perms = (mandate.permission ?? []).filter((p) => targetOf(p, mandate) === req.target);
  if (perms.length === 0) {
    return {
      decision: "block",
      reasonCode: "NO_PERMISSION_FOR_ACTION",
      matched: { kind: "no-permission", target: req.target }
    };
  }
  for (const p of perms) {
    const failing = (p.constraint ?? []).find((c) => !constraintSatisfied(c, req));
    if (!failing) return { decision: "allow", reasonCode: "AUTHORIZED" };
  }
  const firstFail = (perms[0].constraint ?? []).find((c) => !constraintSatisfied(c, req));
  return {
    decision: firstFail?.onFail ?? "block",
    reasonCode: reasonFor(firstFail),
    matched: { kind: "permission", target: perms[0].target, constraint: firstFail }
  };
}
function remainingBudget(b) {
  return Math.max(0, b.cap - b.spent - b.held);
}
function canAuthorize(b, amount) {
  return amount >= 0 && amount <= remainingBudget(b);
}
function applyHold(b, amount) {
  return { ...b, held: b.held + amount };
}
function applyCapture(b, amount) {
  return { cap: b.cap, spent: b.spent + amount, held: Math.max(0, b.held - amount) };
}
function releaseHold(b, amount) {
  return { ...b, held: Math.max(0, b.held - amount) };
}
function sumEventField(events, type, field) {
  return events.filter((e) => e.type === type).reduce((acc, e) => acc + (typeof e.payload[field] === "number" ? e.payload[field] : 0), 0);
}

// src/policy-core/evaluate.ts
var PRECEDENCE2 = { allow: 0, escalate: 1, block: 2 };
function evaluate(input) {
  let decision = "allow";
  let reasonCode = "AUTHORIZED";
  const consider = (d, code) => {
    if (PRECEDENCE2[d] > PRECEDENCE2[decision]) {
      decision = d;
      reasonCode = code;
    }
  };
  const std = evaluateBoundStandards(input.standards ?? [], input.context);
  if (std.decision !== "allow") consider(std.decision, std.reasonCode ?? "STANDARD_RULE");
  const sop = evaluateBoundStandards(input.sops ?? [], input.context);
  if (sop.decision !== "allow") consider(sop.decision, sop.reasonCode ?? "SOP_RULE");
  if (input.mandate && input.mandateRequest) {
    const m = evaluateMandate(input.mandate, input.mandateRequest);
    if (m.decision !== "allow") consider(m.decision, m.reasonCode);
  }
  return { decision, reasonCode, authorizationId: null, remaining: null, proofRef: null };
}

// src/policy-core/canonical.ts
function buildAuthMessage(f) {
  return `${f.agentDid}|${f.action}|${f.amount}|${f.currency}|${f.merchant ?? ""}|${f.nonce}|${f.issuedAt}`;
}

// src/policy-core/context.ts
function applySignedLast(unsigned, signed) {
  return { ...unsigned ?? {}, ...signed };
}
export {
  ATOM_REGISTRY,
  ATOM_SPECS,
  CATALOGUED_ATOMS,
  applyCapture,
  applyHold,
  applySignedLast,
  buildAuthMessage,
  canAuthorize,
  evaluate,
  evaluateBoundStandards,
  evaluateMandate,
  evaluateStandardRules,
  moleculeFires,
  releaseHold,
  remainingBudget,
  requiredContextFor,
  sumEventField,
  validateMolecules
};

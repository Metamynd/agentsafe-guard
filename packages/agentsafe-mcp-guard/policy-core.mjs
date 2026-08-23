// GENERATED from backend/src/policy-core — do not edit. Regenerate: npm run build:mcp-guard-core

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
  "rate-limit-exceeded": (c, cfg) => typeof c.callCount === "number" && c.callCount > Number(cfg?.max ?? 0),
  // --- Evidence-quality atoms (SAFR §24). Unlike the allow-list atoms, these fire on ABSENCE:
  //     a REQUIRE semantic — "the action must be backed by this evidence; if it isn't, fire"
  //     (author with escalate/block). Opt-in: they only run when a rule keys them. ---
  // Fires when any REQUIRED evidence type is not among the attested `evidenceTypes` (missing
  // evidence — including none supplied at all → all required missing → fires).
  "evidence-requirement": (c, cfg) => {
    const required = (cfg?.required ?? []).map((t) => String(t).toLowerCase().trim()).filter(Boolean);
    if (required.length === 0) return false;
    const have = new Set((Array.isArray(c.evidenceTypes) ? c.evidenceTypes : []).map((t) => String(t).toLowerCase().trim()));
    return required.some((r) => !have.has(r));
  },
  // Fires when a required minimum confidence (min > 0) is not met — the attested confidence is
  // below it, or absent (a required confidence that was never supplied fails the bar). A min of
  // 0 / unset is no requirement and never fires.
  "evidence-confidence-below": (c, cfg) => {
    const min = Number(cfg?.min ?? 0);
    if (!(min > 0)) return false;
    return typeof c.evidenceConfidence !== "number" || c.evidenceConfidence < min;
  },
  // Trust guidance (MetaMynd Trust Index / HCS-28). Fires when the counterparty's trust score is
  // below a soft REVIEW line — intended to author an ESCALATE (route to a human), NOT a hard block.
  // The score is server-derived (signed-last) so the agent's itinerary can't fake it; when no score
  // is present (e.g. no counterparty resolved) the atom simply does not fire — no guidance.
  "hol-trust-below-review": (c, cfg) => typeof c.holTrustScore === "number" && c.holTrustScore < Number(cfg?.reviewBelow ?? 60)
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
  },
  {
    predicate: "hol-trust-below-review",
    label: "Counterparty trust below review line",
    description: "Routes to human review when the counterparty's MetaMynd Trust Index (HCS-28) score is below a soft review line. Guidance, not a hard block \u2014 author it with an ESCALATE decision. The score is resolved server-side; no counterparty score \u2192 the atom does not fire.",
    config: [{ key: "reviewBelow", type: "number", required: true, description: "Trust score (0\u2013100) below which a human is asked to decide" }],
    requiredContext: ["holTrustScore"]
  },
  {
    predicate: "evidence-requirement",
    label: "Required evidence missing",
    description: "Fires when the action is not backed by every REQUIRED evidence type the agent attests to in `evidenceTypes` (missing evidence \u2014 including none supplied). A REQUIRE control (SAFR \xA724): author it with ESCALATE or BLOCK so an under-evidenced action is stopped or reviewed.",
    config: [{ key: "required", type: "string[]", required: true, description: "Evidence types that must all be present (e.g. kyc, source-doc, signature)" }],
    requiredContext: ["evidenceTypes"]
  },
  {
    predicate: "evidence-confidence-below",
    label: "Evidence confidence below minimum",
    description: "Fires when the attested evidence confidence is below a required minimum \u2014 or absent (SAFR \xA724). A min of 0 / unset is no requirement. Author with ESCALATE to route low-confidence actions to review.",
    config: [{ key: "min", type: "number", required: true, description: "Minimum evidence confidence (0\u20131) required" }],
    requiredContext: ["evidenceConfidence"]
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
var PRECEDENCE = { allow: 0, observe: 1, escalate: 2, block: 3, suspend: 4, quarantine: 5 };
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
    if (!["observe", "block", "escalate", "suspend", "quarantine"].includes(m.decision)) {
      issues.push({ moleculeId: m.id, message: `invalid decision '${m.decision}' (observe|block|escalate|suspend|quarantine)` });
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
function isAuthorityFailure(result) {
  return result.matched?.kind === "expiry" || result.matched?.kind === "no-permission";
}
function authorityFailure(mandate, target, now) {
  const result = evaluateMandate(mandate, { target, now, values: {} });
  return isAuthorityFailure(result) ? { ...result, decision: "block" } : null;
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
var PRECEDENCE2 = { allow: 0, observe: 1, escalate: 2, block: 3, suspend: 4, quarantine: 5 };
function evaluate(input) {
  let decision = "allow";
  let reasonCode = "AUTHORIZED";
  const consider = (d, code) => {
    if (PRECEDENCE2[d] > PRECEDENCE2[decision]) {
      decision = d;
      reasonCode = code;
    }
  };
  const m = input.mandate && input.mandateRequest ? evaluateMandate(input.mandate, input.mandateRequest) : null;
  const authority = m !== null && isAuthorityFailure(m);
  if (m && authority) consider(m.decision, m.reasonCode);
  const std = evaluateBoundStandards(input.standards ?? [], input.context);
  if (std.decision !== "allow") consider(std.decision, std.reasonCode ?? "STANDARD_RULE");
  const sop = evaluateBoundStandards(input.sops ?? [], input.context);
  if (sop.decision !== "allow") consider(sop.decision, sop.reasonCode ?? "SOP_RULE");
  if (m && !authority && m.decision !== "allow") consider(m.decision, m.reasonCode);
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

// src/policy-core/operating-mode.ts
var MODE_RANK = {
  read_only: 0,
  restricted: 1,
  supervised: 2,
  autonomous: 3
};
var MODES_BY_RANK = ["read_only", "restricted", "supervised", "autonomous"];
function isOperatingMode(v) {
  return typeof v === "string" && Object.prototype.hasOwnProperty.call(MODE_RANK, v);
}
function asOperatingMode(v) {
  return isOperatingMode(v) ? v : "autonomous";
}
function moreRestrictive(a, b) {
  return MODE_RANK[a] <= MODE_RANK[b] ? a : b;
}
var SUPERVISED_AMOUNT_CAP = 100;
var RISK_RANK2 = { low: 0, medium: 1, high: 2, critical: 3 };
function riskAtOrAboveHigh(riskLevel) {
  const r = typeof riskLevel === "string" ? RISK_RANK2[riskLevel.toLowerCase()] : void 0;
  return r !== void 0 && r >= RISK_RANK2.high;
}
function operatingModeGate(mode, ctx) {
  const m = asOperatingMode(mode);
  const valueBearing = (ctx.amount ?? 0) > 0;
  if (!valueBearing || m === "autonomous") return { decision: "allow", reasonCode: null };
  switch (m) {
    case "read_only":
      return { decision: "block", reasonCode: "MODE_READ_ONLY" };
    case "restricted":
      return { decision: "escalate", reasonCode: "MODE_RESTRICTED_REVIEW" };
    case "supervised":
      return riskAtOrAboveHigh(ctx.riskLevel) || (ctx.amount ?? 0) >= SUPERVISED_AMOUNT_CAP ? { decision: "escalate", reasonCode: "MODE_SUPERVISED_REVIEW" } : { decision: "allow", reasonCode: null };
    default:
      return { decision: "allow", reasonCode: null };
  }
}
export {
  ATOM_REGISTRY,
  ATOM_SPECS,
  CATALOGUED_ATOMS,
  MODES_BY_RANK,
  MODE_RANK,
  SUPERVISED_AMOUNT_CAP,
  applyCapture,
  applyHold,
  applySignedLast,
  asOperatingMode,
  authorityFailure,
  buildAuthMessage,
  canAuthorize,
  evaluate,
  evaluateBoundStandards,
  evaluateMandate,
  evaluateStandardRules,
  isAuthorityFailure,
  isOperatingMode,
  moleculeFires,
  moreRestrictive,
  operatingModeGate,
  releaseHold,
  remainingBudget,
  requiredContextFor,
  sumEventField,
  validateMolecules
};

// GENERATED from backend/src/features/magp/resume-binding.ts - do not edit. Regenerate: npm run build:guard-core

// src/features/magp/resume-binding.ts
import { createHash } from "node:crypto";

// src/policy-core/canonical.ts
function escapeField(v) {
  return v.replace(/\\/g, "\\\\").replace(/\|/g, "\\|");
}

// src/features/magp/resume-binding.ts
var RESUME_BINDING_PREFIX = "MAGP-RESUME-BIND-v1";
function canonicalAmount(amount) {
  if (amount === null || amount === void 0 || amount === "") return "";
  const n = typeof amount === "number" ? amount : Number(amount);
  if (!Number.isFinite(n)) return String(amount);
  return n === 0 ? "" : String(n);
}
function buildResumeBindingMessage(f) {
  const amount = canonicalAmount(f.amount);
  return [
    RESUME_BINDING_PREFIX,
    f.authorizationId,
    f.action,
    amount,
    amount === "" ? "" : f.currency ?? "",
    // a currency binds nothing without an amount (an SDK defaults it to USD)
    f.merchant ?? "",
    f.resource ?? "",
    f.payloadDigest ?? ""
  ].map((v) => escapeField(String(v))).join("|");
}
var RESUME_CLAIM_PREFIX = "MAGP-RESUME-CLAIM-v1";
function buildResumeClaimMessage(f) {
  return [RESUME_CLAIM_PREFIX, f.escalationId, f.authorizationId, f.agentDid, f.nonce, f.issuedAt].map((v) => escapeField(String(v))).join("|");
}
function resumeRequestDigest(f) {
  return "sha256:" + createHash("sha256").update(buildResumeBindingMessage(f), "utf8").digest("hex");
}
export {
  RESUME_BINDING_PREFIX,
  RESUME_CLAIM_PREFIX,
  buildResumeBindingMessage,
  buildResumeClaimMessage,
  canonicalAmount,
  resumeRequestDigest
};

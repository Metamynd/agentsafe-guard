// GENERATED from backend/src/features/magp/resume-binding.ts - do not edit. Regenerate: npm run build:guard-core

// src/features/magp/resume-binding.ts
import { createHash as createHash2 } from "node:crypto";

// src/policy-core/canonical.ts
function escapeField(v) {
  return v.replace(/\\/g, "\\\\").replace(/\|/g, "\\|");
}

// src/features/magp/payload-binding.ts
import { createHash } from "node:crypto";
var PAYLOAD_DIGEST_PREFIX = "sha256:";
var MAX_CANONICAL_PAYLOAD_BYTES = 256 * 1024;
var MAX_DEPTH = 32;
var PayloadNotCanonicalizable = class extends Error {
  constructor(message) {
    super(message);
    this.name = "PayloadNotCanonicalizable";
  }
};
function hasLoneSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 55296 && c <= 56319) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 56320 && next <= 57343)) return true;
      i++;
    } else if (c >= 56320 && c <= 57343) {
      return true;
    }
  }
  return false;
}
function serialize(value, depth, path) {
  if (depth > MAX_DEPTH) throw new PayloadNotCanonicalizable(`payload is nested deeper than ${MAX_DEPTH} levels at ${path}`);
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new PayloadNotCanonicalizable(`${path} is not a finite number`);
      return JSON.stringify(value);
    // ECMAScript Number::toString — what RFC 8785 specifies; -0 serialises as "0"
    case "string":
      if (hasLoneSurrogate(value)) throw new PayloadNotCanonicalizable(`${path} contains an unpaired surrogate`);
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map((v, i) => serialize(v, depth + 1, `${path}[${i}]`)).join(",")}]`;
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new PayloadNotCanonicalizable(`${path} is not a plain JSON object`);
      const obj = value;
      const keys = Object.keys(obj).sort();
      const parts = keys.map((k) => {
        if (hasLoneSurrogate(k)) throw new PayloadNotCanonicalizable(`${path} has a key with an unpaired surrogate`);
        return `${JSON.stringify(k)}:${serialize(obj[k], depth + 1, `${path}.${k}`)}`;
      });
      return `{${parts.join(",")}}`;
    }
    default:
      throw new PayloadNotCanonicalizable(`${path} is a ${typeof value}, which JSON cannot represent`);
  }
}
function canonicalPayload(value) {
  const text = serialize(value, 0, "$");
  if (Buffer.byteLength(text, "utf8") > MAX_CANONICAL_PAYLOAD_BYTES) {
    throw new PayloadNotCanonicalizable(`canonical payload exceeds ${MAX_CANONICAL_PAYLOAD_BYTES} bytes`);
  }
  return text;
}
function payloadDigestOf(value) {
  return PAYLOAD_DIGEST_PREFIX + createHash("sha256").update(canonicalPayload(value), "utf8").digest("hex");
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
  return "sha256:" + createHash2("sha256").update(buildResumeBindingMessage(f), "utf8").digest("hex");
}
var APPROVED_CONTEXT_DOMAIN = "MAGP-APPROVED-CONTEXT-v1";
function approvedContextDigest(context) {
  return payloadDigestOf({ [APPROVED_CONTEXT_DOMAIN]: context ?? {} });
}
export {
  APPROVED_CONTEXT_DOMAIN,
  RESUME_BINDING_PREFIX,
  RESUME_CLAIM_PREFIX,
  approvedContextDigest,
  buildResumeBindingMessage,
  buildResumeClaimMessage,
  canonicalAmount,
  resumeRequestDigest
};

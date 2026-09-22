// GENERATED from backend/src/features/magp/payload-binding.ts - do not edit. Regenerate: npm run build:guard-core

// src/features/magp/payload-binding.ts
import { createHash } from "node:crypto";

// src/policy-core/canonical.ts
function escapeField(v) {
  return v.replace(/\\/g, "\\\\").replace(/\|/g, "\\|");
}

// src/features/magp/payload-binding.ts
var PAYLOAD_BINDING_PREFIX = "MAGP-PAYLOAD-v1";
var PAYLOAD_REBIND_PREFIX = "MAGP-PAYLOAD-REBIND-v1";
var PAYLOAD_DIGEST_PREFIX = "sha256:";
var PAYLOAD_DIGEST_HEADER = "x-magp-payload-digest";
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
var DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
function isPayloadDigest(value) {
  return typeof value === "string" && DIGEST_RE.test(value);
}
function toWireJson(value) {
  const text = JSON.stringify(value);
  if (text === void 0) throw new PayloadNotCanonicalizable("payload is not JSON-serialisable");
  return JSON.parse(text);
}
function buildPayloadBindingMessage(input) {
  return [PAYLOAD_BINDING_PREFIX, input.agentDid, input.action, input.nonce, input.issuedAt, input.payloadDigest].map((f) => escapeField(String(f))).join("|");
}
function buildPayloadRebindMessage(input) {
  return [PAYLOAD_REBIND_PREFIX, input.agentDid, input.action, input.authorizationId, input.nonce, input.issuedAt, input.payloadDigest].map((f) => escapeField(String(f))).join("|");
}
function decideClaimPayload(stored, presented) {
  if (stored) {
    if (!presented) return { ok: false, reasonCode: "PAYLOAD_DIGEST_REQUIRED" };
    return presented === stored ? { ok: true } : { ok: false, reasonCode: "PAYLOAD_DIGEST_MISMATCH" };
  }
  return presented ? { ok: false, reasonCode: "PAYLOAD_NOT_BOUND_AT_AUTHORIZE" } : { ok: true };
}
function claimDigestField(payloadDigest) {
  return `payload=${payloadDigest}`;
}
function claimEvidenceRefs(idempotencyRef, payloadDigest) {
  const refs = [...idempotencyRef ? [idempotencyRef] : [], ...payloadDigest ? [`payload:${payloadDigest}`] : []];
  return refs.length ? refs : null;
}
export {
  MAX_CANONICAL_PAYLOAD_BYTES,
  PAYLOAD_BINDING_PREFIX,
  PAYLOAD_DIGEST_HEADER,
  PAYLOAD_DIGEST_PREFIX,
  PAYLOAD_REBIND_PREFIX,
  PayloadNotCanonicalizable,
  buildPayloadBindingMessage,
  buildPayloadRebindMessage,
  canonicalPayload,
  claimDigestField,
  claimEvidenceRefs,
  decideClaimPayload,
  isPayloadDigest,
  payloadDigestOf,
  toWireJson
};

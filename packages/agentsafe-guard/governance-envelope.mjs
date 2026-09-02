// GENERATED from backend/src/features/policy/mandate/governance-envelope.ts — do not edit. Regenerate: npm run build:guard-core

// src/features/policy/mandate/governance-envelope.ts
import { createHash } from "node:crypto";
var ENVELOPE_VERSION = "1.0";
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value;
  const keys = Object.keys(obj).filter((k) => obj[k] !== void 0).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}
function envelopeIntegrityHash(env) {
  const { integrity: _omit, ...rest } = env;
  return createHash("sha256").update(stableStringify(rest)).digest("hex");
}
function buildGovernanceEnvelope(input) {
  const base = {
    envelopeId: `env:${input.nonce}`,
    version: ENVELOPE_VERSION,
    createdAt: input.issuedAt,
    agent: { did: input.agentDid },
    action: {
      actionId: `act:${input.nonce}`,
      actionType: input.action,
      amount: input.amount,
      currency: input.currency,
      merchant: input.merchant ?? null,
      ...input.materiality ? { materiality: input.materiality } : {}
    },
    ...input.trace ? { trace: input.trace } : {},
    ...input.itinerary ? { context: input.itinerary } : {}
  };
  return {
    ...base,
    integrity: {
      payloadHash: envelopeIntegrityHash(base),
      signature: input.signature,
      signatureType: "Ed25519"
    }
  };
}
function envelopeHashFor(input) {
  return buildGovernanceEnvelope(input).integrity.payloadHash;
}
function authorizeInputFromEnvelope(env) {
  const nonce = env.envelopeId.startsWith("env:") ? env.envelopeId.slice(4) : env.envelopeId;
  return {
    agentDid: env.agent.did,
    action: env.action.actionType,
    amount: env.action.amount ?? 0,
    currency: env.action.currency ?? "",
    merchant: env.action.merchant ?? void 0,
    itinerary: env.context,
    trace: env.trace,
    materiality: env.action.materiality,
    nonce,
    issuedAt: env.createdAt,
    signature: env.integrity.signature ?? ""
  };
}
export {
  ENVELOPE_VERSION,
  authorizeInputFromEnvelope,
  buildGovernanceEnvelope,
  envelopeHashFor,
  envelopeIntegrityHash,
  stableStringify
};

/**
 * Canonical signed-message builder (spec §8.3).
 *
 * The authorize `signature` is an Ed25519 signature over the UTF-8 string formed
 * by joining these eight fields, in this exact order, with the `|` (U+007C)
 * delimiter, substituting the empty string for an absent merchant or resource:
 *
 *   agentDid | action | amount | currency | merchant | resource | nonce | issuedAt
 *
 * This lives in policy-core (not the gate) so BOTH signer and verifier build the
 * identical bytes — the agent guard signs it, the backend gate reconstructs and
 * verifies it, and any third-party guard does the same. Signature verification
 * itself stays OUT of policy-core (it needs the key, not the evaluator).
 *
 * `resource` was added after `merchant` (a breaking wire-format change, 7→8 fields —
 * every signer must move together) so a mandate's `{leftOperand:'resource'}` constraint
 * (ResourceService.scopeConstraint()) is genuinely non-spoofable: cryptographically
 * committed the same way `merchant` already is, not just signed-last-ordered into the
 * evaluation context, which would leave it alterable by a compromised counterparty
 * relaying a `buildSignedRequest()`-built request onward.
 *
 * Version 2 (spec §8.3.12) — the SIGNED jurisdiction. A request that carries `jurisdiction` signs the eight v1 fields,
 * then the literal version tag `MAGP-AUTH-v2`, then the jurisdiction (ten fields):
 *
 *   agentDid | action | amount | currency | merchant | resource | nonce | issuedAt | MAGP-AUTH-v2 | jurisdiction
 *
 * A request that does not carry it signs exactly the eight v1 fields, byte for byte as before, so every existing client
 * keeps verifying. The verifier chooses the shape from the request itself — `jurisdiction` present → v2, absent → v1 —
 * and never tries the other: stripping the field from a v2 request, or adding one to a v1 request, fails the signature.
 * Every field (the tag included) is escaped as in v1, so a ten-field message can never rebuild as an eight-field one.
 */
export const AUTH_MESSAGE_V2_TAG = 'MAGP-AUTH-v2';

export interface AuthMessageFields {
  agentDid: string;
  action: string;
  amount: number | string;
  currency: string;
  merchant?: string | null;
  resource?: string | null;
  nonce: string;
  issuedAt: string;
  /**
   * The signed jurisdiction (ISO 3166-1 alpha-2, sent upper-case). Absent (undefined/null) = the v1 eight-field message;
   * present = the v2 message above, signed as the literal string transmitted (§8.3.5).
   */
  jurisdiction?: string | null;
}

/**
 * Escape `\` and `|` in a field's string form so it can never be mistaken for the `|`
 * delimiter or another escape sequence. Without this, a field containing a literal `|`
 * (e.g. a merchant name an LLM agent extracted from untrusted content) could shift where
 * a verifier reads the NEXT field's boundary — two structurally different field-tuples
 * joining to byte-identical bytes would be indistinguishable to a verifier that only
 * checks the joined string, even though Ed25519 itself still only accepts the exact bytes
 * that were actually signed. A no-op for every value that contains neither character —
 * every real agentDid/action/currency/nonce/timestamp today — so this changes nothing for
 * existing traffic and only activates for the case it exists to close.
 */
export function escapeField(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

/** Build the canonical UTF-8 message a verifier reconstructs from received fields. */
export function buildAuthMessage(f: AuthMessageFields): string {
  const v1 = [f.agentDid, f.action, f.amount, f.currency, f.merchant ?? '', f.resource ?? '', f.nonce, f.issuedAt];
  const fields = f.jurisdiction === undefined || f.jurisdiction === null ? v1 : [...v1, AUTH_MESSAGE_V2_TAG, f.jurisdiction];
  return fields.map((v) => escapeField(String(v))).join('|');
}

/**
 * The PRE-`resource` (seven-field) canonical message this repo signed before the 7→8 field
 * change documented above. Exists ONLY so the gate can tell a genuinely-invalid signature
 * apart from a still-valid keypair on an SDK old enough to predate `resource` (see
 * mandate.service.ts's SIGNATURE_INVALID handling: a request that verifies against THIS but
 * not `buildAuthMessage` gets a `CLIENT_PROTOCOL_VERSION_UNSUPPORTED` diagnosis instead of
 * the generic, misleading `SIGNATURE_INVALID` a rotated/broken key also produces). A match
 * here is NEVER treated as authorization — the caller still blocks either way; the old
 * message has no slot for a signed resource-scope commitment, so it cannot prove one.
 */
export function buildLegacyAuthMessageV1(f: Omit<AuthMessageFields, 'resource'>): string {
  return [f.agentDid, f.action, f.amount, f.currency, f.merchant ?? '', f.nonce, f.issuedAt]
    .map((v) => escapeField(String(v)))
    .join('|');
}

/**
 * Canonical signed-message builder for a local-mode guard's "local decision receipt"
 * (docs: local-first SDK mode audit visibility). Signed by the agent's own key over
 * agentDid|action|decision|reasonCode|nonce|issuedAt — a DIFFERENT field shape than
 * AuthMessageFields (6 fields here vs. 8 there), so once `escapeField` is applied a
 * receipt signed for this message can never reconstruct to the same bytes as a real
 * authorize() message (and vice versa) — the same domain-separation-by-field-shape
 * `buildCheckpointAnchorMessage` (checkpoint-anchor.ts) already relies on, no new
 * machinery. `decision`/`reasonCode` MUST be signed fields, not just carried unsigned
 * on the wire — otherwise a captured, validly-signed receipt could be resubmitted with
 * a different decision/reasonCode and still verify, corrupting the very audit trail
 * this exists to provide.
 */
export interface LocalDecisionMessageFields {
  agentDid: string;
  action: string;
  decision: string;
  reasonCode: string;
  nonce: string;
  issuedAt: string;
}

/** Build the canonical UTF-8 message a verifier reconstructs from received fields. */
export function buildLocalDecisionMessage(f: LocalDecisionMessageFields): string {
  return [f.agentDid, f.action, f.decision, f.reasonCode, f.nonce, f.issuedAt]
    .map((v) => escapeField(String(v)))
    .join('|');
}

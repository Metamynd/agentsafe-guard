/**
 * Canonical signed-message builder (spec §7.3).
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
 */

export interface AuthMessageFields {
  agentDid: string;
  action: string;
  amount: number | string;
  currency: string;
  merchant?: string | null;
  resource?: string | null;
  nonce: string;
  issuedAt: string;
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
  return [f.agentDid, f.action, f.amount, f.currency, f.merchant ?? '', f.resource ?? '', f.nonce, f.issuedAt]
    .map((v) => escapeField(String(v)))
    .join('|');
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

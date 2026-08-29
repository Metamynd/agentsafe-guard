/**
 * Canonical signed-message builder (spec §7.3).
 *
 * The authorize `signature` is an Ed25519 signature over the UTF-8 string formed
 * by joining these seven fields, in this exact order, with the `|` (U+007C)
 * delimiter, substituting the empty string for an absent merchant:
 *
 *   agentDid | action | amount | currency | merchant | nonce | issuedAt
 *
 * This lives in policy-core (not the gate) so BOTH signer and verifier build the
 * identical bytes — the agent guard signs it, the backend gate reconstructs and
 * verifies it, and any third-party guard does the same. Signature verification
 * itself stays OUT of policy-core (it needs the key, not the evaluator).
 */

export interface AuthMessageFields {
  agentDid: string;
  action: string;
  amount: number | string;
  currency: string;
  merchant?: string | null;
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
function escapeField(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

/** Build the canonical UTF-8 message a verifier reconstructs from received fields. */
export function buildAuthMessage(f: AuthMessageFields): string {
  return [f.agentDid, f.action, f.amount, f.currency, f.merchant ?? '', f.nonce, f.issuedAt]
    .map((v) => escapeField(String(v)))
    .join('|');
}

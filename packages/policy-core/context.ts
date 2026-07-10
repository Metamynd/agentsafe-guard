/**
 * Request-context construction with the signed-field-shadowing defence
 * (spec §6.4.2, §11.5).
 *
 * The request context is the union of a caller-supplied unsigned object
 * (transported as `itinerary`) and the SIGNED request fields. Signed fields MUST
 * be applied LAST so an attacker cannot shadow a signed value (e.g. `amount`,
 * `merchant`) with a colliding unsigned key and slip a cheaper amount or an
 * allowed merchant past the rules. Every context-building path — the Standards/
 * SOP evaluation context and the ODRL mandate `values` — MUST go through this so
 * the invariant holds identically on the gate and on every guard.
 */

/**
 * Merge unsigned caller context with signed fields, signed winning on collision.
 * Pure: returns a new object; inputs are not mutated.
 */
export function applySignedLast<T extends Record<string, unknown>>(
  unsigned: Record<string, unknown> | null | undefined,
  signed: T,
): Record<string, unknown> & T {
  return { ...(unsigned ?? {}), ...signed };
}

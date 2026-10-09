/**
 * Jurisdiction group codes, shared by the mandate's allowed-jurisdictions term (features/policy/mandate/jurisdiction.ts,
 * which expands a group at ISSUANCE) and the `jurisdiction-not-allowed` atom (atom-registry.ts, which expands it at
 * EVALUATION, since an SOP or Standard stores the list as authored).
 *
 * "EU" is an ISO 3166-1 exceptionally-reserved code, not a country, so no request signs it for a member state: a request
 * from France signs FR. Before this, the atom compared "EU" literally, so a rule allowing ['GB', 'EU'] refused FR — while
 * the mandate's own term, given the same list, allowed it (beta regression follow-up, 2026-10-09).
 */

/** The 27 EU member states as of 2026 (Greece is ISO `GR`, not the EU-internal `EL`). */
export const EU_MEMBER_STATES: readonly string[] = Object.freeze([
  'AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GR', 'HR', 'HU',
  'IE', 'IT', 'LT', 'LU', 'LV', 'MT', 'NL', 'PL', 'PT', 'RO', 'SE', 'SI', 'SK',
]);

/** Group code (upper-case) → its member codes. */
export const JURISDICTION_GROUPS: Readonly<Record<string, readonly string[]>> = Object.freeze({ EU: EU_MEMBER_STATES });

/**
 * An allow-list with every group code ADDED to by its members, compared case-insensitively. The group code itself is
 * kept, so a request that literally signs "EU" matches as it did before: this only ever widens a list to what its
 * author meant, never narrows one.
 */
export function expandJurisdictionGroups(list: readonly unknown[]): string[] {
  const out = new Set<string>();
  for (const raw of list) {
    const code = String(raw).trim().toUpperCase();
    out.add(code);
    const group = Object.prototype.hasOwnProperty.call(JURISDICTION_GROUPS, code) ? JURISDICTION_GROUPS[code] : undefined;
    group?.forEach((c) => out.add(c));
  }
  return [...out];
}

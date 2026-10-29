// Types for access-context.mjs (identical in agentsafe-mcp-guard and agentsafe-http-gateway).

export interface AccessPrincipal {
  tenantId?: string | number;
  userId?: string | number;
}

export interface AccessPolicy {
  tenant?: string[];
  user?: string[];
  principal: AccessPrincipal | ((...args: any[]) => AccessPrincipal | Promise<AccessPrincipal>);
}

export interface AccessRefusal {
  reasonCode: 'ACCESS_CONTEXT_MISMATCH' | 'ACCESS_CONTEXT_UNCHECKABLE';
  /** Built from the configured pointer: array indices filled in, object keys a `*` matched left as `*`. Never a value. */
  path: string;
  kind?: 'tenant' | 'user';
  detail?: string;
}

export function parseAccessPointer(pointer: unknown): string[] | null;
export function valuesAt(body: unknown, segments: string[]): { values: Array<{ path: string; value: unknown }> } | { missing: string } | { tooLarge: true };
export function assertAccessPolicy(holder: { access?: AccessPolicy; method?: string; path?: string } | null | undefined, where?: string): void;
export function resolveAccessPrincipal(holder: { access: AccessPolicy }, ...args: any[]): Promise<AccessPrincipal>;
export const ACCESS_REASON_CODES: readonly ['ACCESS_PRINCIPAL_UNAVAILABLE', 'ACCESS_CONTEXT_MISMATCH', 'ACCESS_CONTEXT_UNCHECKABLE'];
/** Null when every named field names the principal. `body` is parsed JSON. */
export function checkAccessContext(body: unknown, access: Pick<AccessPolicy, 'tenant' | 'user'>, principal: AccessPrincipal): AccessRefusal | null;
export function checkAccessValue<T>(value: T, access: Pick<AccessPolicy, 'tenant' | 'user'>, principal: AccessPrincipal): { refusal: AccessRefusal | null; value?: unknown };

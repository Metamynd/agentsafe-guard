// Type declarations for @metamynd/agentsafe-mcp-guard (0.31.0), as .d.mts: the declarations of an ES module
// (agentsafe-mcp-guard.mjs). Hand-written: the package ships plain ESM with no build step and had no types
// before these. They cover the public surface a Service uses; fields the issuer may add later
// are allowed through ([key: string]: unknown).

/** MAGP §6 dispositions. A verdict that is neither `allow` nor `observe` is a refusal (§13.3). */
export type Decision = 'allow' | 'observe' | 'escalate' | 'block' | 'suspend' | 'quarantine' | 'decommission';

/** A signed MAGP request as the agent sent it (the `x-magp-request` header's JSON). */
export interface SignedRequest {
  agentDid: string;
  action: string;
  nonce: string;
  issuedAt: string;
  signature: string;
  amount?: number;
  currency?: string;
  merchant?: string;
  resource?: string;
  jurisdiction?: string;
  authorizationId?: string;
  payloadDigest?: string;
  payloadSignature?: string;
  envelopeSignature?: string;
  itinerary?: Record<string, unknown>;
  [key: string]: unknown;
}

/** What verifyRequest answers. On a permit under requireAuthorization, the claimed hold and how to settle it. */
export interface ServiceVerdict {
  decision: Decision;
  reasonCode: string;
  authorizationId?: string | null;
  /** An anonymous claim's bearer token for settling; absent when the Service signs as its own DID. */
  claimToken?: string;
  counterpartyAuthenticated?: boolean;
  detail?: string;
  /** On an argument refusal: the JSON Pointer of the offending argument. */
  path?: string;
  /**
   * On a permit under an argument policy (the mandate's `arguments`): the arguments to run with, sensitive values redacted
   * or keyed-hashed. Absent when the action has no policy. Non-enumerable.
   */
  arguments?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface VerifyOptions {
  /** What the Service knows about this call (e.g. `{ riskLevel: 'high' }`), applied over the agent's word. */
  trustedContext?: Record<string, unknown>;
  /** sha256 digest of the payload this Service is about to execute (payload binding, §8.3.9). */
  payloadDigest?: string;
  requirePayloadBinding?: boolean;
  requireContextSignature?: boolean;
  x402?: boolean;
  /** A narrower allow-list for this call (a credential profile, §16.3). */
  allowedAgents?: string[];
  /**
   * The call's arguments, checked against the owner's argument policy when the mandate sets one (a call under a policy that
   * passes none is refused, ARGUMENTS_UNCHECKABLE). guardIncomingTool passes its single argument itself.
   */
  arguments?: unknown;
}

export interface GuardIncomingToolOptions extends Omit<VerifyOptions, 'payloadDigest' | 'arguments'> {
  /** Capture the claimed hold when the handler returns; mark it unknown when it throws. */
  settle?: boolean;
  /** Digest the single argument after the signed request (true), or say what to digest. */
  bindPayload?: boolean | ((...args: any[]) => unknown);
  /**
   * Withhold an answer that holds another tenant's or user's records (0.33.0). The handler's result is released only when
   * every named field (JSON Pointers into its JSON form, `*` any key or index) names the principal; otherwise the call
   * throws GovernanceBlocked with `executed: true`.
   */
  access?: ToolAccess;
  /**
   * Forbidden words (0.34.0). The tool runs only when no string in its argument (the first after the signed request), value
   * or key, has one of them, matched as whole words after folding (NFKC + case). Otherwise the call throws GovernanceBlocked
   * with `OUTPUT_FORBIDDEN_WORD` (or `OUTPUT_UNCHECKABLE`), the `path` of the string, never the word, and `executed: false`;
   * a hold this guard settles (`settle: true`) is released, and one it does not settle is left to its owner. The handler
   * receives the JSON snapshot of the argument that was checked.
   */
  output?: ToolOutput;
}

export interface ToolOutput {
  /** Each exactly one word; a phrase is refused when the tool is wrapped. */
  forbidden: string[];
}

/** The principal a call is served for. Never from anything the agent sends: it controls its own request. */
export interface AccessPrincipal {
  tenantId?: string | number;
  userId?: string | number;
}

export interface ToolAccess {
  tenant?: string[];
  user?: string[];
  /** Fixed for a Service dedicated to one principal, or resolved per call (after verification) from what the operator trusts. */
  principal: AccessPrincipal | ((signed: SignedRequest, ...args: any[]) => AccessPrincipal | Promise<AccessPrincipal>);
}

/**
 * The error a guarded handler throws on a refusal. The handler did not run, except when `governance.executed` is true:
 * an `access` check withheld the answer of a handler that did.
 */
export interface GovernanceBlocked extends Error {
  name: 'GovernanceBlocked';
  governance?: ServiceVerdict;
  [key: string]: unknown;
}

export interface SettlementResult {
  ok: boolean;
  reasonCode?: string;
  status?: number;
  [key: string]: unknown;
}

export interface ReportOutcomeInput {
  signed: SignedRequest;
  outcome: 'executed' | 'refused';
  reasonCode: string;
  httpStatus?: number | null;
  servedAgentDid?: string;
  reportId?: string;
  occurrences?: number;
  claimedAuthorizationId?: string;
}

export interface BundleCacheOptions {
  maxAgeMs?: number;
  maxAgents?: number;
  watch?: boolean;
}

export interface McpGuardOptions {
  /** This Service's own DID (did:key or did:hedera). Required. */
  serviceDid: string;
  /** This Service's Ed25519 key (PKCS#8 DER hex). Or a keyProvider / daemon. */
  serviceKey?: string;
  keyProvider?: unknown;
  daemonSocketPath?: string;
  /** The issuer API, e.g. https://metamynd.ai/api/v1. */
  issuerApi?: string;
  fetchBundle?: (agentDid: string) => Promise<Record<string, unknown>>;
  bundleCache?: boolean | BundleCacheOptions;
  /** MetaMynd's policy-signing key (hex, GET /magp/policy/pubkey). */
  policyPublicKey?: string;
  allowUnverifiedBundle?: boolean;
  settlementStore?: unknown;
  verifyCapability?: (...args: any[]) => unknown;
  requireAuthorization?: boolean;
  requireCapability?: boolean;
  requireContextSignature?: boolean;
  /** The agent DIDs this Service acts for, or 'any' (§16.3). */
  allowedAgents?: string[] | 'any';
  /** The principal DID that owns this Service's credentials (§16.3). */
  gatewayOwnerPrincipal?: string;
  honourApprovals?: boolean;
  /** Key for argument hashes (`sensitive: hmac`), at least 32 bytes. Without it such a call is refused. */
  argumentKey?: string | Uint8Array;
}

export interface McpGuard {
  readonly serviceDid: string;
  readonly allowedAgents: readonly string[] | 'any';
  readonly gatewayOwnerPrincipal: string | null | undefined;
  readonly honoursApprovals: boolean;
  /** This guard enforces a mandate's argument policy (0.32.0). */
  readonly checksArguments: true;
  verifyRequest(signed: SignedRequest, opts?: VerifyOptions): Promise<ServiceVerdict>;
  /** Wrap a tool handler: it runs only on a permit, with the signed request as its first argument. */
  guardIncomingTool<Args extends unknown[], R>(
    action: string,
    handler: (signed: SignedRequest, ...args: Args) => R | Promise<R>,
    opts?: GuardIncomingToolOptions,
  ): (signed: SignedRequest, ...args: Args) => Promise<Awaited<R>>;
  claimAuthorization(input: { authorizationId: string; payloadDigest?: string; x402?: boolean; requireHumanApproval?: boolean; expect?: Record<string, unknown> }): Promise<ServiceVerdict>;
  captureAuthorization(input: { authorizationId: string; claimToken?: string; amountCharged: number; bookingRef?: string; settlementTxHash?: string; payTo?: string }): Promise<SettlementResult>;
  releaseAuthorization(input: { authorizationId: string; claimToken?: string; reason?: string }): Promise<SettlementResult>;
  markAuthorizationUnknown(input: { authorizationId: string; reason?: string; claimToken?: string }): Promise<SettlementResult>;
  refundAuthorization(input: { authorizationId: string; amount: number; reason?: string; claimToken?: string }): Promise<SettlementResult>;
  lookupOutcome(input: { authorizationId: string }): Promise<Record<string, unknown>>;
  reportOutcome(input: ReportOutcomeInput): Promise<{ ok: boolean; reasonCode?: string; status?: number; reportId?: string }>;
  /** Sign the Trusted Counterparties registration challenge as this Service (returns 128-hex). */
  acceptCounterpartyChallenge(message: string): Promise<string>;
  handshakeChallenge(input: { fromDid: string; nonceA: string; protoVersion?: string }): Promise<Record<string, unknown>>;
  handshakeVerify(input: { handshakeId: string; sigA: string }): Record<string, unknown>;
  requirePayment(p: { authorizationId: string; agentDid: string; amount: number; payTo: string; asset: string; resource: string; network?: string; decimals?: number }): Record<string, unknown>;
  settle(input: { requirements: Record<string, unknown>; authorizationId: string; paidAmountMinor: number; xPayment?: unknown; settleFn: (...args: any[]) => Promise<{ settled: boolean; txHash?: string }> }): Promise<{ settled: boolean; txHash?: string; reasonCode: string; error?: string }>;
  invalidateBundle(agentDid?: string): void;
  close(): void;
}

export function createMcpGuard(opts: McpGuardOptions): McpGuard;
export function createHandshakeInitiator(input: { fromDid: string; sign: (msg: string) => string | Promise<string> }): {
  hello(): { nonceA: string; message: Record<string, unknown> };
  prove(input: { nonceA: string; challenge: Record<string, unknown> }): Promise<Record<string, unknown>>;
};

export function agentAllowList(allowedAgents: string[] | 'any' | undefined, label: string): { serves(agentDid: string): boolean; pinned: readonly string[] | 'any' };
export function gatewayOwnerFor(pinned: readonly string[] | 'any', gatewayOwnerPrincipal: string | undefined, label: string): string | null;
export function assertProfileAgents(list: unknown, where: string): void;
export function profileAdmits(list: string[] | undefined, agentDid: string): boolean;

export const JURISDICTION_REASON_CODES: readonly string[];
export const CONTEXT_SIGNATURE_REASON_CODES: readonly string[];
export const HANDSHAKE_NONCE: RegExp;
export const PAYLOAD_DIGEST_HEADER: string;
export class PayloadNotCanonicalizable extends Error {}
export function canonicalPayload(payload: unknown): string;
export function payloadDigestOf(payload: unknown): string;
export function isPayloadDigest(value: unknown): value is string;
export function toWireJson(value: unknown): unknown;
export function keepAliveFetch(input: string | URL, init?: Record<string, unknown>): Promise<Response>;

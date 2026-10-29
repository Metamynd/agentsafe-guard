// Type declarations for @metamynd/agentsafe-http-gateway (0.31.1), as .d.mts: the declarations of an ES module
// (gateway.mjs). Hand-written: the package ships plain ESM with no build step and had no types
// before these. route-match.d.mts and service-identity.d.mts declare the other entry points.

// The guard shapes the gateway relies on, declared here so these types stand alone whatever agentsafe-mcp-guard version
// is installed (its own declarations, 0.31.0+, are a superset).
export interface SignedRequest {
  agentDid: string;
  action: string;
  nonce: string;
  issuedAt: string;
  signature: string;
  authorizationId?: string;
  [key: string]: unknown;
}

export interface ServiceVerdict {
  decision: 'allow' | 'observe' | 'escalate' | 'block' | 'suspend' | 'quarantine' | 'decommission';
  reasonCode: string;
  authorizationId?: string | null;
  claimToken?: string;
  counterpartyAuthenticated?: boolean;
  detail?: string;
  [key: string]: unknown;
}

/** What the gateway needs of its guard: createMcpGuard() from @metamynd/agentsafe-mcp-guard provides all of it. */
export interface GatewayGuard {
  // Inputs are `any`, not Record<string, unknown>: a guard's own input types (agentsafe-mcp-guard's ReportOutcomeInput,
  // VerifyOptions, ...) are interfaces, which TypeScript does not treat as assignable to a Record, so
  // createHttpGateway({ guard: createMcpGuard(...) }) failed to compile under --strict in 0.31.0.
  verifyRequest(signed: SignedRequest, opts?: any): Promise<ServiceVerdict>;
  /** True when the guard enforces a mandate's argument policy on the body it is handed (agentsafe-mcp-guard >= 0.32.0). */
  readonly checksArguments?: boolean;
  reportOutcome?(input: any): Promise<{ ok: boolean; reasonCode?: string; status?: number; reportId?: string }>;
  captureAuthorization?(input: any): Promise<{ ok: boolean; [key: string]: unknown }>;
  releaseAuthorization?(input: any): Promise<{ ok: boolean; [key: string]: unknown }>;
  markAuthorizationUnknown?(input: any): Promise<{ ok: boolean; [key: string]: unknown }>;
}

/** The request the gateway is handed (server.mjs builds it from node:http). */
export interface GatewayRequest {
  method: string;
  /** Path with any query string, e.g. `/payments` or `/payments?id=1`. */
  path: string;
  headers: Record<string, string | string[] | undefined>;
  /**
   * The raw body; the payload binding digests exactly these bytes. A Node Buffer is a Uint8Array, so it fits. Declared
   * without Node's types (0.32.4): TypeScript 6+ loads them only when a project asks, and `Buffer` here broke the rest.
   */
  rawBody?: Uint8Array;
  body?: unknown;
  [key: string]: unknown;
}

/** What the gateway answers: the upstream's response, or its own refusal. */
export interface GatewayResponse {
  status: number;
  headers?: Record<string, string>;
  body?: unknown;
  rawBody?: Uint8Array;
  /** The guard's verdict, when the guard was asked. */
  governance?: ServiceVerdict;
  [key: string]: unknown;
}

/** A governed route. Unmatched paths pass through, unless `denyByDefault`. */
export interface Route {
  method?: string;
  /** `*` = one segment, `**` = the rest. */
  path: string;
  /** The governed action this route pins; a request signed for another is refused GATEWAY_ACTION_MISMATCH. */
  action?: string;
  /** The body fields the signature must cover (amount, currency, merchant). `[]` for a value-less route. */
  valueFields?: string[];
  /** The body fields the route accepts; anything else is refused PAYLOAD_UNBINDABLE. */
  allowedFields?: string[];
  /** Query keys forwarded unbound (never a signed value field). */
  allowedQuery?: string[];
  bind?: false | ((req: GatewayRequest, signed: SignedRequest, route: Route) => unknown);
  extract?: (req: GatewayRequest) => SignedRequest | null | undefined;
  /** What this route knows about its own action, applied over the agent's word (e.g. `{ riskLevel: 'high' }`). */
  trustedContext?: Record<string, unknown> | ((request: SignedRequest, req: GatewayRequest) => Record<string, unknown> | Promise<Record<string, unknown>>);
  requirePayloadBinding?: boolean;
  requireContextSignature?: boolean;
  /** A narrower allow-list for this route (a credential profile, §16.3). */
  allowedAgents?: string[];
  /** `false`: this route needs no upstream credential. */
  credential?: false;
  x402?: boolean;
  /**
   * The access check on what the upstream returns: a 2xx JSON answer is released only when every field at `tenant` /
   * `user` (JSON Pointers, `*` for any key or index) names the principal the request is served for. Otherwise 502
   * ACCESS_CONTEXT_MISMATCH or ACCESS_CONTEXT_UNCHECKABLE, with the failing path and never the value.
   */
  access?: RouteAccess;
  [key: string]: unknown;
}

/** The principal a request is served for. Never from anything the agent sends: it controls its own headers and body. */
export interface AccessPrincipal {
  tenantId?: string | number;
  userId?: string | number;
}

export interface RouteAccess {
  tenant?: string[];
  user?: string[];
  /** Fixed for a gateway dedicated to one principal, or resolved per request from what the operator trusts. */
  principal: AccessPrincipal | ((request: SignedRequest, req: GatewayRequest) => AccessPrincipal | Promise<AccessPrincipal>);
}

export interface UpstreamCredential {
  header: string;
  value: string;
}

export interface HttpGatewayOptions {
  /** The guard that verifies each request (createMcpGuard). */
  guard: GatewayGuard;
  routes?: Route[];
  /** Send a permitted request upstream. */
  forward: (req: GatewayRequest) => Promise<GatewayResponse>;
  extractGovernance?: (req: GatewayRequest) => SignedRequest | null | undefined;
  denyByDefault?: boolean;
  bind?: false | ((req: GatewayRequest, signed: SignedRequest, route: Route) => unknown);
  /** The credential added to a permitted call (never seen by the agent). No credential = the call is refused. */
  resolveCredential?: (ctx: { request: SignedRequest; route: Route; decision: ServiceVerdict }) => UpstreamCredential | null | undefined | Promise<UpstreamCredential | null | undefined>;
  settle?: boolean;
  releaseOnStatus?: number[];
  requirePayloadBinding?: boolean;
  requireContextSignature?: boolean;
  settleInBackground?: boolean;
  settleRetryDelaysMs?: number[];
  /** Report what the gateway executed without a claim and what it refused itself to the owner's audit trail. Default true (0.32.0); false opts out. */
  reportOutcomes?: boolean;
  reportSpool?: string;
  reportSpoolRetryMs?: number;
  refusalWindowMs?: number;
  /** Release the claimed hold when forward() throws a connect failure (nothing was sent). Default true (0.32.2). */
  releaseOnConnectFailure?: boolean;
}

/** The gateway: call it with each request. */
export interface HttpGateway {
  (req: GatewayRequest): Promise<GatewayResponse>;
  flushReports(): Promise<number>;
  pendingSettlements(): number;
  drainSettlements(timeoutMs?: number): Promise<unknown>;
}

export function createHttpGateway(opts: HttpGatewayOptions): HttpGateway;

export const BOUND_FIELDS: readonly string[];
export const DEFAULT_ALLOWED_FIELDS: readonly string[];
export const UNBINDABLE: unique symbol;
export function defaultExtractGovernance(req: GatewayRequest): SignedRequest | null;
export function defaultBindPayload(req: GatewayRequest, signed: SignedRequest, route: Route): unknown;
export function boundValueMatches(field: string, signedValue: unknown, payloadValue: unknown): boolean;
export function executedPayloadDigest(req: GatewayRequest, route: Route): { digest?: string; error?: unknown };
export function queryRefusal(path: string, route: Route): string | null;
export const CONNECT_FAILURE_CODES: readonly string[];
export function connectFailureCode(err: unknown): string | null;
export function requestNeverSent(err: unknown): boolean;
export function parseStrictJson(text: string): unknown;
export function keepAliveFetch(input: string | URL, init?: Record<string, unknown>): Promise<Response>;

// Type declarations for @metamynd/agentsafe-guard (0.36.0), as .d.mts: the declarations of an ES module (agentsafe-guard.mjs). Hand-written against agentsafe-guard.mjs: the package ships
// plain ESM with no build step, and had no types at all (pre-beta evaluation 2026-10-09, L5d). They cover the public
// surface a TypeScript agent uses; fields the issuer may add later are allowed through ([key: string]: unknown).

/** MAGP §6 dispositions. A verdict that is neither `allow` nor `observe` is a refusal (§13.3). */
export type Decision = 'allow' | 'observe' | 'escalate' | 'block' | 'suspend' | 'quarantine' | 'decommission';

/** What the gate (or a local evaluation) answered. `reasonCode` is the stable code; branch on it, never on prose. */
export interface Verdict {
  decision: Decision;
  reasonCode: string;
  /** The hold a permit reserved; settle it with capture/void (guardTool does it for you). */
  authorizationId?: string | null;
  /** The handle for a held action: waitForEscalation / guardTool's .resume. */
  escalationId?: string | null;
  /** The anchored evidence event for this decision (proof()). */
  eventId?: string | null;
  remaining?: number | null;
  hint?: string;
  detail?: string;
  error?: string;
  payloadDigest?: string;
  riskSignals?: unknown[];
  [key: string]: unknown;
}

/** The fields an authorize request carries. `action` is the mandate's action key. */
export interface AuthorizeRequest {
  action: string;
  amount?: number;
  currency?: string;
  merchant?: string;
  resource?: string;
  /** ISO 3166-1 alpha-2, signed (MAGP §8.3.12). A jurisdiction in `context` is ignored. */
  jurisdiction?: string;
  /** What the rules read: `riskLevel` ('low' | 'medium' | 'high' | 'critical'), `tool`, ... */
  context?: Record<string, unknown>;
  trace?: unknown;
  materiality?: unknown;
  /** The complete payload the tool will execute; digested and signed so a service is held to it (§8.3.9). */
  payload?: unknown;
}

/** What a tool's arguments map to: everything an AuthorizeRequest carries but the action, which the tool names. */
export type MappedRequest = Omit<AuthorizeRequest, 'action'>;

/** A request signed for a gateway or MCP server to re-verify (the `x-magp-request` header's JSON). */
export interface SignedRequest {
  agentDid: string;
  action: string;
  nonce: string;
  issuedAt: string;
  signature: string;
  authorizationId?: string;
  [key: string]: unknown;
}

/** The decision a guarded tool's handler receives. */
export interface ToolDecision extends Verdict {
  /** Headers that hand THIS permitted call to a MAGP gateway: `{ 'x-magp-request': ... }` (0.31.0). */
  governanceHeaders(): Promise<Record<string, string>>;
}

/** The error a guarded tool throws on a refusal. `governance` is the verdict. The tool did not run. */
export interface GovernanceBlocked extends Error {
  name: 'GovernanceBlocked';
  governance: Verdict;
  raisedByGuard?: boolean;
}

export interface ExecutionContext<A = unknown> {
  action: string;
  args: A;
  decision: ToolDecision;
  proceed(): unknown;
}
export type ExecutionAdapter = <A>(ctx: ExecutionContext<A>) => unknown;

export interface GuardToolOptions {
  executionAdapter?: ExecutionAdapter;
  /** 'capture' (default): capture the hold when the tool returns. 'none': leave it. */
  settle?: 'capture' | 'none';
  /** Release the hold when the tool throws: true, or decide per error. Default: only when nothing can have run. */
  releaseOnError?: boolean | ((err: unknown) => boolean);
}

/** A guarded tool: call it like the handler; `.resume` runs an approved escalation once with the same arguments. */
export interface GuardedTool<A, R> {
  (args: A): Promise<R>;
  resume(escalationId: string, args: A, opts?: { timeoutMs?: number; intervalMs?: number }): Promise<R>;
}

export interface SettlementResult {
  ok: boolean;
  reasonCode?: string;
  [key: string]: unknown;
}

export interface EscalationStatus {
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'modified' | string;
  reasonCode?: string;
  authorizationId?: string | null;
  [key: string]: unknown;
}

export interface KeyProvider {
  signAuthorize(fields: Record<string, unknown>): Promise<string>;
  [method: string]: unknown;
}

export interface GuardOptions {
  /** The issuer API, e.g. https://metamynd.ai/api/v1 (or `config.apiBase`). */
  api?: string;
  agentDid?: string;
  /** The agent's key (DER PKCS#8 hex from agent.metamynd.json). Or a keyProvider. */
  agentKey?: string;
  keyProvider?: KeyProvider | 'daemon' | { type: 'daemon'; socketPath?: string };
  daemonSocketPath?: string;
  /** A portable agent config (agent.metamynd.json's contents) or its path. Explicit fields win. */
  config?: Record<string, unknown>;
  configPath?: string;
  /** 'remote' (default) asks the gate; 'local' evaluates the signed bundle offline. */
  mode?: 'remote' | 'local' | string;
  executionAdapter?: ExecutionAdapter;
  /** Sign the request's context (default true since 0.17.0). */
  signContext?: boolean;
  [key: string]: unknown;
}

export interface Guard {
  readonly agentDid: string;
  readonly mode: string;
  readonly executionAdapter: ExecutionAdapter;
  authorize(request: AuthorizeRequest): Promise<Verdict>;
  buildSignedRequest(request: AuthorizeRequest): Promise<SignedRequest>;
  guardTool<A = any, R = unknown>(
    action: string,
    handler: (args: A, decision: ToolDecision) => R | Promise<R>,
    mapArgs?: (args: A) => MappedRequest,
    opts?: GuardToolOptions,
  ): GuardedTool<A, Awaited<R>>;
  capture(authorizationId: string, amountCharged: number, bookingRef?: string, settlementTxHash?: string): Promise<SettlementResult>;
  void(authorizationId: string, reason?: string): Promise<SettlementResult>;
  bindPayload(input: { authorizationId: string; action: string; payload: unknown }): Promise<Record<string, unknown>>;
  waitForEscalation(escalationId: string, opts?: { timeoutMs?: number; intervalMs?: number }): Promise<EscalationStatus>;
  escalationStatus(escalationId: string): Promise<EscalationStatus>;
  proof(eventId: string): Promise<Record<string, unknown>>;
  check(input: AuthorizeRequest): Promise<Verdict>;
  authorizeLocal(input: AuthorizeRequest): Verdict;
  evaluateLocally(input: Record<string, unknown>): Verdict;
  guardToolLocal<A = any, R = unknown>(
    action: string,
    handler: (args: A, decision: ToolDecision) => R | Promise<R>,
    mapArgs?: (args: A) => MappedRequest,
    getBundle?: unknown,
    opts?: GuardToolOptions,
  ): (args: A) => Promise<Awaited<R>>;
  loadBundle(force?: boolean): Promise<Record<string, unknown>>;
  watchPolicy(onChange: (bundle: Record<string, unknown>) => void): () => void;
  verifyOnChain(...args: unknown[]): Promise<unknown>;
  handshake(): Record<string, unknown>;
  preparePayment(requirements: unknown, expectedAuthorizationId?: string): unknown;
  effectDispatching(...args: unknown[]): Promise<unknown>;
  effectDispatched(...args: unknown[]): Promise<unknown>;
  effectUnknown(authorizationId: string, reason?: string): Promise<unknown>;
  effectStatus(authorizationId: string): Promise<unknown>;
  verifyKey(input?: { ref?: string; challenge?: string; token?: string }): Promise<unknown>;
  signChallenge(challenge: string): Promise<string>;
  readonly policyAnchor: unknown;
}

export function createGuard(opts?: GuardOptions): Guard;
/** Build a guard from agent.metamynd.json (a path, an https URL, or the parsed object). `passphrase` opens an encrypted key. */
export function createGuardFromConfig(source: string | Record<string, unknown>, overrides?: GuardOptions & { passphrase?: string }): Promise<Guard>;

export const JURISDICTION_REASON_CODES: readonly string[];
export const CONTEXT_SIGNING_REASON_CODES: readonly string[];
export const HANDSHAKE_NONCE: RegExp;
export function normalizeJurisdiction(value: unknown): string | undefined;
export function derivedRiskNote(decision: Verdict): string;
export function localReceiptDetailOf(request?: Record<string, unknown>): Record<string, unknown>;
export const liveExecutionAdapter: ExecutionAdapter;
export const dryRunExecutionAdapter: ExecutionAdapter;
export function executionAdapterFromEnv(env?: Record<string, string | undefined>): ExecutionAdapter | undefined;
export function keepAliveFetch(input: string | URL, init?: Record<string, unknown>): Promise<Response>;

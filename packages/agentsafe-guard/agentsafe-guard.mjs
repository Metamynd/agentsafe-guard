// agentsafe-guard.mjs — drop-in runtime governance for any Node agent (OpenClaw, LangChain, custom).
//
// ZERO external dependencies: uses Node's built-in Ed25519 (node:crypto) + fetch (Node 18+),
// plus policy-core.mjs (the deterministic evaluator, itself dependency-free, generated from
// backend/src/policy-core). Before an agent performs a governed action the guard can either
// call the AgentSafe authorize gate (trustless fallback) OR evaluate a signed policy bundle
// LOCALLY (spec §9.2 cooperative mode) — both compute the identical allow/block/escalate
// verdict from the identical inputs, because they run the same policy-core.
//
// The agent's private key is a Hedera Ed25519 DER key (the AGENT_KEY the seed prints).
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve as resolvePath } from 'node:path';
import { evaluate, buildAuthMessage, applySignedLast, operatingModeGate, buildRuleContext, riskFloorFor, effectiveRiskFloor, maxRisk, normalizeRiskLevel, documentEnforcesJurisdiction } from './policy-core.mjs';
import { envelopeHashFor } from './governance-envelope.mjs';
import { payloadDigestOf, toWireJson } from './payload-binding.mjs';
import { approvedContextDigest, resumeRequestDigest } from './resume-binding.mjs';
import { verifyDidSignature } from './magp-did.mjs';
import { checkSettlementBinding } from './x402.mjs';
import { resolveKeyProvider, decryptAgentKeyWithPassword } from './key-providers.mjs';
// fetch() with a 60 s keep-alive (metamynd.ai sits behind Cloudflare, which strips the Keep-Alive header, so the built-in
// fetch would drop an idle connection after 4 s) — see keepalive-fetch.mjs.
import { keepAliveFetch as fetch } from './keepalive-fetch.mjs';
/** The same keep-alive fetch, for an agent's own calls to metamynd.ai (or anywhere) — reuses warm connections. */
export { keepAliveFetch } from './keepalive-fetch.mjs';

/**
 * The jurisdiction refusals the gate can answer (spec §8.3.12), all hard blocks:
 *   - JURISDICTION_REQUIRED    the mandate restricts jurisdictions (or an enforced SOP/Standard rule reads one) and the
 *                              request signed none (and the payee has no registered country);
 *   - JURISDICTION_NOT_ALLOWED the signed jurisdiction is not on the mandate's allow-list;
 *   - JURISDICTION_MISMATCH    the payee's REGISTERED country differs from the signed one (the registry wins).
 */
export const JURISDICTION_REASON_CODES = Object.freeze(['JURISDICTION_REQUIRED', 'JURISDICTION_NOT_ALLOWED', 'JURISDICTION_MISMATCH']);

/**
 * Normalise a caller's `jurisdiction` (ISO 3166-1 alpha-2): trimmed, checked to be exactly two ASCII letters, upper-cased.
 * `undefined`/`null` = none (the request signs the v1 message). Anything else throws (`code: 'MALFORMED_REQUEST'`) — it is
 * refused here, never sent. The ASCII check runs BEFORE upper-casing: `'ß'.toUpperCase()` is `'SS'`.
 */
export function normalizeJurisdiction(value) {
  if (value === undefined || value === null) return undefined;
  const trimmed = typeof value === 'string' ? value.trim() : '';
  if (!/^[A-Za-z]{2}$/.test(trimmed)) {
    throw Object.assign(new Error(`jurisdiction must be an ISO 3166-1 alpha-2 country code (two letters), got ${JSON.stringify(String(value).slice(0, 16))}`), { code: 'MALFORMED_REQUEST' });
  }
  return trimmed.toUpperCase();
}

/** The `trace` keys the gate's authorize schema keeps (mandate.controller.ts TraceSchema); it strips any other. */
const TRACE_KEYS = ['workflowId', 'workflowStep', 'parentActionId', 'toolCalls', 'dataSources', 'checksPerformed', 'upstreamEvidenceRefs'];

/**
 * Refusals this guard answers before a request is sent when the context cannot be signed (signContext, on by default):
 * CONTEXT_SIGNING_UNSUPPORTED — the key provider cannot produce a context signature the gate would verify (a custom
 * provider without signEnvelope; an agentsafe-signer daemon older than 0.19.0 for a request whose amount/currency is
 * omitted). Upgrade the signer, or pass `signContext: false`.
 */
export const CONTEXT_SIGNING_REASON_CODES = Object.freeze(['CONTEXT_SIGNING_UNSUPPORTED']);

/** The keys an unsigned context could name a jurisdiction under — the gate never reads them, so neither does local eval. */
const UNSIGNED_JURISDICTION_KEYS = ['jurisdiction', 'mm:jurisdiction'];
/**
 * The risk the issuer derived for a verdict (MAGP §6.4.3, gate v1.82+: `riskSignals` — owner tier, a payment at or above the
 * owner's share of the per-transaction cap, a first payment to a new merchant), as a note for the refusal message: an agent
 * that said "low" can tell why it is held. Empty when none applied (then the agent's own riskLevel decided it).
 */
/**
 * The detail a v2 local receipt binds (0.26.0, MAGP-LOCAL-DECISION-v2): the request's amount, currency (only with an amount),
 * merchant and the digest of its payload. Bounded to the issuer's columns; a payload that cannot be canonicalised binds none.
 */
/** Effect outcomes (GET …/effect) after which a hold is final: there is nothing left for an agent to capture. */
const SETTLED_OUTCOMES = new Set(['settled', 'not_executed', 'expired', 'reversing', 'reversed', 'reversal_failed']);

/** At most `max` UTF-16 units (the issuer's column limit), never ending in half of a surrogate pair. */
function cutUtf16(s, max) {
  if (s.length <= max) return s;
  const cut = s.slice(0, max);
  const last = cut.charCodeAt(cut.length - 1);
  return last >= 0xd800 && last <= 0xdbff ? cut.slice(0, -1) : cut;
}

export function localReceiptDetailOf(request = {}) {
  const amount = typeof request.amount === 'number' && Number.isFinite(request.amount) && request.amount !== 0 ? request.amount : null;
  let payloadDigest = null;
  if (request.payload !== undefined) {
    try {
      payloadDigest = payloadDigestOf(toWireJson(request.payload));
    } catch {
      payloadDigest = null;
    }
  }
  return {
    amount,
    currency: amount !== null ? String(request.currency ?? 'USD').slice(0, 8) : null,
    merchant: typeof request.merchant === 'string' && request.merchant ? cutUtf16(request.merchant, 120) : null,
    payloadDigest,
  };
}

export function derivedRiskNote(decision) {
  const signals = Array.isArray(decision?.riskSignals) ? decision.riskSignals : [];
  if (signals.length === 0) return '';
  return ` (risk derived by the issuer: ${signals.map((s) => `${s.signal}: ${s.detail ?? s.level}`).join('; ')})`;
}

function withoutUnsignedJurisdiction(context) {
  if (!context || !UNSIGNED_JURISDICTION_KEYS.some((k) => Object.prototype.hasOwnProperty.call(context, k))) return context;
  const out = { ...context };
  for (const k of UNSIGNED_JURISDICTION_KEYS) delete out[k];
  return out;
}

/**
 * Replay a Merkle sibling chain and report whether it reconstructs `root`.
 *
 * Byte-identical to backend/src/features/magp/merkle.ts: leaves and siblings are hex
 * sha256 digests, and an internal node is sha256 over the CONCATENATED RAW BYTES of its
 * children (not the hex text), in left-then-right order. Hashing the hex strings instead
 * would produce a self-consistent but incompatible tree — one that verified nothing the
 * backend ever anchored, while appearing to work.
 */
function verifyMerkleInclusion(leaf, proof, root) {
  const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
  const hashNodes = (a, b) => sha(Buffer.concat([Buffer.from(a, 'hex'), Buffer.from(b, 'hex')]));
  let computed = leaf;
  for (const step of proof) {
    if (!step || typeof step.sibling !== 'string') return false;
    computed = step.position === 'left' ? hashNodes(step.sibling, computed) : hashNodes(computed, step.sibling);
  }
  return computed === root;
}

/**
 * ExecutionAdapter (SAFR §19, Phase-4 PR-4) — the seam between a PERMITTING verdict
 * (allow / observe) and the real side-effect. Before this, a guarded tool called its
 * handler directly, so the only outcomes were "execute for real" or "throw". An adapter
 * interposes so the SAME governed decision can be run live, SIMULATED (dry-run), or routed
 * to a sandbox — without touching the tool handler or the gate.
 *
 * Contract: `async (execCtx) => result`, where
 *   execCtx = { action, args, decision, proceed }
 *   proceed() runs the real handler (handler(args, decision)) and returns its result.
 * An adapter that calls `proceed()` executes for real; one that returns WITHOUT calling it
 * substitutes the side-effect. Adapters run ONLY after the guard has permitted the action —
 * a block/escalate still throws GovernanceBlocked before any adapter is consulted.
 */

/** The default: execute the real handler unchanged. */
export const liveExecutionAdapter = (ctx) => ctx.proceed();

/**
 * Simulate the side-effect: do NOT call the handler, return a describe-only result. Lets an
 * agent exercise a fully-governed flow (identity → mandate → controls → verdict) with no real
 * booking/payment/write — for staging, canaries, and OBSERVE-mode dry-runs.
 */
export const dryRunExecutionAdapter = (ctx) => ({
  dryRun: true,
  action: ctx.action,
  decision: ctx.decision?.decision ?? null,
  reasonCode: ctx.decision?.reasonCode ?? null,
  authorizationId: ctx.decision?.authorizationId ?? null,
  args: ctx.args,
});

/**
 * Process-default adapter from `AGENTSAFE_EXECUTION_MODE` ('live' | 'dry-run'). Returns null
 * when unset/live so the caller's own default (live) applies — behavior-neutral by default.
 */
export function executionAdapterFromEnv(env = (typeof process !== 'undefined' ? process.env : {})) {
  const mode = String(env.AGENTSAFE_EXECUTION_MODE ?? '').toLowerCase().trim();
  if (mode === 'dry-run' || mode === 'dryrun') return dryRunExecutionAdapter;
  return null;
}

/**
 * @param {{ api: string, agentDid: string, agentKey: string }} cfg
 *   api      e.g. "http://localhost:9926/api/v1" or "https://metamynd.ai/api/v1"
 *   agentDid the agent's did:hedera
 *   agentKey the agent's Ed25519 private key (Hedera DER hex, held only by the agent)
 */
/**
 * Read + parse an agent config file, failing with the NEXT STEP rather than a bare `ENOENT`.
 * `agent.metamynd.json` holds the agent's identity (and, for a managed key, its secret), so it is
 * deliberately gitignored — which means a fresh clone of any agent project can never contain it.
 * A raw "no such file or directory" left a first-time user with no way forward (beta regression
 * 2026-09-20, BR-004); the message below names the three ways to get the file.
 */
function readConfigFile(path, who) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    if (e && e.code === 'ENOENT') {
      throw new Error([
        `${who}: no agent config at "${resolvePath(path)}".`,
        `  agent.metamynd.json holds the agent's identity and key, so it is gitignored - a fresh clone never has it.`,
        `  To get one:`,
        `    1. New agent:      npx create-metamynd-agent      (creates the agent and writes this file)`,
        `    2. Existing agent: dashboard -> Agents -> your agent -> download its configuration, save it as ${path}`,
        `    3. Kept elsewhere: pass its real path, e.g. createGuardFromConfig('/path/to/agent.metamynd.json')`,
        `  Then re-run. Step-by-step: https://metamynd.ai/developers/quickstart`,
      ].join('\n'));
    }
    throw new Error(`${who}: cannot read agent config "${path}": ${e && e.message}`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`${who}: "${path}" is not valid JSON (${e.message}). Re-download the configuration rather than editing it by hand.`);
  }
}

/**
 * Async loader — build a guard from the portable config the one-call `POST /onboarding/agent`
 * endpoint returns: a URL, a file path, or the config object itself. Overrides win over the config.
 *   const guard = await createGuardFromConfig('./agent.metamynd.json');
 *
 * Passphrase-encrypted key delivery (docs/design/passphrase-encrypted-key-delivery-plan.md): when
 * the loaded config carries `agentKeyEncrypted` (no plaintext `agentKey` — the operator set a
 * passphrase at issuance) and no explicit `agentKey`/`keyProvider` override was given, pass
 * `{ passphrase }` here to decrypt it IN-MEMORY before the guard is built:
 *   const guard = await createGuardFromConfig('./agent.metamynd.json', { passphrase: '...' });
 * The passphrase itself is never sent anywhere by this function — only used locally to derive
 * the decryption key, matching the one hard invariant the design doc names.
 */
export async function createGuardFromConfig(source, overrides = {}) {
  let cfg = source;
  if (typeof source === 'string') {
    cfg = /^https?:\/\//.test(source) ? await (await fetch(source)).json() : readConfigFile(source, 'createGuardFromConfig');
  }
  if (cfg && cfg.data && !cfg.agentDid) cfg = cfg.data; // unwrap a { success, data } API response
  const { passphrase, ...rest } = overrides;
  if (cfg?.agentKeyEncrypted && !cfg.agentKey && !rest.agentKey && !rest.keyProvider) {
    if (!passphrase) {
      throw new Error("createGuardFromConfig: this config's key is passphrase-encrypted — pass { passphrase }");
    }
    const agentKey = decryptAgentKeyWithPassword(cfg.agentKeyEncrypted.ciphertext, passphrase, cfg.agentKeyEncrypted.salt);
    return createGuard({ config: cfg, agentKey, ...rest });
  }
  return createGuard({ config: cfg, ...rest });
}

/**
 * What a handshake will sign as a counterparty's nonce (§8.2): a plain random token, nothing else. Both sides sign the
 * OTHER side's nonce with their own key, so a nonce that is free text makes the signer an oracle — a malicious peer sends a
 * canonical authorize message (or a MAGP-SERVICE-v1 claim) as its "nonce" and walks away with a valid signature on it.
 * Every MAGP message that can authorize anything contains "|"; a token of these characters can never be one.
 */
export const HANDSHAKE_NONCE = /^[A-Za-z0-9_-]{16,128}$/;

/** The fields of a tool's mapped request that buildSignedRequest() signs (everything but the action, which the tool names). */
function requestFieldsOf(mapped = {}) {
  const { amount, currency, merchant, resource, jurisdiction, context, trace, materiality, payload } = mapped;
  return { amount, currency, merchant, resource, jurisdiction, context, trace, materiality, payload };
}

export function createGuard(opts = {}) {
  // Accept a portable agent config (from /onboarding/agent) via `config` or `configPath`, in
  // addition to explicit { api, agentDid, agentKey }. Explicit fields win over the config.
  let cfg = opts.config ?? null;
  if (!cfg && opts.configPath) {
    cfg = readConfigFile(opts.configPath, 'createGuard');
  }
  if (cfg && cfg.data && !cfg.agentDid) cfg = cfg.data; // unwrap a { success, data } API response
  const api = opts.api ?? cfg?.apiBase ?? cfg?.api;
  const agentDid = opts.agentDid ?? cfg?.agentDid;
  if (!api || !agentDid) throw new Error('createGuard requires { api, agentDid } — directly, or via { config } / { configPath } / createGuardFromConfig() — plus either { agentKey } or { keyProvider }');
  const base = api.replace(/\/$/, '');
  // ExecutionAdapter seam (SAFR §19): an explicit opt wins, else the AGENTSAFE_EXECUTION_MODE env,
  // else live. Applies to every guarded tool unless a tool passes its own adapter.
  const defaultExecutionAdapter = opts.executionAdapter ?? executionAdapterFromEnv() ?? liveExecutionAdapter;
  // keyProvider seam (docs/design/agent-key-custody-local-signer-daemon-plan.md): defaults to
  // 'staticKey' (the raw key in THIS process, today's only behavior before this seam existed) —
  // pass keyProvider:'daemon' + daemonSocketPath to keep the key out of this process entirely.
  // Every place this file used to call a local sign(message) now calls one of the provider's
  // four methods instead — see key-providers.mjs for why there are four, not one.
  const keyProvider = resolveKeyProvider(opts, cfg);

  // Context-claim binding (MAGP §8.3.13, docs/design/context-claim-binding.md): sign the GovernanceEnvelope hash too, so
  // the gate and every counterparty can prove the agent's OWN key attested to the context it submitted (itinerary, trace,
  // materiality) — not just the signed action subset — and refuse one rewritten in transit (CONTEXT_SIGNATURE_INVALID).
  // ON by default since 0.17.0; `signContext: false` (option or config file) opts out, and the wire body then carries no
  // envelopeSignature field at all, exactly as before. Receivers that predate it ignore the field.
  //
  // Fails CLOSED: a key provider that cannot produce the signature (a custom provider without signEnvelope, a daemon whose
  // signature does not match the hash sent) refuses the request with CONTEXT_SIGNING_UNSUPPORTED — it never quietly sends
  // the context unsigned, which a receiver requiring the signature would refuse anyway and which is exactly what a relay
  // stripping the field looks like. The remedy is named in the error: upgrade the signer, or pass signContext: false.
  const signContext = (opts.signContext ?? cfg?.signContext ?? true) !== false;
  async function envelopeSignatureFor({ action, amount, currency, merchant, context, trace, materiality, nonce, issuedAt }) {
    if (!signContext) return undefined;
    if (typeof keyProvider.signEnvelope !== 'function') {
      throw Object.assign(new Error('this keyProvider cannot sign the context (no signEnvelope); add it, or pass signContext: false'), { code: 'CONTEXT_SIGNING_UNSUPPORTED' });
    }
    // The hash is independent of `signature` (excluded from what it commits to — see
    // governance-envelope.ts), so an empty placeholder here is exact, not approximate.
    return keyProvider.signEnvelope({ agentDid, action, amount, currency, merchant, itinerary: context, trace, materiality, nonce, issuedAt });
  }
  /**
   * The context fields exactly as a verifier will see them, so the hash signed is the hash it recomputes: each value as it
   * survives JSON (a Date becomes its string, an undefined member disappears), and `trace` reduced to the keys the gate's
   * schema keeps (it strips any other key before hashing, so signing one would fail CONTEXT_SIGNATURE_INVALID). Applied
   * only when the context is signed; with signContext: false the fields are sent as given, as before.
   */
  function contextOnWire({ context, trace, materiality }) {
    if (!signContext) return { context, trace, materiality };
    const asJson = (v) => { const s = JSON.stringify(v); return s === undefined ? undefined : JSON.parse(s); };
    let t = asJson(trace);
    if (t && typeof t === 'object' && !Array.isArray(t)) t = Object.fromEntries(Object.entries(t).filter(([k]) => TRACE_KEYS.includes(k)));
    return { context: asJson(context), trace: t, materiality: asJson(materiality) };
  }

  // Payload binding (spec §8.3.9): sign a digest of the COMPLETE payload the caller will execute, bound to THIS authorization
  // (agent, action, nonce, issuedAt). The eight signed fields cover amount/merchant/resource only; everything else a tool takes
  // (a payee, an account number) is otherwise unbound, and this is what binds it. `payload` is whatever the executing
  // counterparty will receive — the JSON body a gateway forwards, or the arguments an MCP tool is called with — normalised to
  // the JSON it would be on the wire. Fails CLOSED: if a binding was asked for and cannot be produced (a payload JSON cannot
  // carry, or a key provider that cannot sign one), this throws — it never quietly sends the request unbound.
  async function payloadBindingFor({ action, nonce, issuedAt, payload }) {
    if (payload === undefined) return {};
    let payloadDigest;
    try {
      payloadDigest = payloadDigestOf(toWireJson(payload));
    } catch (err) {
      throw Object.assign(new Error(`payload cannot be bound: ${err?.message ?? err}`), { code: 'PAYLOAD_NOT_CANONICALIZABLE' });
    }
    if (typeof keyProvider.signPayloadBinding !== 'function') {
      throw Object.assign(new Error('this keyProvider cannot sign a payload binding (signPayloadBinding)'), { code: 'PAYLOAD_BINDING_UNSUPPORTED' });
    }
    const payloadSignature = await keyProvider.signPayloadBinding({ agentDid, action, nonce, issuedAt, payloadDigest });
    return { payloadDigest, payloadSignature };
  }

  /**
   * Bind a payload to a hold that ALREADY EXISTS and carries none (spec §8.3.11). A reviewer's MODIFY changes the action this
   * agent signed, so the hold it mints — or the one minted when the re-entered review is approved — has no payload digest, and
   * an executor that requires binding could never claim it. This is how the agent binds the payload of the action that WILL
   * run: it signs a message naming the authorization (so the digest cannot be lifted onto another hold) and the gate applies it
   * only while the hold is live, unclaimed and unbound.
   *
   *   const status = await guard.escalationStatus(escalationId);              // approved, or modified
   *   await guard.bindPayload({ authorizationId: status.authorizationId, action, payload });   // then hand the executor a FRESH
   *   const signed = { ...(await guard.buildSignedRequest({ action, ...modified, payload })), authorizationId: status.authorizationId };
   *
   * Never throws for a gate answer: `{ bound: true, payloadDigest }` or `{ bound: false, reasonCode }`. A payload JSON cannot
   * carry, or a key provider that cannot sign a binding, is `bound: false` too — and the caller must then not proceed as if the
   * hold were bound.
   */
  async function bindPayload({ authorizationId, action, payload } = {}) {
    if (!authorizationId || !action || payload === undefined) return { bound: false, reasonCode: 'MALFORMED_REQUEST' };
    try {
      const nonce = crypto.randomUUID();
      const issuedAt = new Date().toISOString();
      let payloadDigest;
      try {
        payloadDigest = payloadDigestOf(toWireJson(payload));
      } catch (err) {
        return { bound: false, reasonCode: 'PAYLOAD_NOT_CANONICALIZABLE', error: String(err?.message ?? err) };
      }
      if (typeof keyProvider.signPayloadBinding !== 'function') return { bound: false, reasonCode: 'PAYLOAD_BINDING_UNSUPPORTED' };
      const payloadSignature = await keyProvider.signPayloadBinding({ agentDid, action, authorizationId, nonce, issuedAt, payloadDigest });
      const res = await fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/payload-binding`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentDid, action, nonce, issuedAt, payloadDigest, payloadSignature }),
      });
      const body = await res.json().catch(() => null);
      if (res.ok && body?.data?.payloadDigest === payloadDigest) return { bound: true, payloadDigest, authorizationId, ...(body.data.alreadyBound ? { alreadyBound: true } : {}) };
      // A 200 that does not echo the digest we sent is an issuer that predates late binding answering something else: not bound.
      return { bound: false, reasonCode: res.ok ? 'PAYLOAD_BINDING_NOT_CONFIRMED' : (body?.data?.reasonCode ?? body?.message ?? `GATE_HTTP_${res.status}`) };
    } catch (err) {
      if (err?.code === 'PAYLOAD_BINDING_UNSUPPORTED') return { bound: false, reasonCode: err.code, error: String(err.message) };
      return { bound: false, reasonCode: err?.code?.startsWith?.('DAEMON_') ? 'SIGNER_UNREACHABLE' : 'GATE_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }

  // --- Enforcement mode (spec §9.2 + local-first plan) --------------------------------------
  // 'local' (DEFAULT): decide the rule layer LOCALLY against a cached signed bundle — a
  //   block needs no network; an allowed VALUE action is still sealed by the remote gate
  //   (two-phase hold + cumulative cap + evidence), and an ESCALATE is parked there so the
  //   owner can see and decide it (0.18.1). 'remote': every call hits the gate.
  const mode = opts.mode ?? cfg?.mode ?? 'local';
  const bundleUrl = opts.bundleUrl ?? cfg?.bundleUrl ?? `${base}/policy/bundle/${encodeURIComponent(agentDid)}`;
  const sealValueActions = opts.sealValueActions !== false; // default true
  // When an authorize call fails AFTER it was sent (a timeout, a dropped connection, a proxy's 5xx), the gate may still have
  // committed a hold this agent never heard of. It is looked up and released after these delays (ms); [] turns it off.
  const orphanDelaysMs = Array.isArray(opts.orphanReleaseDelaysMs) ? opts.orphanReleaseDelaysMs : [2_000, 10_000, 30_000];
  let warnedNoRequestDigest = false; // once per guard: the gate predates the resume binding (§9a.5)
  let warnedNoResumeClaim = false; // once per guard: the gate predates the resume claim (§9a.6)
  let warnedNoContextDigest = false; // once per guard: the gate predates the approved-context binding (§9a.5, rerun 5 F-1-NF)
  // Escalations being resumed in THIS process right now, by any gated tool of this guard: a second, concurrent resume of
  // the same one is refused instead of racing the first past the "still unused?" check (since 0.22.0).
  const resumesInFlight = new Set();
  // Build B — trustless currency check. When on, the guard trusts its local bundle ONLY if that
  // bundle is the LATEST one anchored on the agent's Hedera topic (read from a public mirror);
  // otherwise it defers to the authoritative remote gate. Opt-in for now.
  const verifyOnChain = opts.verifyOnChain ?? cfg?.verifyOnChain ?? false;
  const _anchorTtlMs = opts.anchorTtlMs ?? 60_000;
  let _bundle = null;
  let _bundleAt = 0;
  let _bundleMaxAgeMs = 10 * 60 * 1000; // overwritten by the bundle's maxStaleness
  // How old a cached bundle may be for a LOCAL permit or containment refusal (0.30.0, rerun 5 N-1): the agent's live state
  // (suspended, reinstated, rules edited) reaches this process within this window, not within maxStaleness. 0 = every time.
  const lifecycleMaxAgeOpt = opts.lifecycleMaxAgeMs ?? cfg?.lifecycleMaxAgeMs;
  const lifecycleMaxAgeMs = typeof lifecycleMaxAgeOpt === 'number' && Number.isFinite(lifecycleMaxAgeOpt) ? Math.max(0, lifecycleMaxAgeOpt) : 5_000;
  let _bundleRefresh = null; // one forced re-fetch shared by every call that finds the bundle too old at once
  let _anchor = null;
  let _anchorAt = 0;
  let _highestSeq = 0; // monotonic: never accept a mirror response with fewer policy ops than seen

  /** Parse an ISO-8601 duration like "PT10M" / "PT30S" / "PT1H" → ms (or null). */
  function _durationMs(s) {
    const m = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(String(s ?? ''));
    if (!m) return null;
    return ((+m[1] || 0) * 3600 + (+m[2] || 0) * 60 + (+m[3] || 0)) * 1000 || null;
  }

  /**
   * Build a signed authorize request (spec §7.2/§7.3) WITHOUT sending it — the object an
   * agent presents to a counterparty (e.g. an MCP) so the counterparty can re-verify the
   * agent's authorization trustlessly against the agent's policy bundle (§9.3). Same shape
   * `authorize()` posts to the gate; a fresh nonce each call.
   */
  async function buildSignedRequest({ action, amount, currency, merchant, resource, jurisdiction, context = {}, trace, materiality, payload }) {
    // Signed jurisdiction (spec §8.3.12): normalised once; the SAME value is signed (v2 message) and sent top-level. A
    // malformed one throws here. Absent → the v1 message and no `jurisdiction` on the wire, byte for byte as before.
    const signedJurisdiction = normalizeJurisdiction(jurisdiction);
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    // This object is presented to a COUNTERPARTY (spec §9.3) — but its own docstring also
    // promises "same shape authorize() posts to the gate", so it must ALSO independently
    // re-verify if posted straight to /policy/mandate/authorize, not just via a naive
    // counterparty reconstruction. Found live: signing with amount/currency genuinely
    // undefined (bothOmitted) produced a message the backend's authMessage() — which
    // ALWAYS defaults a missing amount/currency to 0/'USD' before reconstructing,
    // regardless of the wire body — could never verify. Fix: SIGN with the same 0/'USD'
    // default authorize() and the gate both use, unconditionally; the WIRE body still
    // keeps a real omission as a real omission. A naive third-party reconstruction (e.g.
    // today's agentsafe-mcp-guard, which doesn't yet apply this same default) would need
    // the same fix to correctly re-verify a bothOmitted request — flagged as a follow-up,
    // not something to leave this function broken against the gate over.
    const bothOmitted = amount === undefined && currency === undefined;
    const wireAmount = bothOmitted ? undefined : (amount ?? 0);
    const wireCurrency = bothOmitted ? undefined : (currency ?? 'USD');
    const signedAmount = amount ?? 0;
    const signedCurrency = currency ?? 'USD';
    // `resource` is independent of amount/currency's bothOmitted pairing — it always signs and
    // travels exactly as given (undefined stays undefined on the wire, buildAuthMessage's own
    // internal `?? ''` fallback handles the signed-message side, same as `merchant`).
    // trace/materiality are GovernanceEnvelope fields (SAFR §5) — unsigned metadata; the
    // signed message stays the action subset, so verification is unchanged. `resource` is
    // deliberately NOT passed to envelopeSignatureFor: the backend's governance-envelope.ts
    // action fields don't include it yet either (only amount/currency/merchant) — adding it
    // to just one side would break Tier-1 envelope-hash verification for any resource-
    // declaring request. A coordinated backend+guard follow-up, not something to do half here.
    ({ context, trace, materiality } = contextOnWire({ context, trace, materiality }));
    const [signature, envelopeSignature, binding] = await Promise.all([
      keyProvider.signAuthorize(authFieldsFor({ action, amount: signedAmount, currency: signedCurrency, merchant, resource, nonce, issuedAt, jurisdiction: signedJurisdiction })),
      envelopeSignatureFor({ action, amount: wireAmount, currency: wireCurrency, merchant, context, trace, materiality, nonce, issuedAt }),
      payloadBindingFor({ action, nonce, issuedAt, payload }),
    ]);
    return { agentDid, action, amount: wireAmount, currency: wireCurrency, merchant, resource, ...jurisdictionField(signedJurisdiction), itinerary: context, trace, materiality, nonce, issuedAt, signature, envelopeSignature, ...binding };
  }

  /**
   * The exact fields handed to keyProvider.signAuthorize — ONE builder for both signing paths, and `jurisdiction` is a
   * key only when it is also sent (jurisdictionField). A provider that spreads what it is given into buildAuthMessage
   * therefore can never sign a v2 message for a request that goes out without the field (or the reverse).
   */
  function authFieldsFor({ action, amount, currency, merchant, resource, nonce, issuedAt, jurisdiction }) {
    return { agentDid, action, amount, currency, merchant, resource, nonce, issuedAt, ...jurisdictionField(jurisdiction) };
  }
  function jurisdictionField(jurisdiction) {
    return jurisdiction === undefined ? {} : { jurisdiction };
  }

  /**
   * Ask the gate whether an action is authorized. Never throws on a policy decision —
   * returns { decision:'allow'|'block'|'escalate', reasonCode, authorizationId, remaining }.
   * A network/gate failure returns a fail-CLOSED block so the agent can't proceed blind.
   */
  async function authorize({ action, amount, currency, merchant, resource, jurisdiction, context = {}, trace, materiality, payload }) {
    let signedJurisdiction;
    try {
      signedJurisdiction = normalizeJurisdiction(jurisdiction);
    } catch (err) {
      return { decision: 'block', reasonCode: 'MALFORMED_REQUEST', authorizationId: null, error: String(err.message) }; // refused locally, never sent
    }
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    let sent = false; // the request left this process: a failure from here on may follow a hold the gate committed
    try {
      // This is verified SERVER-SIDE by the gate, which independently reconstructs the signed
      // message via its own authMessage() (mandate.service.ts) — that function ALSO defaults a
      // missing amount/currency to 0/'USD' before rebuilding the message, regardless of what the
      // wire body actually contains. So the client signs with that same 0/'USD' default whenever
      // a field is genuinely omitted — matching the gate's reconstruction — while the WIRE body
      // below keeps a real omission as a real omission (not the gate's problem: it defaults on
      // its own) rather than fabricating amount:0/currency:'USD' for a non-financial action.
      // `resource` needs no such dance: the gate's authMessage() spreads `...input` directly
      // (no explicit default), and buildAuthMessage's own internal `f.resource ?? ''` fallback
      // already matches whatever this client signs when it too is genuinely omitted.
      const signedAmount = amount ?? 0;
      const signedCurrency = currency ?? 'USD';
      // The canonical message itself is built by the key provider (policy-core's
      // buildAuthMessage, same as the backend gate verifies against — spec §7.3), not here —
      // see key-providers.mjs for why callers pass structured fields, not a pre-built string.
      // `resource` deliberately NOT passed to envelopeSignatureFor — see buildSignedRequest's
      // own comment on why (backend governance-envelope.ts doesn't include it yet either).
      ({ context, trace, materiality } = contextOnWire({ context, trace, materiality }));
      const [signature, envelopeSignature, binding] = await Promise.all([
        keyProvider.signAuthorize(authFieldsFor({ action, amount: signedAmount, currency: signedCurrency, merchant, resource, nonce, issuedAt, jurisdiction: signedJurisdiction })),
        envelopeSignatureFor({ action, amount, currency, merchant, context, trace, materiality, nonce, issuedAt }),
        payloadBindingFor({ action, nonce, issuedAt, payload }),
      ]);
      sent = true;
      const res = await fetch(`${base}/policy/mandate/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // trace/materiality (SAFR §5 envelope) and envelopeSignature (context signature, on by default) ride
        // as unsigned-message metadata; JSON.stringify drops them when undefined, so an
        // agent that omits them (or sets signContext: false) sends the legacy body.
        body: JSON.stringify({
          agentDid, action, amount, currency, merchant, resource, ...jurisdictionField(signedJurisdiction), itinerary: context, trace, materiality, nonce, issuedAt,
          signature,
          envelopeSignature,
          ...binding, // payloadDigest + payloadSignature, or nothing for an unbound request
        }),
      });
      const body = await res.json().catch(() => null);
      // A 5xx with no decision (a proxy that gave up, an issuer that failed after committing) is answered like a lost
      // response: blocked here, and any hold the request minted is looked up and released.
      if (res.status >= 500 && !body?.data?.decision) releaseOrphan(nonce);
      const data = body?.data ?? { decision: 'block', reasonCode: `GATE_HTTP_${res.status}` };
      // The gate ACKNOWLEDGES a binding by echoing the digest it stored. A permit or escalation that does not — a hop stripped
      // the fields, or the backend predates payload binding and ignored them — was never bound, and this agent must not act as
      // if it were: refuse, and release the hold it just got (best effort; an unclaimed hold also lapses on its own).
      if (binding.payloadDigest && (data.decision === 'allow' || data.decision === 'observe' || data.decision === 'escalate') && data.payloadDigest !== binding.payloadDigest) {
        if (data.authorizationId) {
          const id = data.authorizationId;
          settleProof('void', id, ['']).then((agentProof) => fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(id)}/void`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(agentProof ? { agentProof } : {}) })).catch(() => {});
        }
        return { decision: 'block', reasonCode: 'PAYLOAD_BINDING_NOT_CONFIRMED', authorizationId: null, error: 'the gate did not confirm the payload binding (an older backend, or the digest was stripped in transit)' };
      }
      return data;
    } catch (err) {
      // A payload binding that was asked for and cannot be produced is its own answer — NOT a gate outage, and never a
      // reason to send the request unbound. Fail closed with the real cause.
      if (err?.code === 'PAYLOAD_NOT_CANONICALIZABLE' || err?.code === 'PAYLOAD_BINDING_UNSUPPORTED' || err?.code === 'JURISDICTION_SIGNING_UNSUPPORTED' || err?.code === 'CONTEXT_SIGNING_UNSUPPORTED') {
        return { decision: 'block', reasonCode: err.code, error: String(err.message) };
      }
      // A daemon-backed keyProvider can fail before the gate is ever reached (the signer, not
      // the gate, was unreachable) — a distinct reasonCode so this doesn't read as a gate outage
      // it wasn't. Still fail-CLOSED either way, which is the property that actually matters.
      const reasonCode = err?.code?.startsWith?.('DAEMON_') ? 'SIGNER_UNREACHABLE' : 'GATE_UNREACHABLE';
      if (sent && reasonCode === 'GATE_UNREACHABLE') releaseOrphan(nonce);
      return { decision: 'block', reasonCode, error: String(err?.message ?? err) };
    }
  }

  /**
   * An authorize whose answer never arrived (a timeout, a dropped connection, a proxy's 5xx) may still have minted a hold:
   * the gate commits it whether or not anyone is waiting. Nothing could use or settle it, and its budget would stay reserved
   * until the TTL. So it is looked up by this request's nonce (GET .../authorize/by-request) and released with this agent's
   * signed void — retried after each of `orphanReleaseDelaysMs`, since the gate may still be working on it. Best effort, in
   * the background, and it never keeps the process alive. (Since 0.22.0; pre-beta rerun 3, D-7.)
   */
  function releaseOrphan(nonce) {
    let attempt = 0;
    const next = () => {
      if (attempt >= orphanDelaysMs.length) return; // the hold's TTL is the backstop
      const timer = setTimeout(async () => {
        attempt++;
        try {
          const r = await fetch(`${base}/policy/mandate/authorize/by-request?agentDid=${encodeURIComponent(agentDid)}&nonce=${encodeURIComponent(nonce)}`);
          const body = await r.json().catch(() => null);
          const id = r.ok ? body?.data?.authorizationId : null;
          if (id) { await voidHold(id, 'ORPHANED: the agent never received this authorization'); return; }
        } catch { /* still unreachable — try again */ }
        next();
      }, orphanDelaysMs[attempt]);
      timer.unref?.();
    };
    next();
  }

  /**
   * Settle an approved hold (two-phase). Call after the real action succeeds with the
   * amount actually charged (≤ the authorized amount). Pass the x402 `settlementTxHash`
   * to record the on-chain payment proof against the capture (§7a.3.2). Optional —
   * skip for non-payment tools.
   */
  async function capture(authorizationId, amountCharged, bookingRef, settlementTxHash) {
    // Signed as this agent (MAGP-SETTLE-v1) when the key provider can: a hold nobody has claimed is settled only by its own
    // agent or a counterparty the owner registered, on every owner (MAGP §8.7.4; an authorizationId alone settles nothing).
    const agentProof = await settleProof('capture', authorizationId, [String(amountCharged), bookingRef ?? '', settlementTxHash ?? '']).catch(() => undefined);
    const res = await fetch(`${base}/policy/mandate/authorize/${authorizationId}/capture`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amountCharged, bookingRef, settlementTxHash, ...(agentProof ? { agentProof } : {}) }),
    });
    return res.json().catch(() => ({}));
  }

  /**
   * Release a hold nobody has claimed, returning its amount to the budget (since 0.21.0). Signed as this agent
   * (MAGP-SETTLE-v1), which the issuer requires for an owner with registered counterparties and for every mainnet hold
   * (MAGP §8.7.4) — the raw unsigned POST earlier READMEs showed is refused there with COUNTERPARTY_AUTH_REQUIRED.
   *
   * Never throws. Resolves to the issuer's answer: `{ voided: true, reasonCode: 'HOLD_VOIDED' }`, or `{ voided: false,
   * reasonCode }` — `NOT_HELD` (already settled or released: not an error), `COUNTERPARTY_MISMATCH` (a service has claimed it
   * and may already have acted; only it can release it), `GATE_UNREACHABLE` (the hold stands; its TTL is the backstop).
   *
   * @param {string} authorizationId
   * @param {string} [reason]
   * @returns {Promise<{ voided: boolean, reasonCode: string, authorizationId?: string, status?: string }>}
   */
  async function voidHold(authorizationId, reason) {
    try {
      const why = reason ? String(reason) : '';
      const agentProof = await settleProof('void', authorizationId, [why]).catch(() => undefined);
      const res = await fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/void`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...(why ? { reason: why } : {}), ...(agentProof ? { agentProof } : {}) }),
      });
      const body = await res.json().catch(() => null);
      const data = body?.data && typeof body.data === 'object' ? body.data : {};
      return { ...data, voided: data.voided === true, reasonCode: data.reasonCode ?? body?.message ?? `GATE_HTTP_${res.status}` };
    } catch (err) {
      return { voided: false, reasonCode: 'GATE_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }

  /**
   * Poll a held (escalated) action until its owner decides, or `timeoutMs` passes (since 0.21.0). Resolves to the last
   * `escalationStatus()` answer — it may STILL be `pending` when the timeout hits. Act only when `status === 'approved'`
   * and an `authorizationId` came back: a hold nobody has decided is a hold, and an unreachable gate never resolves a wait
   * in the action's favour.
   *
   * @param {string} escalationId
   * @param {{ timeoutMs?: number, intervalMs?: number }} [opts]  defaults: 10 minutes, every 2 seconds
   */
  async function waitForEscalation(escalationId, { timeoutMs = 600_000, intervalMs = 2_000 } = {}) {
    const deadline = Date.now() + Math.max(0, timeoutMs);
    for (;;) {
      const st = await escalationStatus(escalationId);
      if (st?.status !== 'pending' || Date.now() >= deadline) return st;
      await new Promise((r) => setTimeout(r, Math.max(50, Math.min(intervalMs, deadline - Date.now()))));
    }
  }

  /**
   * This agent's signature over settling its OWN unclaimed hold (MAGP-SETTLE-v1), or undefined when the key provider cannot
   * sign one (a caller's own provider without signSettle, or a signer daemon older than 0.20.0) — the call then goes unsigned,
   * which the issuer accepts only for an open testnet owner. `fields`: capture → amountCharged, bookingRef, settlementTxHash;
   * void → reason ('' when none). Exactly the strings sent.
   */
  async function settleProof(verb, authorizationId, fields) {
    if (typeof keyProvider.signSettle !== 'function') return undefined;
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    try {
      const signature = await keyProvider.signSettle({ verb, agentDid, authorizationId, nonce, issuedAt, fields });
      return { agentDid, nonce, issuedAt, signature };
    } catch (err) {
      if (err?.code === 'SETTLE_SIGNING_UNSUPPORTED') return undefined;
      throw err;
    }
  }

  /**
   * Evaluate a signed policy bundle LOCALLY — no network — using the same
   * deterministic policy-core the gate runs (spec §9.2 cooperative mode). Given the
   * same (rule packs, mandate, request), this returns the identical verdict the
   * gate would. The stateful parts the gate owns (nonce/replay, atomic spend-cap
   * reservation, evidence anchoring) are NOT done here — this is the local
   * allow/block/escalate pre-check, so `authorizationId`/`remaining` are null.
   *
   * @param {object} p
   * @param {Array<{standardKey:string,document:object}>} [p.standards] enforced Standards bound to the agent
   * @param {Array<{standardKey:string,document:object}>} [p.sops]      active SOPs assigned to the agent
   * @param {object} [p.mandate]  the ODRL mandate document (omit to skip the mandate layer)
   * @param {{action:string,amount?:number,currency?:string,merchant?:string,resource?:string,jurisdiction?:string,context?:object,cumulativeSpend?:number,now?:string}} p.request
   * @returns {{decision:'allow'|'block'|'escalate',reasonCode:string|null,authorizationId:null,remaining:null,proofRef:null}}
   */
  function evaluateLocally({ contained = null, operatingMode = null, standards = [], sops = [], mandate, request }) {
    // Push containment (Phase 2.3): a server-CONTAINED agent is denied at the EDGE,
    // before any rule eval. `contained` rides alongside the signed bundle as a SIBLING
    // response field (never inside the signed payload, so the bundle signature stays
    // valid) and is refreshed on the `policy:changed` push, reaching the guard in ~1s.
    if (contained && contained.status) {
      const decision = contained.status === 'quarantined' ? 'quarantine' : 'suspend';
      const reasonCode = contained.status === 'quarantined' ? 'AGENT_QUARANTINED' : 'AGENT_SUSPENDED';
      return { decision, reasonCode, authorizationId: null, remaining: null, proofRef: null };
    }
    const { action, amount = 0, currency = 'USD', merchant = '', resource = null, cumulativeSpend = amount, now } = request;
    // The jurisdiction the rules and the mandate term judge is the SIGNED one only (spec §8.3.12), exactly as at the gate:
    // a context `jurisdiction` / `mm:jurisdiction` is the agent's unsigned word and is dropped. (A payee's registered
    // country, which the gate prefers, is not in the bundle — the gate stays the authority on JURISDICTION_MISMATCH.)
    const jurisdiction = normalizeJurisdiction(request.jurisdiction);
    const context = withoutUnsignedJurisdiction(request.context ?? {});
    // Operating-mode autonomy ladder (Phase 2.5b): the trust-driven posture rides as a
    // SIBLING (like `contained`) and biases the edge verdict identically to the gate.
    // READ_ONLY denies a value-bearing action up-front; SUPERVISED/RESTRICTED only
    // ESCALATE, applied to the verdict below so a rule block/escalate still outranks it.
    // The EFFECTIVE risk (spec §6.4.3): the owner's tier in the mandate is a floor under the agent's own claim, so
    // this local pre-check agrees with the gate instead of telling the agent "low" is enough.
    const modeGate = operatingModeGate(operatingMode?.mode, { amount, riskLevel: maxRisk(effectiveRiskFloor(mandate, action, amount), normalizeRiskLevel(context?.riskLevel)) ?? undefined });
    if (modeGate.decision === 'block') {
      return { decision: 'block', reasonCode: modeGate.reasonCode, authorizationId: null, remaining: null, proofRef: null };
    }
    // Signed fields (action/agentDid/amount, mm:* operands) are applied LAST so an
    // unsigned context key can never shadow them (spec §6.4.2) — the same invariant
    // the gate enforces, via the same policy-core helper.
    const verdict = evaluate({
      standards,
      sops,
      mandate,
      // currency/merchant/resource are signed fields too, same as action/agentDid/amount —
      // omitting them here means a currency-scoped amount-over/cumulative-over Standards/SOP
      // atom always sees currency as absent and fires closed. Mirrors mandate.service.ts's
      // ruleCtx (PR #588) and the same fix in agentsafe-mcp-guard.mjs's verdictFromBundle.
      context: buildRuleContext({ unsigned: context, signed: { action, agentDid, amount, currency, merchant, resource, ...(jurisdiction ? { jurisdiction } : {}) }, riskFloor: effectiveRiskFloor(mandate, action, amount) }),
      mandateRequest: mandate
        ? {
            target: action,
            now: now ?? new Date().toISOString(),
            values: applySignedLast(context, {
              'mm:payAmount': amount,
              'mm:cumulativeSpend': cumulativeSpend,
              'mm:merchant': merchant,
              // A payAmount/cumulativeSpend constraint issued with a `unit` (currency) is
              // only satisfied in that currency (see mandate-eval.ts's constraintSatisfied)
              // — omitting this here would make EVERY unit-bearing cap fail regardless of
              // amount, since undefined never equals a real unit. Defaults to 'USD' to match
              // the same default this file already uses for authorize()/buildSignedRequest().
              'mm:currency': currency,
              // Unprefixed `resource` (not `mm:resource`) to match the constraint's own
              // leftOperand (ResourceService.scopeConstraint()) — mirrors mandate.service.ts.
              resource,
              // The allowed-jurisdictions term: with none signed it fails JURISDICTION_REQUIRED, as at the gate.
              'mm:jurisdiction': jurisdiction,
              jurisdiction,
            }),
          }
        : undefined,
    });
    // An enforced jurisdiction rule with nothing signed: the atom does not fire on a missing value, so the gate refuses
    // JURISDICTION_REQUIRED — a hard block that outranks an escalate. Mirrored here so the local pre-check agrees.
    const hardStop = verdict.decision === 'block' || verdict.decision === 'suspend' || verdict.decision === 'quarantine';
    if (!jurisdiction && !hardStop && [...standards, ...sops].some((s) => documentEnforcesJurisdiction(s?.document))) {
      return { decision: 'block', reasonCode: 'JURISDICTION_REQUIRED', authorizationId: null, remaining: null, proofRef: null };
    }
    // Mode ESCALATE floor: only lifts an otherwise-PERMIT (allow or observe) to human
    // review (never softens a stricter verdict) — most-restrictive-wins, mirroring the
    // backend gate exactly (escalate outranks observe, so a flag never masks it).
    if ((verdict.decision === 'allow' || verdict.decision === 'observe') && modeGate.decision === 'escalate') {
      return { ...verdict, decision: 'escalate', reasonCode: modeGate.reasonCode };
    }
    return verdict;
  }

  /** Fetch + cache the agent's signed policy bundle (refreshed per its maxStaleness). */
  async function loadBundle(force = false) {
    const now = Date.now();
    if (!force && _bundle && now - _bundleAt < _bundleMaxAgeMs) return _bundle;
    const res = await fetch(bundleUrl);
    const body = await res.json().catch(() => null);
    const b = body?.data ?? body;
    if (!b || (!b.mandates && !b.sops && !b.standards)) throw new Error(`invalid policy bundle from ${bundleUrl}`);
    // Live containment + operating mode ride as SIBLINGS of the signed bundle (never
    // inside it, so the signature stays valid); stash them on the in-memory copy.
    b.contained = body?.contained ?? null;
    b.operatingMode = body?.operatingMode ?? null;
    _bundle = b;
    _bundleAt = now;
    _bundleMaxAgeMs = _durationMs(b.maxStaleness) ?? _bundleMaxAgeMs;
    return b;
  }

  /**
   * Map a fetched bundle into the shape evaluateLocally expects, for one action.
   *
   * `mandateFound` distinguishes "no mandate matches THIS action" from "omit mandate to
   * skip the layer" (evaluateLocally's own documented, intentional behavior for a caller
   * that never resolves one at all, e.g. guardToolLocal's caller-supplied bundle) — found
   * live: this used to fall back to `mandates[0]` (an ARBITRARY, possibly unrelated
   * mandate for a completely different action) rather than correctly reporting no
   * authority for this one, and `authorizeLocal` never distinguished either case from a
   * genuinely-mandate-less bundle, so an ungranted action with no Standard/SOP rule
   * happening to also catch it was silently ALLOWED instead of NO_PERMISSION_FOR_ACTION.
   */
  function _bundleFor(b, action) {
    const mandates = b.mandates ?? [];
    const match = mandates.find((m) => m.action === action);
    return {
      contained: b.contained ?? null,
      operatingMode: b.operatingMode ?? null,
      standards: (b.standards ?? []).map((s) => ({ standardKey: s.id ?? s.standardKey ?? 'standard', document: s.document })).filter((s) => s.document),
      sops: (b.sops ?? []).map((s) => ({ standardKey: s.id ?? s.sopId ?? 'sop', document: s.document })).filter((s) => s.document),
      mandate: match?.document,
      mandateFound: !!match,
      anyMandates: mandates.length > 0,
      // Granted once and revoked (bundle `revokedActions`, §6.2.6): it only names WHICH refusal, never whether to refuse.
      revoked: Array.isArray(b.revokedActions) && b.revokedActions.includes(action),
    };
  }

  const _sha256 = (s) => 'sha256:' + crypto.createHash('sha256').update(String(s)).digest('hex');

  /**
   * Read the CURRENT anchored policy for this agent from its OWN Hedera topic via a public
   * mirror node — no MetaMynd call (Build B / spec §5.3.1). Returns { sigDigest, seq } of the
   * latest `policy-update` op, or null. Cached for `_anchorTtlMs`; monotonic on `seq`.
   */
  async function _currentAnchor() {
    const now = Date.now();
    if (_anchor && now - _anchorAt < _anchorTtlMs) return _anchor;
    const m = /^did:hedera:([^:]+):[^_]+_(.+)$/.exec(agentDid);
    if (!m) return _anchor;
    const network = m[1];
    const topicId = m[2];
    const mbase = network === 'mainnet' ? 'https://mainnet.mirrornode.hedera.com' : 'https://testnet.mirrornode.hedera.com';
    try {
      // Newest-first: the latest `policy-update` op for this DID is the current policy. Its topic
      // sequence_number is the monotonic marker (globally increasing under Hedera consensus), so a
      // rollback / a mirror hiding recent updates shows a LOWER seq and is rejected. (A very busy
      // topic could bury the op past one page; a per-agent topic won't — pagination is a refinement.)
      const body = await fetch(`${mbase}/api/v1/topics/${topicId}/messages?limit=100&order=desc`).then((r) => (r.ok ? r.json() : null));
      const hit = (body?.messages ?? [])
        .map((x) => { try { return { seq: Number(x.sequence_number), op: JSON.parse(Buffer.from(x.message, 'base64').toString('utf8')) }; } catch { return null; } })
        .filter((e) => e && e.op?.op === 'policy-update' && e.op.did === agentDid)
        .sort((a, b) => b.seq - a.seq)[0];
      if (!hit) return _anchor;
      const a = { sigDigest: hit.op.sigDigest ?? null, seq: hit.seq };
      if (a.seq >= _highestSeq) { _anchor = a; _anchorAt = now; _highestSeq = a.seq; }
    } catch { /* mirror unreachable — keep the last known anchor */ }
    return _anchor;
  }

  // Verdicts the backend's /policy/decisions/local accepts (local-decision.service.ts's LOCAL_DECISIONS). Since 0.31.1 a
  // containment refusal ('suspend' / 'quarantine', given from the server's own `contained` flag) is reported too: the
  // containment is the server's state, but that a contained agent kept TRYING was recorded nowhere (pre-beta rerun 5,
  // N-4). An issuer that predates it refuses the report, which is fire-and-forget, so nothing else changes there.
  const REPORTABLE_LOCAL_DECISIONS = new Set(['allow', 'observe', 'block', 'escalate', 'suspend', 'quarantine']);

  /**
   * Best-effort, NEVER awaited by the caller: reports a purely-local verdict to the gate
   * for audit VISIBILITY only (Activity Log / fleet decision-mix / regulator log otherwise
   * show nothing for the large majority of decisions under the default local-first mode —
   * see docs/design/... and this package's own README "Enforcement mode" section for why
   * that's a deliberate security tradeoff, not a bug, but one that used to leave zero trail
   * anywhere). Silently does nothing if the keyProvider doesn't support it (e.g. the daemon
   * keyProvider, which doesn't implement signLocalDecision in this version) or the verdict
   * isn't one the endpoint accepts. Never throws, never delays the caller.
   */
  function reportLocalDecision(action, decision, reasonCode, request = {}) {
    if (typeof keyProvider.signLocalDecision !== 'function' && typeof keyProvider.signLocalReceipt !== 'function') return;
    if (!REPORTABLE_LOCAL_DECISIONS.has(decision)) return;
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    void (async () => {
      // v2 (0.26.0, AUD-1): the receipt names WHAT was refused — amount, currency, merchant and the payload digest, signed
      // with the verdict — so the owner's Activity Log can show it. A provider that cannot sign v2 still reports v1.
      if (typeof keyProvider.signLocalReceipt === 'function') {
        const detail = localReceiptDetailOf(request);
        const signature = await keyProvider.signLocalReceipt({ agentDid, action, decision, reasonCode, nonce, issuedAt, detail });
        const res = await fetch(`${base}/policy/decisions/local`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ agentDid, action, decision, reasonCode, nonce, issuedAt, signature, v: 2, detail }),
        });
        // An issuer that predates v2 strips `v`/`detail`, checks the v1 message and refuses SIGNATURE_INVALID: report the
        // verdict once more as v1 (a fresh nonce), so the decision is still on the record, just without its detail.
        const body = res.ok ? null : await res.json().catch(() => null);
        if (body?.data?.reasonCode !== 'SIGNATURE_INVALID' || typeof keyProvider.signLocalDecision !== 'function') return;
        const nonceV1 = crypto.randomUUID();
        const issuedAtV1 = new Date().toISOString();
        const signatureV1 = await keyProvider.signLocalDecision({ agentDid, action, decision, reasonCode, nonce: nonceV1, issuedAt: issuedAtV1 });
        await fetch(`${base}/policy/decisions/local`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ agentDid, action, decision, reasonCode, nonce: nonceV1, issuedAt: issuedAtV1, signature: signatureV1 }),
        });
        return;
      }
      const signature = await keyProvider.signLocalDecision({ agentDid, action, decision, reasonCode, nonce, issuedAt });
      await fetch(`${base}/policy/decisions/local`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentDid, action, decision, reasonCode, nonce, issuedAt, signature }),
      });
    })().catch(() => {});
  }

  /**
   * LOCAL-FIRST decision (the default). Evaluates the rule layer against the cached
   * bundle with the same policy-core the gate runs — so a block/escalate is decided
   * with NO network. An allowed VALUE action (amount > 0) is then sealed by the remote
   * gate (two-phase hold + cumulative-spend cap + anchored evidence — the parts that
   * MUST be server-side); set `sealValueActions:false` for pure offline. If the bundle
   * can't be loaded, defers to the authoritative remote gate rather than blind-allow.
   */
  function authorizeLocal(input) {
    return authorizeLocalOn(input, false);
  }
  async function authorizeLocalOn(input, refreshed) {
    const { action, amount = 0 } = input;
    // A local PERMIT, or a local refusal for containment, rests on the agent's live state (suspended, quarantined, the
    // rules as they stand) — which the cached bundle may have outlived: it is kept for its maxStaleness (10 minutes), so a
    // suspended agent's process kept permitting value-less calls, and a reinstated one kept refusing, for that long
    // (pre-beta rerun 5, N-1). Such a verdict is only given on a bundle younger than `lifecycleMaxAgeMs` (5 s by default);
    // an older one is fetched again first, and if that fails the authoritative gate decides. A rule BLOCK is still decided
    // on the cached bundle with no network: refusing on slightly older rules can only refuse more, not run anything.
    const onFreshBundle = async (decide) => {
      if (refreshed || Date.now() - _bundleAt <= lifecycleMaxAgeMs) return decide();
      try {
        _bundleRefresh ??= loadBundle(true).finally(() => { _bundleRefresh = null; });
        await _bundleRefresh;
      } catch {
        return authorize(input);
      }
      return authorizeLocalOn(input, true);
    };
    try {
      normalizeJurisdiction(input.jurisdiction);
    } catch (err) {
      return { decision: 'block', reasonCode: 'MALFORMED_REQUEST', authorizationId: null, error: String(err.message) }; // as authorize() would
    }
    let b;
    try {
      b = await loadBundle();
    } catch {
      return authorize(input); // no local rules → authoritative remote gate
    }
    // Trustless currency check (Build B): trust the local bundle only if it is the LATEST one
    // anchored on Hedera; otherwise defer to the authoritative remote gate (never evaluate against
    // a bundle we can't prove is current — this defeats a stale/rolled-back or forged bundle).
    if (verifyOnChain) {
      const anchor = await _currentAnchor();
      // The issuer re-issues a compiled bundle at serve time (fresh issuedAt, re-signed — so maxStaleness bounds the age
      // of THIS copy, not of the compile) and carries the anchored compile signature as `compiledSignature`. An issuer
      // that predates that serves the compiled bundle itself, whose own signature is the anchored one.
      const sig = b?.compiledSignature ?? b?.proof?.signature;
      if (!anchor?.sigDigest || !sig || _sha256(sig) !== anchor.sigDigest) return authorize(input);
    }
    const { mandateFound, anyMandates, revoked, ...bundleForAction } = _bundleFor(b, action);
    // No mandate covers this action at all — refuse outright rather than let evaluateLocally
    // silently allow (its documented "omit mandate to skip the layer" behavior is for a
    // caller that never intended a mandate check, not for one that looked and found none).
    // Standards/SOP containment still applies first — a suspended/quarantined agent is
    // refused for THAT reason, not misreported as merely lacking this one action.
    if (!mandateFound) {
      const contained = bundleForAction.contained;
      if (contained && contained.status) {
        return onFreshBundle(() => {
          const decision = contained.status === 'quarantined' ? 'quarantine' : 'suspend';
          const reasonCode = contained.status === 'quarantined' ? 'AGENT_QUARANTINED' : 'AGENT_SUSPENDED';
          const local = { decision, reasonCode, authorizationId: null, remaining: null, proofRef: null };
          reportLocalDecision(action, local.decision, local.reasonCode, input);
          return local;
        });
      }
      const local = { decision: 'block', reasonCode: revoked ? 'MANDATE_REVOKED' : anyMandates ? 'NO_PERMISSION_FOR_ACTION' : 'NO_MANDATE', authorizationId: null, remaining: null, proofRef: null };
      reportLocalDecision(action, local.decision, local.reasonCode, input);
      return local;
    }
    const local = evaluateLocally({ ...bundleForAction, request: input });
    // An ESCALATE asks a person to decide, and the person can only see what the gate recorded: the escalation, its
    // escalationId (what escalationStatus() polls) and the evidence event all exist only once the gate has parked the
    // action. Decided here, none of them did — the owner's Escalations queue never showed it, nothing could approve it,
    // and the scaffold's "approve it in the dashboard and the action resumes" could not come true (2026-10-02 pre-beta
    // evaluation, H-1). So it goes to the gate, which is authoritative anyway, exactly as an allowed value action is
    // sealed there. Pure offline (sealValueActions:false) has no gate to park it at, so it stays local there.
    if (local.decision === 'escalate' && sealValueActions) return authorize(input);
    // allow/observe both PERMIT; block/contain (and an offline escalate) are decided locally with no network.
    const permits = local.decision === 'allow' || local.decision === 'observe';
    const containment = local.decision === 'suspend' || local.decision === 'quarantine';
    if (!permits && !containment) {
      reportLocalDecision(action, local.decision, local.reasonCode, input); // fire-and-forget — see above
      return local; // denied/escalated locally, no network
    }
    if (permits && amount > 0 && sealValueActions) return authorize(input); // seal value action remotely (allow or observe)
    // A non-value permit, or a containment refusal: only on a fresh bundle (see onFreshBundle above).
    return onFreshBundle(() => {
      reportLocalDecision(action, local.decision, local.reasonCode, input); // fire-and-forget
      return local; // local is sufficient
    });
  }

  /** Mode-aware decision used by guardTool: 'local' (default) or 'remote'. */
  async function check(input) {
    return mode === 'remote' ? authorize(input) : authorizeLocal(input);
  }

  /**
   * Watch for policy changes over Server-Sent Events (Build C) — ZERO-dependency (plain fetch,
   * no socket client). On a `policy:changed` push the guard invalidates its bundle + on-chain
   * anchor cache, so the NEXT call re-fetches (and re-verifies) the new rules — reaching the edge
   * in ~1s instead of within maxStaleness. Push is an optimization: a dropped stream still leaves
   * staleness (A) + the on-chain check (B) as the floor. Auto-reconnects with a short backoff.
   * Returns a handle with `.close()`. Optional `onChange(payload)` callback.
   */
  function watchPolicy(onChange) {
    let stopped = false;
    let controller = null;
    (async () => {
      while (!stopped) {
        try {
          controller = new AbortController();
          const res = await fetch(`${base}/policy/events/${encodeURIComponent(agentDid)}`, {
            headers: { Accept: 'text/event-stream' },
            signal: controller.signal,
          });
          if (!res.ok || !res.body) throw new Error(`policy events ${res.status}`);
          const reader = res.body.getReader();
          const dec = new TextDecoder();
          let buf = '';
          while (!stopped) {
            const { value, done } = await reader.read();
            if (done) break;
            buf += dec.decode(value, { stream: true });
            let i;
            while ((i = buf.indexOf('\n\n')) >= 0) {
              const frame = buf.slice(0, i);
              buf = buf.slice(i + 2);
              if (!/^event:\s*policy:changed/m.test(frame)) continue; // ignore comments/heartbeats
              _bundle = null; _bundleAt = 0; _anchor = null; _anchorAt = 0; // invalidate → next call re-fetches
              if (onChange) {
                const dline = frame.split('\n').find((l) => l.startsWith('data:'));
                try { onChange(dline ? JSON.parse(dline.slice(5).trim()) : {}); } catch { /* ignore */ }
              }
            }
          }
        } catch {
          /* stream dropped — reconnect */
        }
        if (!stopped) await new Promise((r) => setTimeout(r, 2000));
      }
    })();
    return { close() { stopped = true; try { controller?.abort(); } catch { /* ignore */ } } };
  }

  /**
   * Like guardTool, but evaluates LOCALLY against a policy bundle instead of calling
   * the gate — cooperative-mode, low-latency governance (spec §9.2). Fails CLOSED:
   * any error during local evaluation throws GovernanceBlocked, never allows.
   *
   * Unlike `guardTool()`'s default local-first path (`authorizeLocal()`), this one makes
   * NO network call of any kind, ever — that is its entire purpose (pure-offline,
   * cooperative-mode use). It does NOT report to /policy/decisions/local, so a verdict
   * decided this way has NO central audit trail at all, by design — a deliberate,
   * pre-existing tradeoff this package leaves unchanged.
   *
   * @param {string} action
   * @param {(args:any, decision:any)=>any} handler
   * @param {(args:any)=>{amount?:number,currency?:string,merchant?:string,context?:object}} mapArgs
   * @param {object|((args:any)=>object|Promise<object>)} getBundle  { standards, sops, mandate } (or a resolver)
   */
  function guardToolLocal(action, handler, mapArgs = (a) => a, getBundle = {}, toolOpts = {}) {
    const adapter = toolOpts.executionAdapter ?? defaultExecutionAdapter;
    return async (args) => {
      let decision;
      try {
        const { amount, currency, merchant, jurisdiction, context } = mapArgs(args);
        const bundle = typeof getBundle === 'function' ? await getBundle(args) : getBundle;
        decision = evaluateLocally({ ...bundle, request: { action, amount, currency, merchant, jurisdiction, context } });
      } catch (err) {
        decision = { decision: 'block', reasonCode: 'LOCAL_EVAL_ERROR', error: String(err?.message ?? err) };
      }
      // allow/observe both PERMIT execution; observe is permit-but-flag (SAFR §11) — the
      // handler receives the `decision` so a caller can surface/log the observation.
      if (decision.decision !== 'allow' && decision.decision !== 'observe') {
        const err = new Error(`AgentSafe ${decision.decision.toUpperCase()} "${action}": ${decision.reasonCode}${derivedRiskNote(decision)}`);
        err.name = 'GovernanceBlocked';
        err.governance = decision;
        throw err;
      }
      if (decision.decision === 'observe') {
        console.warn(`[agentsafe] OBSERVE "${action}": ${decision.reasonCode} — permitted under monitoring`);
      }
      // ExecutionAdapter seam (§19): the adapter runs the real handler (proceed) or substitutes it.
      return adapter({ action, args, decision, proceed: () => handler(args, decision) });
    };
  }

  /**
   * Wrap a tool handler so it is gated. Returns a function you register with your agent
   * framework in place of the raw handler. On a non-allow decision it THROWS a
   * GovernanceBlocked error (with `.governance`) so the agent surfaces the reason and
   * does NOT perform the action.
   *
   * @param {string} action  the governed action (must match a mandate scope, e.g. 'flight-purchase')
   * @param {(args:any, decision:any)=>any} handler  the real tool implementation
   * @param {(args:any)=>{amount?:number,currency?:string,merchant?:string,resource?:string,jurisdiction?:string,context?:object}} mapArgs
   *   maps the tool's call args to the gate inputs (amount/merchant, the signed `jurisdiction` if any, + the context the
   *   rules need)
   */
  function guardTool(action, handler, mapArgs = (a) => a, toolOpts = {}) {
    const adapter = toolOpts.executionAdapter ?? defaultExecutionAdapter;
    // What becomes of the hold an allowed call was granted (since 0.21.0; pre-beta rerun 3, D-2/D-3). Left alone, an unclaimed
    // hold lapses with its TTL: a tool that RAN gave its budget back after 15 minutes (the cumulative cap could be spent
    // again), and one that FAILED kept the budget reserved until then.
    //   - success → captured at the authorized amount (`settle: 'none'` opts out). Where a gateway claimed the hold it has
    //     already settled it, and the issuer refuses the agent's capture — harmless, and ignored.
    //   - failure → released only when nothing can have run: the error is a GovernanceBlocked a SERVICE raised (one that
    //     re-verifies the request refused it), or it says `nothingExecuted: true`, or `releaseOnError` says so (true, or
    //     (err) => boolean). A refusal raised by a guard wrapper itself (a guarded call nested inside this tool) does not
    //     count: this tool may have acted before it. Any other failure keeps the hold: a tool that threw may still have
    //     acted. And a hold a service CLAIMED is never released by the agent — the issuer refuses it, because the service
    //     may already have acted.
    const settle = toolOpts.settle ?? 'capture';
    const releaseOnError = toolOpts.releaseOnError ?? false;
    const refusal = (decision) => {
      const err = new Error(`AgentSafe ${decision.decision.toUpperCase()} "${action}": ${decision.reasonCode}${derivedRiskNote(decision)}`);
      err.name = 'GovernanceBlocked';
      err.governance = decision;
      err.raisedByGuard = true; // this wrapper's own refusal — never evidence that an enclosing tool did nothing
      return err;
    };
    const nothingRan = (err) =>
      (err?.name === 'GovernanceBlocked' && err?.raisedByGuard !== true) || err?.nothingExecuted === true ||
      releaseOnError === true || (typeof releaseOnError === 'function' && releaseOnError(err) === true);
    // A capture that cannot reach the gate is retried briefly: one that never lands lets the hold of an action that RAN
    // lapse with its TTL, and its spend stop counting against the cap. A refusal (already settled by a gateway) is final.
    //
    // A hold a counterparty CLAIMED is not this agent's to settle (0.27.0, pre-beta rerun 4 F-3): the gateway that ran the
    // tool claimed it before executing and settles it itself, at what it really charged and attested as its own. Capturing
    // here raced that settlement — an agent's full-amount capture landing first was recorded `unattested` and the gateway's
    // own (possibly lower) charge was refused HOLD_STATE_CHANGED. The claim precedes execution and execution precedes the
    // response this tool returned, so by now a claim is visible. Only when the gate cannot be asked does the agent capture
    // (counting the spend is the safe side).
    async function captureRan(authorizationId, amount) {
      const fx = await effectStatus(authorizationId);
      if (fx?.claimed === true || SETTLED_OUTCOMES.has(fx?.outcome)) return;
      for (const wait of [0, 250, 1000]) {
        if (wait) await new Promise((r) => setTimeout(r, wait));
        try { await capture(authorizationId, amount); return; } catch { /* unreachable — try again */ }
      }
    }
    async function run(args, permit, mapped) {
      // The headers a tool hands a MAGP-protected service (a gateway) to have THIS permitted call executed there
      // (0.31.0; pre-beta rerun 5, FW N-3): the same request, freshly signed with its payload bound, carrying the
      // authorization it was granted. Python's guarded tools have governance_headers(); a Node tool used to rebuild and
      // re-sign the request by hand. Non-enumerable, so a decision compared or logged as data is unchanged.
      const decision = Object.defineProperty({ ...permit }, 'governanceHeaders', {
        enumerable: false,
        value: async () => {
          const signed = await buildSignedRequest({ action, ...requestFieldsOf(mapped) });
          return { 'x-magp-request': JSON.stringify(permit.authorizationId ? { ...signed, authorizationId: permit.authorizationId } : signed) };
        },
      });
      let result;
      try {
        // ExecutionAdapter seam (§19): the adapter runs the real handler (proceed) or substitutes it.
        result = await adapter({ action, args, decision, proceed: () => handler(args, decision) });
      } catch (err) {
        if (decision.authorizationId && nothingRan(err)) {
          const reason = 'tool did not run: ' + (err?.governance?.reasonCode ?? err?.code ?? err?.name ?? 'error');
          await voidHold(decision.authorizationId, reason.slice(0, 200));
        }
        throw err;
      }
      if (decision.authorizationId && settle === 'capture' && typeof mapped?.amount === 'number') {
        await captureRan(decision.authorizationId, mapped.amount);
      }
      return result;
    }
    const gated = async (args) => {
      const mapped = mapArgs(args);
      const decision = await check({ action, ...mapped });
      // allow/observe both PERMIT execution; observe is permit-but-flag (SAFR §11) — the
      // handler receives the `decision` so a caller can surface/log the observation.
      if (decision.decision !== 'allow' && decision.decision !== 'observe') throw refusal(decision);
      if (decision.decision === 'observe') {
        console.warn(`[agentsafe] OBSERVE "${action}": ${decision.reasonCode} — permitted under monitoring`);
      }
      return run(args, decision, mapped);
    };
    /**
     * Run an ESCALATED call once its owner approves it (since 0.21.0). Pass the escalationId from the refusal
     * (`err.governance.escalationId`) and the SAME args the original call had: the approval is bound to that request, and
     * a service that re-verifies it refuses a different one. Waits for the decision (`waitForEscalation`, same options),
     * then runs the tool with the authorization the approval minted — settled like any allowed call. Throws a
     * GovernanceBlocked when it was not approved (rejected, modified, expired, still pending at the timeout, or the gate
     * was unreachable), with the status in `err.governance`.
     *
     * Once only: it runs the tool only while the approved authorization is still `not_started` (nothing has used it). A
     * second resume of the same escalation — after a run that was settled, a gateway's claim, or an expiry — is refused
     * `AUTHORIZATION_ALREADY_USED` without touching the tool, and one started while another is still running in this
     * process is refused `AUTHORIZATION_IN_USE` (0.22.0). Separate PROCESSES resuming the same escalation at once need a
     * lock of their own (the scaffold takes its saved call atomically) or a gateway, which claims the authorization
     * atomically.
     */
    // The resume binding of the request these args map to, under the approval's authorization. The payload counts only
    // when the hold carries one (`payloadBound`); a hold a reviewer's MODIFY minted has none until it is bound.
    const resumeDigestFor = (st, mapped) => {
      let payloadDigest = '';
      if (st.payloadBound && mapped.payload !== undefined) {
        try {
          payloadDigest = payloadDigestOf(toWireJson(mapped.payload));
        } catch {
          payloadDigest = 'unbindable';
        }
      }
      return resumeRequestDigest({
        authorizationId: st.authorizationId,
        action,
        amount: mapped.amount,
        currency: mapped.currency ?? 'USD',
        merchant: mapped.merchant ?? '',
        resource: mapped.resource ?? '',
        payloadDigest,
      });
    };
    // The approved-context digest of the context these args map to, as the gate receives it (JSON on the wire; none is {}).
    const resumeContextDigestFor = (mapped) => {
      try {
        return approvedContextDigest(toWireJson(mapped.context ?? {}));
      } catch {
        return 'unbindable';
      }
    };
    // 'claimed' | 'unsupported' (no signer for it, or an issuer that predates it: run as before) | a refusal code.
    // `digests` (0.32.0, pre-beta rerun 6 F-1-NF-R): { requestDigest, contextDigest } of the request THESE args map to. Signed as
    // MAGP-RESUME-CLAIM-v2 when the issuer asks for it (`resumeClaimVersion` >= 2 on the status), so the issuer itself refuses
    // a resume of anything but the approved request and context; an older issuer only knows v1 and gets v1.
    const claimResume = async (escalationId, authorizationId, digests) => {
      if (typeof keyProvider.signResumeClaim !== 'function') return 'unsupported';
      const nonce = crypto.randomUUID();
      const issuedAt = new Date().toISOString();
      const bound = digests ? { requestDigest: digests.requestDigest, contextDigest: digests.contextDigest } : {};
      const signature = await keyProvider.signResumeClaim({ escalationId, authorizationId, agentDid, nonce, issuedAt, ...bound });
      let res;
      try {
        res = await fetch(`${base}/policy/escalations/${encodeURIComponent(escalationId)}/resume-claim`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ agentDid, nonce, issuedAt, signature, ...bound }),
        });
      } catch {
        return 'GATE_UNREACHABLE'; // never run a resume the issuer could not be told about
      }
      if (res.ok) return 'claimed';
      const body = await res.json().catch(() => undefined);
      // An issuer that predates the route answers the framework's own 404 page, not JSON. A JSON 404 (an escalation the
      // issuer does not know, or a proxy's error body) is a refusal: never run unclaimed on an ambiguous answer.
      if (res.status === 404 && body === undefined) {
        if (!warnedNoResumeClaim) {
          warnedNoResumeClaim = true;
          console.warn('[agentsafe] this gate has no resume claim (it predates MAGP §9a.6): resume() runs unclaimed, so two processes resuming one approval could both run it');
        }
        return 'unsupported';
      }
      const code = body?.data?.reasonCode;
      return typeof code === 'string' && code ? code : `GATE_HTTP_${res.status}`;
    };
    gated.resume = async (escalationId, args, opts = {}) => {
      if (resumesInFlight.has(escalationId)) {
        throw refusal({ decision: 'block', reasonCode: 'AUTHORIZATION_IN_USE', escalationId, status: 'approved' });
      }
      resumesInFlight.add(escalationId);
      try {
        return await resumeOnce(escalationId, args, opts);
      } finally {
        resumesInFlight.delete(escalationId);
      }
    };
    const resumeOnce = async (escalationId, args, opts) => {
      const st = await waitForEscalation(escalationId, opts);
      if (st?.status !== 'approved' || !st.authorizationId) {
        throw refusal({ decision: st?.status === 'pending' ? 'escalate' : 'block', reasonCode: st?.reasonCode ?? `ESCALATION_${String(st?.status ?? 'unknown').toUpperCase()}`, escalationId, status: st?.status ?? null });
      }
      const fx = await effectStatus(st.authorizationId);
      if (fx?.outcome !== 'not_started') {
        const unreachable = fx?.effectState === 'unreachable';
        throw refusal({ decision: 'block', reasonCode: unreachable ? 'GATE_UNREACHABLE' : 'AUTHORIZATION_ALREADY_USED', escalationId, authorizationId: st.authorizationId, status: 'approved', outcome: fx?.outcome ?? null });
      }
      const mapped = mapArgs(args);
      // Only what was approved (0.24.0, §9a.5): the approval's hold is for ONE request. A gateway re-verifies it, but an
      // in-process tool has nothing else between these args and the tool, so they must reproduce the hold's requestDigest.
      if (!st.requestDigest && !warnedNoRequestDigest) {
        warnedNoRequestDigest = true;
        console.warn('[agentsafe] this gate returns no requestDigest (it predates MAGP §9a.5): resume() cannot check its args against the approved request, so pass the SAME args; a gateway still re-verifies them');
      }
      if (st.requestDigest && resumeDigestFor(st, mapped) !== st.requestDigest) {
        throw refusal({ decision: 'block', reasonCode: 'ESCALATION_REQUEST_MISMATCH', escalationId, authorizationId: st.authorizationId, status: 'approved' });
      }
      // And only the CONTEXT that was approved (0.29.0, §9a.5): the digest above binds what the approval spends — for an action
      // that spends nothing, little more than its name — so an approval of { target: 'record-A', op: 'read' } could run as
      // { target: 'record-B', op: 'delete-all' }. The status carries a digest of the itinerary the reviewer was shown.
      if (st.requestDigest && !st.contextDigest && !warnedNoContextDigest) {
        warnedNoContextDigest = true;
        console.warn('[agentsafe] this gate returns no contextDigest (it predates the approved-context binding, MAGP §9a.5): resume() cannot check the context against the approval, so pass the SAME args');
      }
      if (st.contextDigest && resumeContextDigestFor(mapped) !== st.contextDigest) {
        throw refusal({ decision: 'block', reasonCode: 'ESCALATION_REQUEST_MISMATCH', escalationId, authorizationId: st.authorizationId, status: 'approved' });
      }
      // The ONE resume (0.28.0, §9a.6): taken at the issuer, atomically, so a second PROCESS resuming the same escalation
      // is refused AUTHORIZATION_IN_USE instead of running an in-process tool twice (the in-process lock above covers one
      // process only). At most once — a crash after this does not hand the approval to another run.
      const digests = Number(st.resumeClaimVersion) >= 2 ? { requestDigest: resumeDigestFor(st, mapped), contextDigest: resumeContextDigestFor(mapped) } : undefined;
      const claimed = await claimResume(escalationId, st.authorizationId, digests);
      if (claimed !== 'claimed' && claimed !== 'unsupported') {
        throw refusal({ decision: 'block', reasonCode: claimed, escalationId, authorizationId: st.authorizationId, status: 'approved' });
      }
      return run(args, { decision: 'allow', reasonCode: st.reasonCode ?? 'ESCALATION_APPROVED', authorizationId: st.authorizationId, escalationId }, mapped);
    };
    return gated;
  }

  /**
   * Mutual-handshake INITIATOR (spec §8.2). Prove control of this agent's DID to a
   * Service and verify the Service controls its DID — no issuer calls (keys are in
   * the DIDs, §4.1.2). Returns { hello, prove } to drive the exchange:
   *   const hs = guard.handshake();
   *   const { nonceA, message } = hs.hello();           // → send HELLO to the Service
   *   const { sigA, handshakeId } = await hs.prove({ nonceA, challenge });  // verifies the Service, → send PROVE
   * `prove` throws HandshakeFailed if the Service's CHALLENGE does not verify.
   */
  function handshake() {
    return {
      hello() {
        const nonceA = crypto.randomUUID();
        return { nonceA, message: { fromDid: agentDid, nonceA, protoVersion: '1.0' } };
      },
      async prove({ nonceA, challenge } = {}) {
        const { toDid, nonceB, sigB, handshakeId } = challenge ?? {};
        if (!toDid || !nonceB || !sigB) throw new Error('malformed CHALLENGE');
        // Signed with THIS agent's key below: anything but a plain token would let the Service obtain this agent's signature
        // on a message of its choosing — an authorize request, for one (see HANDSHAKE_NONCE).
        if (typeof nonceB !== 'string' || !HANDSHAKE_NONCE.test(nonceB)) {
          const e = new Error('CHALLENGE nonce is not a plain token — refusing to sign it');
          e.name = 'HandshakeFailed';
          throw e;
        }
        if (!verifyDidSignature(toDid, nonceA, sigB)) {
          const e = new Error('Service failed to prove control of its DID');
          e.name = 'HandshakeFailed';
          throw e;
        }
        return { handshakeId, sigA: await keyProvider.signHandshakeNonce(nonceB), remoteDid: toDid };
      },
    };
  }

  /**
   * Read a Service's 402 PaymentRequirements and prepare to pay (spec §7a.1 step 5).
   * Refuses a 402 that is NOT bound to a MAGP authorization (§7a.2.1) — the agent
   * must never pay for an ungoverned request — and refuses one whose authorization
   * does not match the `authorizationId` the agent holds from its own authorize
   * (allow) step, so a swapped 402 can't redirect the payment.
   *
   * @param {object} requirements  the x402 PaymentRequirements from the 402 response
   * @param {string} [expectedAuthorizationId]  the authorizationId from guard.authorize()
   * @returns {{authorizationId:string, amountMinor:string, payTo:string, asset:string, network:string, resource:string}}
   */
  function preparePayment(requirements, expectedAuthorizationId) {
    const a = requirements?.accepts?.[0];
    if (!a?.extra?.magpAuthorizationId) {
      const e = new Error('402 is not bound to a MAGP authorization — refusing to pay');
      e.name = 'UnboundPayment';
      throw e;
    }
    if (expectedAuthorizationId && a.extra.magpAuthorizationId !== expectedAuthorizationId) {
      const e = new Error('402 authorization does not match the agent authorization');
      e.name = 'AuthorizationMismatch';
      throw e;
    }
    // Pay exactly the authorized amount; the binding check guards against overpay.
    checkSettlementBinding(requirements, { authorizationId: a.extra.magpAuthorizationId, paidAmountMinor: a.maxAmountRequired });
    return {
      authorizationId: a.extra.magpAuthorizationId,
      amountMinor: a.maxAmountRequired,
      payTo: a.payTo,
      asset: a.asset,
      network: a.network,
      resource: a.resource,
    };
  }

  /**
   * Poll the outcome of an escalated action (spec §9a). When authorize() returns
   * `escalate`, its `escalationId` parks the action for the Owner to approve/deny.
   * The agent polls this until the status is terminal; on `approved` the returned
   * `authorizationId` carries into the §7a capture/pay flow. Fails soft (never throws).
   * @returns {Promise<{status:string,reasonCode:string,authorizationId:string|null,expiresAt:string|null}>}
   */
  async function escalationStatus(escalationId) {
    try {
      const res = await fetch(`${base}/policy/escalations/${encodeURIComponent(escalationId)}/status`);
      const body = await res.json().catch(() => null);
      return body?.data ?? { status: 'unknown', reasonCode: `GATE_HTTP_${res.status}`, authorizationId: null, expiresAt: null };
    } catch (err) {
      return { status: 'unreachable', reasonCode: 'GATE_UNREACHABLE', authorizationId: null, expiresAt: null, error: String(err?.message ?? err) };
    }
  }

  /**
   * Merkle inclusion proof for a decision's evidence record — fetched, then VERIFIED
   * HERE rather than taken on trust.
   *
   * The point of an inclusion proof is that its holder can check it WITHOUT trusting the
   * party that issued it. A helper that returned the server's payload as-is would look
   * like proof and function as assertion: the caller would be believing MetaMynd's claim
   * that the record is in the anchored batch, which is exactly the thing the proof exists
   * to make unnecessary. So the sibling chain is replayed locally and the recomputed root
   * is compared to the anchored one; `verified` is this SDK's own conclusion.
   *
   * Absence and falsification are reported as DIFFERENT outcomes, because they mean
   * opposite things to whoever is asking:
   *
   *   status 'verified'    the record is provably in the batch anchored at anchorTxId
   *   status 'pending'     no anchored batch contains it YET — anchoring is asynchronous
   *                        (§10.2), so a recent decision is normally pending, not missing
   *   status 'failed'      a proof was returned and it does NOT reconstruct the root.
   *                        This is the alarming one and must never be conflated with
   *                        'pending'
   *   status 'unreachable' the gate could not be asked; nothing is implied either way
   *
   * Note the trust boundary this does NOT cross: it proves the record belongs to the
   * batch that claims `root`. Proving that root was published on Hedera is a separate,
   * stronger check against the mirror node — see integrations/magp-evidence/, the offline
   * auditor, which does it with MetaMynd entirely absent.
   */
  async function proof(eventId) {
    if (!eventId) throw new Error('proof requires the evidence eventId');
    let body;
    let httpStatus;
    try {
      const res = await fetch(`${base}/magp/evidence/${encodeURIComponent(eventId)}/proof`);
      httpStatus = res.status;
      body = await res.json().catch(() => null);
    } catch (err) {
      return { status: 'unreachable', verified: false, eventId, reason: 'GATE_UNREACHABLE', error: String(err?.message ?? err) };
    }

    if (httpStatus === 404) {
      // Not an error: batching is asynchronous, so a decision made seconds ago has
      // genuinely not been anchored yet. Saying "unverified" here would read as doubt
      // about a record that is simply young.
      return { status: 'pending', verified: false, eventId, reason: 'NOT_YET_ANCHORED' };
    }
    const data = body?.data;
    if (!data?.leaf || !data?.root || !Array.isArray(data?.proof)) {
      return { status: 'unreachable', verified: false, eventId, reason: `GATE_HTTP_${httpStatus}` };
    }

    const verified = verifyMerkleInclusion(data.leaf, data.proof, data.root);
    return {
      status: verified ? 'verified' : 'failed',
      verified,
      eventId,
      leaf: data.leaf,
      root: data.root,
      proof: data.proof,
      anchorTxId: data.anchorTxId ?? null,
      anchorRef: data.anchorRef ?? null,
      anchoredAt: data.anchoredAt ?? null,
      ...(verified ? {} : { reason: 'MERKLE_ROOT_MISMATCH' }),
    };
  }

  /**
   * Effect-safety runtime (E2): report the external-effect lifecycle so an AMBIGUOUS
   * connector outcome never becomes a blind capture/void. Call effectDispatching() just
   * before the side-effecting call and effectDispatched() when the connector accepts.
   * Once UNKNOWN, capture/void are refused by the gate until the effect is reconciled.
   *
   * Reporting UNKNOWN is NOT the agent's call: see effectUnknown() below (deprecated).
   */
  async function _effectPost(authorizationId, kind, payload = {}) {
    try {
      const res = await fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/effect/${kind}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => null);
      return body?.data ?? { ok: false, reasonCode: `GATE_HTTP_${res.status}` };
    } catch (err) {
      return { ok: false, reasonCode: 'GATE_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }
  const effectDispatching = (authorizationId) => _effectPost(authorizationId, 'dispatching');
  const effectDispatched = (authorizationId, remoteRef) => _effectPost(authorizationId, 'dispatched', { remoteRef });
  /**
   * @deprecated since 0.15.4 — always rejects, without calling the gate. Kept only so existing imports do not break.
   *
   * Since 2026-09-24 `POST /policy/mandate/authorize/:authId/effect/unknown` accepts only the party that CLAIMED the hold
   * (its signature, or an anonymous claim's token), the hold's owner, or an admin. The agent is none of those, and this
   * method sent no claimer credential, so the gate refused it every time (403 COUNTERPARTY_MISMATCH) and the effect was
   * never marked. Report an ambiguous outcome from the claiming SERVICE instead —
   * `@metamynd/agentsafe-mcp-guard`'s `markAuthorizationUnknown({ authorizationId, reason, claimToken })` (signed as its
   * serviceDid, or with the claimToken its claim returned) — or have the hold's owner (an owner-authenticated call) do it. An agent
   * that only needs to know what happened can poll `effectStatus(authorizationId)`.
   *
   * @param {string} authorizationId
   * @param {string} [reason]
   * @returns {Promise<never>} rejects with an Error named `EffectUnknownNotSupported`, `code: 'EFFECT_UNKNOWN_AGENT_UNSUPPORTED'`
   */
  async function effectUnknown(authorizationId, reason) {
    const e = new Error(
      'guard.effectUnknown() is deprecated and no longer calls the gate: only the party that claimed the hold ' +
      '(the executing service), the hold\'s owner or an admin may mark an effect UNKNOWN, and an agent is none of them. ' +
      'Report it from the service with @metamynd/agentsafe-mcp-guard markAuthorizationUnknown({ authorizationId, reason, claimToken }) ' +
      '(signed as its serviceDid, or with its claimToken), or ask the owner. Poll guard.effectStatus(authorizationId) to follow the outcome.',
    );
    e.name = 'EffectUnknownNotSupported';
    e.code = 'EFFECT_UNKNOWN_AGENT_UNSUPPORTED';
    e.authorizationId = authorizationId ?? null;
    throw e;
  }
  async function effectStatus(authorizationId) {
    try {
      const res = await fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/effect`);
      const body = await res.json().catch(() => null);
      return body?.data ?? { effectState: null, reasonCode: `GATE_HTTP_${res.status}` };
    } catch (err) {
      return { effectState: 'unreachable', reasonCode: 'GATE_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }

  /**
   * BYOK proof-of-possession (onboarding proposal #4). For an agent that brought its OWN key,
   * MetaMynd issued the identity with a one-time `challenge` and left the key UNVERIFIED — the gate
   * blocks it with AGENT_KEY_UNVERIFIED until control is proven. This signs the challenge with the
   * agent's private key (the same Ed25519 the gate checks) and submits it to verify-key, flipping
   * the key to verified. A one-time SETUP step: verify-key is owner-authenticated, so pass the owner
   * `token` you onboarded with. `ref` defaults to the identityId; `challenge` comes from the config.
   *
   * @param {{ ref: string, challenge: string, token?: string }} p
   * @returns {Promise<{ verified: boolean, did?: string }>}
   */
  async function verifyKey({ ref, challenge, token } = {}) {
    if (!ref || !challenge) throw new Error('verifyKey requires { ref, challenge } (from the BYOK onboarding config)');
    const res = await fetch(`${base}/agent-identity/${encodeURIComponent(ref)}/verify-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ signature: await keyProvider.signKeyControlChallenge(challenge) }),
    });
    const body = await res.json().catch(() => null);
    if (!res.ok) {
      const e = new Error(body?.message || `verify-key HTTP ${res.status}`);
      e.name = 'KeyVerificationFailed';
      throw e;
    }
    return body?.data ?? { verified: true };
  }

  /** Sign a BYOK challenge with the agent's key — for integrators who submit verify-key themselves. */
  async function signChallenge(challenge) {
    if (!challenge) throw new Error('signChallenge requires the challenge nonce');
    return keyProvider.signKeyControlChallenge(challenge);
  }

  return { authorize, authorizeLocal, check, loadBundle, policyAnchor: _currentAnchor, watchPolicy, mode, verifyOnChain, buildSignedRequest, bindPayload, capture, void: voidHold, waitForEscalation, guardTool, evaluateLocally, guardToolLocal, handshake, preparePayment, escalationStatus, proof, effectDispatching, effectDispatched, effectUnknown, effectStatus, verifyKey, signChallenge, agentDid, executionAdapter: defaultExecutionAdapter };
}

// agentsafe-a2a-guard.mjs — governance for the A2A (Agent2Agent) protocol, the receiving
// agent's own task boundary. See docs/design/a2a-compatibility-scope.md for the full design
// rationale and citations; this file implements exactly what that scope names.
//
// A2A already gives agents transport-level auth (AgentCard `securitySchemes`) and task-lifecycle
// states — what it explicitly leaves as "application-level responsibility" is spend limits, a
// policy engine, an audit trail, and any notion of accountability surviving a task handoff. This
// guard closes that the same way agentsafe-mcp-guard closes it for MCP: the RECEIVER independently
// re-verifies a signed MAGP envelope against the calling agent's own published policy bundle,
// using the SAME deterministic policy-core the gate and the MCP guard run. It never trusts the
// caller's own claim about what it's authorized to do.
//
// Deliberately DOES NOT port the MCP guard's mutual DID handshake (§8.2): A2A already has
// transport-level auth and a discovery-time AgentCard exchange, so a second challenge-response
// identity proof on top would duplicate work the base protocol already does. Identity for
// MetaMynd's purposes rides entirely in the per-message signed envelope.
//
// Dependencies are the same shape as agentsafe-mcp-guard: two generated, zero-external-dependency
// bundles (policy-core.mjs, magp-did.mjs) plus a hand-written one (magp-policy.mjs, identical copy
// to the MCP guard's — see that file's own header for why it's duplicated rather than shared).
import crypto from 'node:crypto';
import { evaluate, buildAuthMessage, applySignedLast, operatingModeGate, buildRuleContext, riskFloorFor, maxRisk, normalizeRiskLevel, documentEnforcesJurisdiction } from './policy-core.mjs';
import { verifyDidSignature } from './magp-did.mjs';

/**
 * The jurisdiction refusals the issuer's gate can answer (spec §8.3.12), all hard blocks: JURISDICTION_REQUIRED,
 * JURISDICTION_NOT_ALLOWED, JURISDICTION_MISMATCH (the payee's registered country differs from the signed one).
 */
export const JURISDICTION_REASON_CODES = Object.freeze(['JURISDICTION_REQUIRED', 'JURISDICTION_NOT_ALLOWED', 'JURISDICTION_MISMATCH']);

/** An agent's unsigned context with its jurisdiction claims removed — the gate never reads them, so neither do we. */
function withoutUnsignedJurisdiction(context) {
  if (!context || !['jurisdiction', 'mm:jurisdiction'].some((k) => Object.prototype.hasOwnProperty.call(context, k))) return context;
  const { jurisdiction: _j, 'mm:jurisdiction': _mj, ...rest } = context;
  return rest;
}

/** Key-order-independent JSON, only to tell whether two context objects say the same thing. */
function sameJson(a, b) {
  const stable = (v) => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
    if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
    return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(',')}}`;
  };
  return stable(a) === stable(b);
}

/**
 * The agent's unsigned request context, read from the envelope under its canonical name `itinerary` (MAGP §8.2 — the
 * name agentsafe-guard's `buildSignedRequest`, and so `buildA2AEnvelope`, puts on the wire, the name the issuer's gate
 * reads, and the object an `envelopeSignature` (context-claim binding) commits to).
 *
 * `context` is accepted as a DEPRECATED alias, for envelopes built by hand for a2a-guard < 0.11.0. Refused as
 * MALFORMED_REQUEST: both present and different (the receiver would have to pick one, and the other is what a
 * different reader evaluates); the alias alongside an `envelopeSignature` (that signature covers `itinerary`, not the
 * alias); a context that is not a JSON object. Absent or null → `{}`.
 * @returns {{ ok: true, itinerary: Record<string, unknown> } | { ok: false }}
 */
export function unsignedContextOf(signed) {
  const has = (k) => Object.prototype.hasOwnProperty.call(signed ?? {}, k) && signed[k] !== undefined && signed[k] !== null;
  const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
  const hasItinerary = has('itinerary');
  const hasAlias = has('context');
  if (hasItinerary && !isObject(signed.itinerary)) return { ok: false };
  if (hasAlias && !isObject(signed.context)) return { ok: false };
  if (hasItinerary && hasAlias) return sameJson(signed.itinerary, signed.context) ? { ok: true, itinerary: signed.itinerary } : { ok: false };
  if (hasAlias) return signed.envelopeSignature !== undefined && signed.envelopeSignature !== null ? { ok: false } : { ok: true, itinerary: signed.context };
  return { ok: true, itinerary: hasItinerary ? signed.itinerary : {} };
}

/**
 * The context-signature refusals (context-claim binding, docs/design/context-claim-binding.md), both hard blocks returned
 * before any rule is evaluated, answered as TASK_STATE_AUTH_REQUIRED: CONTEXT_SIGNATURE_INVALID (an `envelopeSignature` is
 * present and does not verify — the same code the issuer's gate answers) and CONTEXT_SIGNATURE_REQUIRED (none, on a guard
 * with `requireContextSignature`; receiver-only, the gate has no such option).
 */
export const CONTEXT_SIGNATURE_REASON_CODES = Object.freeze(['CONTEXT_SIGNATURE_INVALID', 'CONTEXT_SIGNATURE_REQUIRED']);

/**
 * The agent's context signature, checked the way the issuer's gate checks it: an Ed25519 signature by the agent's key (the
 * key in its DID, as for the envelope's request signature) over `envelopeHashFor` — the backend's own function, generated
 * into governance-envelope.mjs — computed over the WIRE fields (no defaults), and over `itinerary`, the exact object this
 * guard then evaluates (unsignedContextOf's; `undefined` when the envelope carried none, which it evaluates as `{}`). It
 * commits to the itinerary, trace and materiality. Present but not a verifying string (empty included: a signature is never
 * read as absent) → CONTEXT_SIGNATURE_INVALID. Absent (undefined / null) → CONTEXT_SIGNATURE_REQUIRED when required,
 * otherwise nothing to check. (The deprecated `context` alias beside a signature never gets here: unsignedContextOf refuses it.)
 * @returns {string|null} the refusal's reason code, or null to carry on
 */
function contextSignatureRefusal(signed, itinerary, required) {
  const sig = signed.envelopeSignature;
  if (sig === undefined || sig === null) return required ? 'CONTEXT_SIGNATURE_REQUIRED' : null;
  if (typeof sig !== 'string' || sig === '') return 'CONTEXT_SIGNATURE_INVALID';
  const { agentDid, action, amount, currency, merchant, trace, materiality, nonce, issuedAt } = signed;
  const hash = envelopeHashFor({ agentDid, action, amount, currency, merchant, itinerary, trace, materiality, nonce, issuedAt, signature: '' });
  return verifyDidSignature(agentDid, hash, sig) ? null : 'CONTEXT_SIGNATURE_INVALID';
}
import { envelopeHashFor } from './governance-envelope.mjs';
import { verifyBundle } from './magp-policy.mjs';
import { PAYLOAD_DIGEST_HEADER, buildPayloadBindingMessage, claimDigestField, isPayloadDigest, payloadDigestOf, toWireJson } from './payload-binding.mjs';
// fetch() with a 60 s keep-alive (metamynd.ai sits behind Cloudflare, which strips the Keep-Alive header, so the built-in
// fetch would drop an idle connection after 4 s) — see keepalive-fetch.mjs.
import { keepAliveFetch as fetch } from './keepalive-fetch.mjs';
/** The same keep-alive fetch, for the rest of an A2A agent's calls to metamynd.ai — reuses warm connections. */
export { keepAliveFetch } from './keepalive-fetch.mjs';

/** The URI identifying MetaMynd's MAGP extension to A2A (open question #1 in the scope doc — a
 *  naming decision, not an engineering one; change freely before this ships). Declared in an
 *  outgoing Message's `extensions` array and in a consequential skill's AgentCard entry so
 *  governance is discoverable before any task is ever sent. */
export const MAGP_A2A_EXTENSION_URI = 'https://schemas.metamynd.ai/a2a-extension/magp/v1';

/**
 * The issuer could not be reached — a network failure or a 5xx on the bundle fetch. Tagged so verifyRequest refuses it
 * GATE_UNREACHABLE, the agent guard's code for the same outage, instead of the catch-all GUARD_ERROR (eval 2026-10-03, N-6).
 * A 4xx is an answer, not an outage, and stays an ordinary error.
 */
function gateUnreachable(cause) {
  const err = new Error(`issuer unreachable: ${String(cause?.message ?? cause)}`);
  err.code = 'GATE_UNREACHABLE';
  return err;
}

/** Freshness window for signed requests (spec §7.7) — how far `issuedAt` may lag server time. */
const FRESHNESS_MS = 5 * 60 * 1000;
/** How far `issuedAt` may lead server time — clock skew, not a pre-signing window. Checked
 *  separately so a single `Math.abs()` window can't fold both directions together (the same bug
 *  found live in the MCP guard once — see that file's own comment). */
const CLOCK_SKEW_TOLERANCE_MS = 30 * 1000;

// --- Initiator-side helpers (used by whichever agent is SENDING the A2A message) --------------

/**
 * Build the {metadata, extensions} fragment to splice into an outgoing A2A `Message` — the
 * envelope a receiving agent's `guardA2ATask` will independently re-verify. Reuses the calling
 * agent's EXISTING signing path unchanged: `guard` is an `agentsafe-guard` instance
 * (`createGuard(...)`), and this is a pure serialization adapter over its already-public
 * `buildSignedRequest` — no new signing code, no network call of its own.
 *
 * @param {ReturnType<import('@metamynd/agentsafe-guard').createGuard>} guard
 * Payload binding (MAGP 8.3.9): pass `payload` (the task input the receiver will execute — for `guardA2ATask({ bindPayload: true })`
 * that is the message's `parts`) and the envelope also carries a digest of it, signed with the agent's key, which the receiver
 * compares with what it is about to run and states in its claim.
 *
 * `jurisdiction` (ISO 3166-1 alpha-2, needs agentsafe-guard >= 0.16.0) is signed into the envelope (MAGP 8.3.12) and verified
 * by the receiver; a jurisdiction inside `context` is unsigned and ignored. `context` travels on the wire as `itinerary`\n * (the canonical name, MAGP §8.2), which is what the receiver evaluates.
 *
 * @param {{action:string, amount?:number, currency?:string, merchant?:string, resource?:string, jurisdiction?:string, context?:object, payload?:unknown}} params
 * @returns {Promise<{metadata: Record<string, unknown>, extensions: string[]}>}
 */
export async function buildA2AEnvelope(guard, params) {
  const signed = await guard.buildSignedRequest(params);
  return { metadata: { [MAGP_A2A_EXTENSION_URI]: signed }, extensions: [MAGP_A2A_EXTENSION_URI] };
}

/**
 * What a binding covers, computed the same way on both sides — the sending agent passes it as `payload` to
 * buildA2AEnvelope, and `guardA2ATask({ bindPayload: true, bindScope })` digests it on receipt.
 *
 *   'parts'   — the message's `parts` only (the default, and the only scope before 0.7.0). `metadata`,
 *               `referenceTaskIds` and `extensions` reach the handler UNBOUND.
 *   'message' — `parts` plus `metadata`, `referenceTaskIds` and `extensions`: everything a handler can read from the
 *               message. The MAGP envelope itself is left out (its metadata key and its own extension URI), because it
 *               carries the signature over this very digest and is added after the digest is taken. The `task` argument
 *               is never bound — it is the receiver's state, not the sender's input.
 *
 * `'message'` becomes the default at the next breaking release (owner decision 2026-09-24); until then, choose it.
 */
export function a2aBindingValue(message, scope = 'parts') {
  if (scope === 'parts') return message?.parts;
  if (scope !== 'message') throw new Error(`bindScope must be 'parts' or 'message', got ${JSON.stringify(scope)}`);
  const { [MAGP_A2A_EXTENSION_URI]: _envelope, ...metadata } = message?.metadata ?? {};
  const extensions = (message?.extensions ?? []).filter((u) => u !== MAGP_A2A_EXTENSION_URI);
  const value = { parts: message?.parts ?? [] };
  if (Object.keys(metadata).length > 0) value.metadata = metadata;
  if (message?.referenceTaskIds !== undefined) value.referenceTaskIds = message.referenceTaskIds;
  if (extensions.length > 0) value.extensions = extensions;
  return value;
}

/** Read a signed MAGP envelope back out of an incoming `Message`, or null if the extension was
 *  never used — `guardA2ATask` treats that as MAGP_ENVELOPE_MISSING, not as an implicit permit. */
export function extractEnvelope(message) {
  return message?.metadata?.[MAGP_A2A_EXTENSION_URI] ?? null;
}

// --- Decision -> TaskState mapping (spec §5 of the scope doc; no MCP analog) -------------------

/** The subset of A2A's real `TaskState` enum this guard emits (verified against `a2a.proto`,
 *  not the prose spec — see the scope doc for why that distinction mattered). */
export const TASK_STATE = {
  WORKING: 'TASK_STATE_WORKING',
  INPUT_REQUIRED: 'TASK_STATE_INPUT_REQUIRED',
  AUTH_REQUIRED: 'TASK_STATE_AUTH_REQUIRED',
  REJECTED: 'TASK_STATE_REJECTED',
};

/** Reason codes that mean "the caller's identity/signature/envelope itself is the problem" —
 *  mapped to TASK_STATE_AUTH_REQUIRED, the spec's own more precise state for exactly this,
 *  rather than the generic REJECTED every other block reason gets. Free to implement (a
 *  different enum value, not new logic), so there's no reason not to be precise here. */
const AUTH_FAILURE_REASON_CODES = new Set([
  'MAGP_ENVELOPE_MISSING',
  'MALFORMED_REQUEST',
  'SIGNATURE_INVALID',
  'CONTEXT_SIGNATURE_INVALID',
  'CONTEXT_SIGNATURE_REQUIRED',
  'REQUEST_EXPIRED',
  'BUNDLE_SUBJECT_MISMATCH',
  'POLICY_BUNDLE_UNSIGNED',
  'POLICY_BUNDLE_STALE',
  'POLICY_BUNDLE_SIGNATURE_INVALID',
]);

/**
 * Map a MetaMynd gate decision to the A2A TaskState that best expresses it. Pure, total (every
 * decision this guard can produce maps to something) — see the scope doc's §5 table for the
 * rationale behind each row.
 * @returns {{ taskState: string, permitted: boolean }}
 */
export function mapDecisionToTaskState(decision, reasonCode) {
  if (decision === 'allow' || decision === 'observe') return { taskState: TASK_STATE.WORKING, permitted: true };
  if (decision === 'escalate') return { taskState: TASK_STATE.INPUT_REQUIRED, permitted: false };
  // block / suspend / quarantine (and anything unrecognised) all deny execution. AUTH_REQUIRED
  // is reserved for the identity/envelope-shaped subset; everything else — a real policy
  // refusal, or containment — is REJECTED. Containment's specific reason still travels in the
  // returned TaskStatus's message metadata (see buildTaskStatus), so nothing is lost by folding
  // suspend/quarantine into the same terminal state A2A itself offers no closer analog for.
  if (AUTH_FAILURE_REASON_CODES.has(reasonCode)) return { taskState: TASK_STATE.AUTH_REQUIRED, permitted: false };
  return { taskState: TASK_STATE.REJECTED, permitted: false };
}

/**
 * Build a wire-shaped `TaskStatus` (camelCase JSON, matching A2A's proto3-JSON mapping) carrying
 * the guard's verdict — for a refusal, this IS the response; nothing throws. `escalationId`
 * (present only on an ESCALATE from a bundle that names one) lets the initiating agent poll the
 * exact same `escalation_status()`/`escalationStatus()` every existing client already implements,
 * unmodified.
 */
export function buildTaskStatus({ decision, reasonCode, escalationId, contextId, taskId }) {
  const { taskState } = mapDecisionToTaskState(decision, reasonCode);
  const summary =
    taskState === TASK_STATE.WORKING
      ? 'permitted'
      : taskState === TASK_STATE.INPUT_REQUIRED
        ? `held for review: ${reasonCode}`
        : taskState === TASK_STATE.AUTH_REQUIRED
          ? `authorization required: ${reasonCode}`
          : `refused: ${reasonCode}`;
  return {
    state: taskState,
    message: {
      messageId: `metamynd-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      contextId: contextId ?? null,
      taskId: taskId ?? null,
      role: 'agent',
      parts: [{ text: summary }],
      metadata: { [MAGP_A2A_EXTENSION_URI]: { decision, reasonCode, escalationId: escalationId ?? null } },
    },
    timestamp: new Date().toISOString(),
  };
}

// --- Receiver-side guard -------------------------------------------------------------------

/**
 * @param {object} cfg
 * @param {string} [cfg.serviceDid] this agent's own DID — attribution only (logging/evidence);
 *   no handshake or signing happens on this side, so unlike agentsafe-mcp-guard this is never
 *   required.
 * @param {string} [cfg.issuerApi] the issuer API base (e.g. https://metamynd.ai/api/v1) to fetch
 *   the calling agent's policy bundle from.
 * @param {(agentDid:string)=>Promise<object>} [cfg.fetchBundle] override bundle loading
 *   (tests / caching).
 * @param {string} [cfg.policyPublicKey] MetaMynd's Ed25519 policy-signing key (hex). When set,
 *   the guard verifies the bundle's own signature + freshness and fails closed for EVERY action, amount 0
 *   included, on an unsigned/tampered/stale bundle — see magp-policy.mjs. Without it the bundle is only as
 *   trustworthy as the transport: over plain http:// nothing authenticates it, so every task is refused
 *   (POLICY_BUNDLE_UNVERIFIED, 0.13.3) unless `allowUnverifiedBundle` is set.
 * @param {boolean} [cfg.allowUnverifiedBundle] accept tasks on a bundle fetched over plain http:// with no
 *   `policyPublicKey` pinned. Off by default: a proxy on that path can rewrite the rules — lift a spend cap, or grant
 *   an amount-0 action the agent never had. For local development only. (Ported from agentsafe-mcp-guard.)
 * @param {boolean} [cfg.requireAuthorization] when true, a PERMIT is only granted if the
 *   envelope's `authorizationId` atomically claims single-use execution against the stateful
 *   issuer gate — closes REPLAY and CUMULATIVE SPEND, which a stateless re-check alone cannot.
 *   Ported unchanged from agentsafe-mcp-guard: this protection is transport-agnostic, and there
 *   is no A2A-specific reason to drop it. Off by default, same reasoning as the MCP guard: it
 *   costs a network round trip per value-bearing task.
 * @param {boolean} [cfg.requireContextSignature] when true, an envelope with no `envelopeSignature` (the agent's own
 *   signature over its context — context-claim binding) is refused CONTEXT_SIGNATURE_REQUIRED before any rule is
 *   evaluated. Off by default: the signature is optional (agentsafe-guard >= 0.17.0 sends it unless `signContext: false`), and a
 *   PRESENT one is always verified either way. Turn it on where the caller's context drives a decision and anything can
 *   sit between the caller and this agent — without it, a relay can strip the signature and rewrite the context.
 *   Overridable per skill (guardA2ATask option) and per call (verifyRequest option).
 * @param {string[]|'any'} [cfg.allowedAgents] the agent DIDs this agent accepts tasks from (MAGP §16.3). A task signed by
 *   any other agent is refused `AGENT_NOT_ADMITTED` before its policy is fetched or any authorization is claimed. Every check
 *   judges the CALLER against the CALLER's own policy, so without this an agent that acts with its owner's credentials
 *   does so for any agent on the platform whose own owner granted it a matching action (XT-1, ported from
 *   agentsafe-mcp-guard). `'any'` accepts every governed agent on purpose. Left unset, it accepts every agent, as before
 *   0.15.0, and says so once at startup.
 */
/**
 * The `allowedAgents` option (MAGP §16.3): `serves(agentDid)` over a verified agent DID, and `pinned` — reported as
 * `guard.allowedAgents` (the DIDs, `'any'`, or `null` when unset). A list must name at least one DID, each a non-empty
 * string — a typo is an agent that serves nobody or everybody, so it fails at startup. Unset accepts every agent, as
 * before, and warns once. (Same as agentsafe-mcp-guard's.)
 */
export function agentAllowList(allowedAgents, label) {
  if (allowedAgents === 'any') {
    console.warn(`[${label}] allowedAgents: 'any' — this Service acts for EVERY governed agent, each judged only by its own owner's rules. Right only for a public tool, or one that resolves each caller's own credential (the Credential Vault); never for a Service that holds one owner's credentials (MAGP §16.3).`);
    return { serves: () => true, pinned: 'any' };
  }
  // Unset is a startup error (pre-beta refinement plan, 2026-10-04): a Service that holds credentials must name whom it
  // acts for, and serving everyone has to be said out loud ('any') — it is never what an omission means.
  if (allowedAgents === undefined || allowedAgents === null) {
    throw new Error(`${label}: allowedAgents is required — the agent DIDs this Service acts for (MAGP §16.3), or 'any' for a Service that holds no one owner's credentials`);
  }
  if (!Array.isArray(allowedAgents) || allowedAgents.length === 0 || allowedAgents.some((d) => typeof d !== 'string' || d.trim() === '')) {
    throw new Error(`${label}: allowedAgents must be 'any' or a non-empty array of agent DIDs`);
  }
  const allowed = new Set(allowedAgents.map((d) => d.trim()));
  return { serves: (agentDid) => allowed.has(agentDid), pinned: Object.freeze([...allowed]) };
}

/** The principal whose credentials this agent acts with (§16.3); required with an allowedAgents list. Same as agentsafe-mcp-guard's. */
export function gatewayOwnerFor(pinned, gatewayOwnerPrincipal, label) {
  if (pinned === 'any') return null;
  if (typeof gatewayOwnerPrincipal !== 'string' || !/^did:[a-z0-9]+:\S+$/.test(gatewayOwnerPrincipal.trim())) {
    throw Object.assign(new Error(`${label}: gatewayOwnerPrincipal is required with allowedAgents — the principal DID that owns the credentials this agent acts with (GATEWAY_OWNER_UNBOUND, MAGP §16.3)`), { code: 'GATEWAY_OWNER_UNBOUND' });
  }
  return gatewayOwnerPrincipal.trim();
}

/** A skill's own admitted agents: a non-empty list of DIDs; a malformed one fails startup. */
export function assertProfileAgents(list, where) {
  if (!Array.isArray(list) || list.length === 0 || list.some((d) => typeof d !== 'string' || d.trim() === '')) {
    throw new Error(`allowedAgents for ${where} must be a non-empty array of agent DIDs`);
  }
}

/** Does a skill's profile admit this (verified) agent? A malformed profile admits nobody. */
export function profileAdmits(list, agentDid) {
  return Array.isArray(list) && list.some((d) => typeof d === 'string' && d.trim() === agentDid);
}

/**
 * A `trustedContext` this skill's author configured must be a real object, and any `riskLevel` in it a real level.
 * One that is not (a lookup that missed, a typo) means the deriver is BROKEN, and the safe reading is a refused
 * task, never "carry on with the agent's word". `undefined` means "not configured". Ported from agentsafe-mcp-guard.
 */
function assertTrustedContext(tc, where) {
  if (tc === undefined) return;
  if (tc === null || typeof tc !== 'object' || Array.isArray(tc)) throw new Error(`trustedContext${where ? ` for ${where}` : ''} must be an object (got ${tc === null ? 'null' : Array.isArray(tc) ? 'an array' : typeof tc})`);
  if (Object.prototype.hasOwnProperty.call(tc, 'riskLevel') && normalizeRiskLevel(tc.riskLevel) === null) {
    throw new Error(`trustedContext${where ? ` for ${where}` : ''}.riskLevel is not one of low|medium|high|critical`);
  }
}

export function createA2aGuard({ serviceDid, serviceKey, issuerApi, fetchBundle, policyPublicKey, requireAuthorization = false, allowUnverifiedBundle = false, requireContextSignature: requireContextSignatureDefault = false, allowedAgents, gatewayOwnerPrincipal } = {}) {
  const { serves: servesAgent, pinned: allowedAgentsPinned } = agentAllowList(allowedAgents, 'a2a-guard');
  const owner = gatewayOwnerFor(allowedAgentsPinned, gatewayOwnerPrincipal, 'a2a-guard');
  const base = issuerApi ? issuerApi.replace(/\/$/, '') : null;
  // TLS or loopback: only then may a grant's `approvedByHuman` lift an escalate (§8.7.18) — see agentsafe-mcp-guard.
  const issuerChannelAuthenticated = !!base && (/^https:\/\//i.test(base) || /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(base));
  // With no policyPublicKey, nothing but the transport vouches for the policy bundle. Over plain http:// nothing does: a
  // proxy on the path can rewrite the rules and the guard would enforce the forged ones. A custom fetchBundle is the
  // integrator's own source, so it is left to them. (agentsafe-mcp-guard's D-08 rule, which this guard lacked until 0.13.3.)
  const bundleUnauthenticated = !policyPublicKey && typeof fetchBundle !== 'function' && !!base && !/^https:\/\//i.test(base);
  if (!policyPublicKey && base) {
    console.warn(
      bundleUnauthenticated
        ? `[a2a-guard] no policyPublicKey and the issuer is not https (${base}): nothing authenticates the policy bundle. Every task is refused (POLICY_BUNDLE_UNVERIFIED)${allowUnverifiedBundle ? ' — except allowUnverifiedBundle is set, so they are NOT' : ''}. Pin policyPublicKey (GET /magp/policy/pubkey, out of band).`
        : '[a2a-guard] no policyPublicKey: the policy bundle is trusted on the strength of TLS alone. Pin policyPublicKey (GET /magp/policy/pubkey, out of band) so a rewritten bundle is refused.',
    );
  }
  // Optional: this agent's own Ed25519 key (Hedera DER hex). With a self-certifying `serviceDid`
  // (did:key / did:hedera) it lets the guard SIGN its settlement-surface calls as its own identity — see
  // serviceAuthHeaders. Without it every call stays anonymous, exactly as before.
  const servicePrivateKey = serviceKey ? crypto.createPrivateKey({ key: Buffer.from(serviceKey, 'hex'), format: 'der', type: 'pkcs8' }) : null;

  /** Headers that sign one settlement-surface call as this agent's own DID (see agentsafe-mcp-guard's serviceAuthHeaders). */
  function serviceAuthHeaders(action, authorizationId, fields = []) {
    if (!servicePrivateKey || !serviceDid || !/^did:(key|hedera):/.test(serviceDid)) return {};
    const escape = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    const message = ['MAGP-SERVICE-v1', action, authorizationId, ...fields, nonce, issuedAt].map(escape).join('|');
    const signature = crypto.sign(null, Buffer.from(message, 'utf8'), servicePrivateKey).toString('hex');
    return { 'x-magp-service-did': serviceDid, 'x-magp-service-nonce': nonce, 'x-magp-service-issued-at': issuedAt, 'x-magp-service-signature': signature };
  }

  /**
   * The code of an issuer refusal (MAGP §8.7.8): `data.reasonCode` first (every refusal carries it, and a 200 `NOT_HELD`
   * void has it only there), then the bare-code `message`. Branch on it, never on `detail`. Same as agentsafe-mcp-guard.
   */
  const refusalCode = (body, fallback) => body?.data?.reasonCode ?? body?.message ?? fallback;
  /** The standard refusal body's sentence for people (`data.detail`) — for logs only. */
  const refusalDetail = (body) => (typeof body?.data?.detail === 'string' ? { detail: body.data.detail } : {});

  /**
   * Claim the authorization, retrying ONCE when the answer is lost. Every claim CALL carries a fresh
   * unguessable `Idempotency-Key`, reused only for the retry of that same call, so the issuer can recognise a
   * retry as this claimant's own and return the original grant (`replayed: true`) instead of refusing — a claim
   * that landed but whose response was lost would otherwise leave the hold claimed with nobody executing it.
   * Only an AMBIGUOUS failure (no response, or a 5xx) is retried; a definite answer, including
   * AUTHORIZATION_ALREADY_CLAIMED, is final. Ported unchanged from agentsafe-mcp-guard.
   */
  // `x402: true` declares the hold is settled by an x402 payment (MAGP §8.7.9 / §11): the issuer records it as x402-bound, so a
  // settlement below the authorization (or a release after the claim) must be confirmed by an independent observer. It only
  // widens checks, so it is a plain body flag; unset, the claim request is exactly as before.
  // `requireHumanApproval: true` (MAGP §8.7.18): grant only a hold a PERSON approved — see agentsafe-mcp-guard's own note.
  // `expect` (MAGP §8.7.19): what this receiver is about to execute, compared by the issuer BEFORE it claims.
  async function claimAuthorization({ authorizationId, payloadDigest, x402 = false, requireHumanApproval = false, expect } = {}) {
    if (!authorizationId) return { claimed: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    if (!base) throw new Error('issuerApi is required to claim an authorization');
    if (payloadDigest !== undefined && !isPayloadDigest(payloadDigest)) return { claimed: false, reasonCode: 'PAYLOAD_DIGEST_INVALID' };
    const idempotencyKey = crypto.randomUUID().replace(/-/g, '');
    const attempts = 2;
    let lastError;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      try {
        // `payloadDigest` — the digest of exactly what THIS receiver is about to execute — is one more signed field and rides as a
        // header: the issuer compares it with the digest the AGENT signed for this authorization and refuses the claim (leaving the
        // hold unclaimed) on any difference. Payload binding, spec 8.3.9 / 8.7.11.
        const auth = serviceAuthHeaders('claim', authorizationId, [idempotencyKey, ...(payloadDigest ? [claimDigestField(payloadDigest)] : [])]);
        const flags = { ...(x402 === true ? { x402: true } : {}), ...(requireHumanApproval === true ? { requireHumanApproval: true } : {}), ...(expect && typeof expect === 'object' ? { expect } : {}) };
        const hasFlags = Object.keys(flags).length > 0;
        const res = await fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/effect/dispatching`, {
          method: 'POST',
          headers: { ...auth, 'idempotency-key': idempotencyKey, ...(payloadDigest ? { [PAYLOAD_DIGEST_HEADER]: payloadDigest } : {}), ...(hasFlags ? { 'Content-Type': 'application/json' } : {}) },
          ...(hasFlags ? { body: JSON.stringify(flags) } : {}),
        });
        const body = await res.json().catch(() => null);
        // Ambiguous, so worth one retry with the same key: a 5xx, or EFFECT_TRANSITION_CONTENDED (an overlapping
        // attempt of yours is mid-claim — not a refusal).
        const ambiguous = res.status >= 500 || (res.status === 409 && body?.message === 'EFFECT_TRANSITION_CONTENDED');
        if (ambiguous && attempt < attempts) { lastError = `HTTP ${res.status}`; await new Promise((r) => setTimeout(r, 150)); continue; }
        if (!res.ok) return { claimed: false, reasonCode: refusalCode(body, `AUTHORIZATION_CLAIM_HTTP_${res.status}`) };
        return {
          claimed: true,
          agentDid: body?.data?.agentDid,
          action: body?.data?.action,
          amount: body?.data?.amount,
          currency: body?.data?.currency,
          merchant: body?.data?.merchant,
          // The digest the agent signed for this authorization (null = unbound); absent from an issuer that predates it.
          payloadDigest: body?.data?.payloadDigest,
          // Whether a person approved this hold (§8.7.18). Only `true` counts; absent (an older issuer) is not an approval.
          approvedByHuman: body?.data?.approvedByHuman === true,
          // The settlement token the issuer hands ONLY the caller whose claim succeeded. Once a hold is
          // claimed it can be settled below its amount, or voided, only with this token — so the skill
          // that executes must keep it and present it (captureAuthorization / releaseAuthorization).
          claimToken: body?.data?.claimToken,
          counterpartyAuthenticated: 'x-magp-service-did' in auth,
          replayed: body?.data?.replayed === true,
        };
      } catch (err) {
        lastError = String(err?.message ?? err);
        if (attempt < attempts) { await new Promise((r) => setTimeout(r, 150)); continue; }
      }
    }
    return { claimed: false, reasonCode: 'AUTHORIZATION_CLAIM_UNREACHABLE', error: lastError };
  }

  /**
   * What became of an authorization (public, keyed by the authorization id): `outcome`, `nothingExecuted`
   * (nothing ran so far) and `retrySafe` (nothing can run later either — retry ONLY on this; a `not_started`
   * hold is still claimable). Best-effort and non-throwing. Ported unchanged from agentsafe-mcp-guard.
   */
  async function lookupOutcome({ authorizationId } = {}) {
    if (!authorizationId) return { ok: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    if (!base) return { ok: false, reasonCode: 'ISSUER_API_REQUIRED' };
    try {
      const res = await fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/effect`);
      const body = await res.json().catch(() => null);
      if (!res.ok || !body?.data) return { ok: false, status: res.status, reasonCode: refusalCode(body, `OUTCOME_HTTP_${res.status}`) };
      return { ok: true, ...body.data };
    } catch (err) {
      return { ok: false, reasonCode: 'ISSUER_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }

  /**
   * Attach the claim to a PERMIT verdict as NON-ENUMERABLE properties: a verdict is routinely echoed
   * onward, and the calling agent is exactly the party the claim token must be kept from. Ported
   * unchanged from agentsafe-mcp-guard.
   */
  function withClaim(verdict, authorizationId, claimToken, authenticated = false) {
    if (!claimToken && !authenticated) return verdict;
    const out = { ...verdict };
    if (claimToken) Object.defineProperty(out, 'claimToken', { value: claimToken, enumerable: false });
    if (authenticated) Object.defineProperty(out, 'counterpartyAuthenticated', { value: true, enumerable: false });
    Object.defineProperty(out, 'authorizationId', { value: authorizationId, enumerable: false });
    return out;
  }

  /**
   * One best-effort call to the issuer's settlement surface. Never throws. On success the response's `data` (e.g.
   * capture's `settlementEvidence`/`amountCharged`/`authorizedAmount`) is kept at `.data` (unchanged) AND spread onto
   * the top level, same convention `lookupOutcome` already used — same as `agentsafe-mcp-guard`'s own `issuerPost`.
   * A refusal is `{ ok: false, status, reasonCode, detail? }`: the issuer's stable code and the one HTTP status that code
   * always has (MAGP §8.7.8 — state conflicts such as NOT_HELD / HOLD_STATE_CHANGED / NOT_CAPTURED / ALREADY_REFUNDED are
   * 409, COUNTERPARTY_MISMATCH 403, an unknown id 404 AUTHORIZATION_NOT_FOUND). Branch on `reasonCode`.
   */
  async function issuerPost(path, body, extraHeaders = {}) {
    if (!base) return { ok: false, reasonCode: 'ISSUER_API_REQUIRED' };
    try {
      const res = await fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...extraHeaders }, body: JSON.stringify(body ?? {}) });
      const payload = await res.json().catch(() => null);
      if (!res.ok) return { ok: false, status: res.status, reasonCode: refusalCode(payload, `ISSUER_HTTP_${res.status}`), ...refusalDetail(payload) };
      if (payload?.success === false) return { ok: false, status: res.status, reasonCode: refusalCode(payload, 'NOT_APPLIED'), ...refusalDetail(payload), data: payload?.data ?? null };
      const data = payload?.data ?? null;
      return { ok: true, status: res.status, ...(data && typeof data === 'object' ? data : {}), data };
    } catch (err) {
      return { ok: false, reasonCode: 'ISSUER_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }

  /** Settle a claimed hold once the skill has executed. See agentsafe-mcp-guard's captureAuthorization. */
  // `payTo`: the account this Service paid — needed when settling BELOW the authorization (the owner's merchant payee
  // directory, MAGP §8.7.14, and the settlement observer check it). Not a signed field; read only after the claimer is proven.
  async function captureAuthorization({ authorizationId, claimToken, amountCharged, bookingRef, settlementTxHash, payTo } = {}) {
    if (!authorizationId) return { ok: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    if (!Number.isFinite(Number(amountCharged))) return { ok: false, reasonCode: 'AMOUNT_CHARGED_REQUIRED' };
    const amount = Number(amountCharged);
    return issuerPost(`/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/capture`, { amountCharged: amount, bookingRef, settlementTxHash, claimToken, ...(payTo ? { payTo: String(payTo) } : {}) }, serviceAuthHeaders('capture', authorizationId, [String(amount), bookingRef ?? '', settlementTxHash ?? '']));
  }

  /** Release a claimed hold whose effect provably did NOT happen. Needs the claim token. */
  async function releaseAuthorization({ authorizationId, claimToken, reason } = {}) {
    if (!authorizationId) return { ok: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    return issuerPost(`/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/void`, { reason, claimToken }, serviceAuthHeaders('void', authorizationId, [reason ?? '']));
  }

  /** Report an ambiguous outcome: the spend stays committed and goes to reconciliation. */
  // `claimToken`: an anonymous claim's token — the issuer now requires the claimer to prove itself (a signed claim signs instead).
  async function markAuthorizationUnknown({ authorizationId, reason, claimToken } = {}) {
    if (!authorizationId) return { ok: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    return issuerPost(`/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/effect/unknown`, { reason, ...(claimToken ? { claimToken } : {}) }, serviceAuthHeaders('unknown', authorizationId, [reason ?? '']));
  }

  /**
   * Record a refund of an already-CAPTURED hold (record-only: no money moves; the cap stops counting it). `amount`
   * omitted = everything still captured. Only the hold's claimer may refund it (or its owner / an admin): a keyed receiver
   * signs the dedicated `refund` action over `[amount ('' = full), reason]`; an anonymous claimer passes its `claimToken`.
   * See agentsafe-mcp-guard's refundAuthorization.
   */
  async function refundAuthorization({ authorizationId, amount, reason, claimToken } = {}) {
    if (!authorizationId) return { ok: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    if (amount !== undefined && !(Number.isFinite(Number(amount)) && Number(amount) > 0)) return { ok: false, reasonCode: 'REFUND_AMOUNT_INVALID' };
    const amountField = amount === undefined ? '' : String(Number(amount));
    return issuerPost(`/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/refund`, { ...(amount !== undefined ? { amount: Number(amount) } : {}), ...(reason !== undefined ? { reason } : {}), ...(claimToken ? { claimToken } : {}) }, serviceAuthHeaders('refund', authorizationId, [amountField, reason ?? '']));
  }

  async function loadBundle(agentDid) {
    if (typeof fetchBundle === 'function') return fetchBundle(agentDid);
    if (!base) throw new Error('issuerApi (or fetchBundle) is required to load the policy bundle');
    const res = await fetch(`${base}/policy/bundle/${encodeURIComponent(agentDid)}`).catch((err) => { throw gateUnreachable(err); });
    if (res.status >= 500) throw gateUnreachable(`HTTP ${res.status}`);
    const body = await res.json().catch(() => null);
    if (!res.ok || !body?.data) throw new Error(`policy bundle fetch failed (HTTP ${res.status})`);
    Object.defineProperty(body.data, '__contained', { value: body?.contained ?? null, enumerable: false, configurable: true });
    Object.defineProperty(body.data, '__operatingMode', { value: body?.operatingMode ?? null, enumerable: false, configurable: true });
    return body.data;
  }

  /** Evaluate the caller's bundle against the request via policy-core (signed fields last) — same
   *  logic as agentsafe-mcp-guard's verdictFromBundle, ported unchanged (transport-agnostic). */
  function verdictFromBundle(bundle, req, trustedContext) {
    const { agentDid, action, amount = 0, currency = 'USD', merchant = '', resource = null, cumulativeSpend = amount, now } = req;
    // The SIGNED jurisdiction (spec §8.3.12, verified with the v2 message in verifyRequest), upper-cased — never the
    // context's unsigned `jurisdiction` / `mm:jurisdiction`, dropped here as the gate drops it.
    const jurisdiction = typeof req.jurisdiction === 'string' ? req.jurisdiction.toUpperCase() : undefined;
    // The agent's unsigned context: `itinerary`, already resolved by verifyRequest (unsignedContextOf).
    const context = withoutUnsignedJurisdiction(req.itinerary ?? {});
    const mandates = bundle.mandates ?? [];
    const mandate = mandates.find((m) => m.action === action)?.document;
    if (!mandate) {
      // Granted once and revoked (bundle `revokedActions`, §6.2.6) — names the refusal, never decides it.
      const revoked = Array.isArray(bundle.revokedActions) && bundle.revokedActions.includes(action);
      return { decision: 'block', reasonCode: revoked ? 'MANDATE_REVOKED' : mandates.length > 0 ? 'NO_PERMISSION_FOR_ACTION' : 'NO_MANDATE' };
    }
    const standards = (bundle.standards ?? []).map((s) => ({ standardKey: s.key, document: s.document }));
    const sops = (bundle.sops ?? []).map((s) => ({ standardKey: `sop:${s.id}`, document: s.document }));
    const verdict = evaluate({
      standards,
      sops,
      mandate,
      // Labelled by source (spec §6.4.3): the agent's `context` is its own word; `trustedContext` is what THIS
      // skill's author derived from the real call; the mandate's `riskTier` is a floor under the claimed risk.
      context: buildRuleContext({
        unsigned: context,
        signed: { action, agentDid, amount, currency, merchant, resource, ...(jurisdiction ? { jurisdiction } : {}) },
        gatewayDerived: trustedContext,
        riskFloor: riskFloorFor(mandate, action),
      }),
      mandateRequest: {
        target: action,
        now: now ?? new Date().toISOString(),
        values: applySignedLast(context, {
          'mm:payAmount': amount,
          'mm:cumulativeSpend': cumulativeSpend,
          'mm:merchant': merchant,
          'mm:currency': currency,
          resource,
          // The allowed-jurisdictions term: with none signed it fails JURISDICTION_REQUIRED, as at the gate.
          'mm:jurisdiction': jurisdiction,
          jurisdiction,
        }),
      },
    });
    // An enforced jurisdiction rule with nothing signed (or derived by this skill): JURISDICTION_REQUIRED, a hard block
    // that outranks an escalate — as at the gate, since the atom does not fire on a missing value.
    const hardStop = verdict.decision === 'block' || verdict.decision === 'suspend' || verdict.decision === 'quarantine';
    const derivedJurisdiction = trustedContext && typeof trustedContext.jurisdiction === 'string' && trustedContext.jurisdiction !== '';
    if (!jurisdiction && !derivedJurisdiction && !hardStop && [...standards, ...sops].some((s) => documentEnforcesJurisdiction(s.document))) {
      return { decision: 'block', reasonCode: 'JURISDICTION_REQUIRED', authorizationId: null, remaining: null, proofRef: null };
    }
    return verdict;
  }

  /**
   * Verify a caller's presented signed MAGP envelope, then re-evaluate policy locally against
   * their issuer-hosted bundle. Fails CLOSED on any bad signature, staleness, fetch error, or
   * evaluation error. Ported from agentsafe-mcp-guard's `verifyRequest` — same steps, no
   * handshake precondition (there is none here) and no capability/x402 binding (out of scope
   * for A2A v1 per the scope doc).
   * @param {{agentDid,action,amount?,currency?,merchant?,resource?,itinerary?,nonce,issuedAt,signature,authorizationId?}} signed (`context` = deprecated alias of `itinerary`, see unsignedContextOf)
   * @param {{ trustedContext?: Record<string, unknown> }} [options] context THIS skill's author derived from the
   *   real call (e.g. `{ riskLevel: 'high' }`), never anything the agent sent: it outranks the agent's claim and is
   *   labelled `gateway_derived`. See agentsafe-mcp-guard's verifyRequest. `requireContextSignature`: this call's override
   *   of the guard's `requireContextSignature` (refuse an envelope with no `envelopeSignature`); a present one is always verified.
   * @returns {Promise<{decision:'allow'|'observe'|'block'|'escalate'|'suspend'|'quarantine',reasonCode:string|null}>}
   */
  async function verifyRequest(signed = {}, { trustedContext, payloadDigest, requirePayloadBinding, requireContextSignature, x402 = false, allowedAgents: profileAgents } = {}) {
    try {
      assertTrustedContext(trustedContext); // a broken deriver is a refused task (GUARD_ERROR), never a quiet downgrade
      const { agentDid, action, amount = 0, currency = 'USD', merchant = '', resource = null, nonce, issuedAt, signature, jurisdiction } = signed;
      if (!agentDid || !action || !nonce || !issuedAt || !signature) {
        return { decision: 'block', reasonCode: 'MALFORMED_REQUEST' };
      }
      // A signed jurisdiction (spec §8.3.12) is two ASCII letters, as the gate accepts it; null reads as absent.
      if (jurisdiction !== undefined && jurisdiction !== null && (typeof jurisdiction !== 'string' || !/^[A-Za-z]{2}$/.test(jurisdiction))) {
        return { decision: 'block', reasonCode: 'MALFORMED_REQUEST' };
      }
      // The unsigned context under its canonical name `itinerary` (a deprecated `context` alias is read only when it
      // cannot disagree with it). Everything below — risk, rules, the mandate's context operands — reads THIS object.
      const unsigned = unsignedContextOf(signed);
      if (!unsigned.ok) return { decision: 'block', reasonCode: 'MALFORMED_REQUEST' };
      const itinerary = unsigned.itinerary;
      // `jurisdiction` present → the v2 message, absent → v1; the shape follows the request and never falls back.
      const message = buildAuthMessage({ agentDid, action, amount, currency, merchant, resource, nonce, issuedAt, jurisdiction });
      if (!verifyDidSignature(agentDid, message, signature)) {
        return { decision: 'block', reasonCode: 'SIGNATURE_INVALID' };
      }
      // Is this an agent this one accepts tasks from at all (§16.3)? Asked of the identity the signature just proved, before
      // anything else: everything below judges the caller by the caller's own policy, which another owner writes.
      if (!servesAgent(agentDid)) return { decision: 'block', reasonCode: 'AGENT_NOT_ADMITTED' };
      // A skill (credential profile) may admit fewer agents than this agent does (§16.3).
      if (profileAgents !== undefined && !profileAdmits(profileAgents, agentDid)) return { decision: 'block', reasonCode: 'CREDENTIAL_PROFILE_NOT_PERMITTED' };
      // The agent's context signature (context-claim binding), in the gate's order: after the request signature, before
      // payload binding and before any rule. The itinerary is otherwise unsigned, so without this a relay between the agent
      // and this receiver could rewrite what the rules below judge. The object hashed is the one evaluated below.
      const hasItinerary = signed.itinerary !== undefined && signed.itinerary !== null;
      const contextRefusal = contextSignatureRefusal(signed, hasItinerary ? itinerary : undefined, requireContextSignature ?? requireContextSignatureDefault);
      if (contextRefusal) return { decision: 'block', reasonCode: contextRefusal };
      // Payload binding (spec 8.3.9). A digest with no valid signature over it binds nothing — refuse it. When THIS receiver states
      // the digest of what it is about to execute (`payloadDigest`), it must be the one the agent signed: a mismatch is refused here,
      // before any claim, so it costs no round trip. (The ISSUER re-checks the same thing against the digest it stored at authorize
      // time when the claim is made — this early check is only cheaper, never the authority.)
      const signedDigest = signed.payloadDigest;
      if (signedDigest !== undefined || signed.payloadSignature !== undefined) {
        const bound = isPayloadDigest(signedDigest) && typeof signed.payloadSignature === 'string'
          && verifyDidSignature(agentDid, buildPayloadBindingMessage({ agentDid, action, nonce, issuedAt, payloadDigest: signedDigest }), signed.payloadSignature);
        if (!bound) return { decision: 'block', reasonCode: 'PAYLOAD_BINDING_INVALID' };
      }
      if (payloadDigest !== undefined) {
        if (!isPayloadDigest(payloadDigest)) return { decision: 'block', reasonCode: 'PAYLOAD_DIGEST_INVALID' };
        if (signedDigest === undefined) {
          // The receiver has a payload; the agent bound none. Refuse only when binding is REQUIRED — otherwise this is an unbound
          // request, exactly as before payload binding existed (and it is not claimed with a digest: see below).
          if (requirePayloadBinding) return { decision: 'block', reasonCode: 'PAYLOAD_BINDING_REQUIRED' };
        } else if (signedDigest !== payloadDigest) {
          return { decision: 'block', reasonCode: 'PAYLOAD_NOT_BOUND' };
        }
      } else if (requirePayloadBinding && signedDigest === undefined) {
        return { decision: 'block', reasonCode: 'PAYLOAD_BINDING_REQUIRED' };
      }
      const ts = Date.parse(issuedAt);
      const age = Date.now() - ts;
      if (Number.isNaN(ts) || age > FRESHNESS_MS || age < -CLOCK_SKEW_TOLERANCE_MS) {
        return { decision: 'block', reasonCode: 'REQUEST_EXPIRED' };
      }
      const bundle = await loadBundle(agentDid);
      if (bundle?.subject && bundle.subject !== agentDid) {
        return { decision: 'block', reasonCode: 'BUNDLE_SUBJECT_MISMATCH' };
      }
      const contained = bundle?.__contained;
      if (contained && contained.status) {
        const decision = contained.status === 'quarantined' ? 'quarantine' : 'suspend';
        const reasonCode = contained.status === 'quarantined' ? 'AGENT_QUARANTINED' : 'AGENT_SUSPENDED';
        return { decision, reasonCode };
      }
      // The EFFECTIVE risk: the owner's tier and this skill's own derivation are floors under the agent's claim.
      const mandateForRisk = (bundle?.mandates ?? []).find((m) => m.action === action)?.document;
      const effectiveRisk = maxRisk(riskFloorFor(mandateForRisk, action), normalizeRiskLevel(trustedContext?.riskLevel), normalizeRiskLevel(itinerary.riskLevel)) ?? undefined;
      const modeGate = operatingModeGate(bundle?.__operatingMode?.mode, { amount, riskLevel: effectiveRisk });
      if (modeGate.decision === 'block') return { decision: 'block', reasonCode: modeGate.reasonCode };
      if (policyPublicKey) {
        const v = verifyBundle(bundle, { publicKey: policyPublicKey, valueBearing: Number(amount) > 0 });
        if (!v.ok) return { decision: 'block', reasonCode: v.reasonCode };
      } else if (bundleUnauthenticated && !allowUnverifiedBundle) {
        // Nothing authenticates these rules (no pinned key, no TLS): refused for every task, amount 0 included — a
        // rewritten bundle could grant an action as easily as lift a cap.
        return { decision: 'block', reasonCode: 'POLICY_BUNDLE_UNVERIFIED' };
      }
      // The owner (§16.3), from the SIGNED bundle: an admitted agent of any other owner is refused (see agentsafe-mcp-guard).
      if (owner && bundle?.ownerPrincipal !== owner) return { decision: 'block', reasonCode: 'GATEWAY_OWNER_MISMATCH' };
      const verdict = verdictFromBundle(bundle, { ...signed, itinerary }, trustedContext);
      const final =
        (verdict.decision === 'allow' || verdict.decision === 'observe') && modeGate.decision === 'escalate'
          ? { ...verdict, decision: 'escalate', reasonCode: modeGate.reasonCode }
          : verdict;
      let claimToken; let claimAuthenticated = false;
      // An ESCALATE with an authorization attached may already have been decided by a person (MAGP §8.7.18) — the issuer
      // says whether, never the request. Only an escalate is lifted; see agentsafe-mcp-guard's verifyRequest for the full note.
      const reviewed = requireAuthorization && final.decision === 'escalate' && !!signed.authorizationId && issuerChannelAuthenticated;
      let permitted = final;
      if (requireAuthorization && (final.decision === 'allow' || final.decision === 'observe' || reviewed)) {
        // The claim states the digest of what THIS receiver is about to execute — only when the agent bound one (a digest for an
        // unbound authorization is refused by the issuer: this receiver would be asserting a binding that does not exist).
        const claimDigest = payloadDigest !== undefined && signedDigest !== undefined ? payloadDigest : undefined;
        const expect = { agentDid, action, ...(Number.isFinite(Number(amount)) ? { amount: Number(amount) } : {}), currency, merchant };
        const claim = await claimAuthorization({ authorizationId: signed.authorizationId, payloadDigest: claimDigest, x402: x402 === true, requireHumanApproval: reviewed, expect });
        claimToken = claim.claimToken; claimAuthenticated = claim.counterpartyAuthenticated === true;
        // A mismatch found only after the grant (an issuer that predates §8.7.19) must not strand the hold: release, then refuse.
        const refuseClaimed = async (reasonCode) => {
          const released = await releaseAuthorization({ authorizationId: signed.authorizationId, claimToken, reason: reasonCode }).catch((err) => ({ ok: false, reasonCode: String(err?.message ?? err) }));
          if (!released?.ok) console.warn(`[a2a-guard] could not release claimed authorization ${signed.authorizationId} after ${reasonCode} (${released?.reasonCode ?? 'unknown'}) — nothing executed; it settles by reconciliation`);
          return { decision: 'block', reasonCode };
        };
        if (reviewed && claim.reasonCode === 'ESCALATION_NOT_APPROVED') return final;
        if (!claim.claimed) return { decision: 'block', reasonCode: claim.reasonCode };
        if (reviewed) {
          if (!claim.approvedByHuman) {
            const released = await releaseAuthorization({ authorizationId: signed.authorizationId, claimToken, reason: 'ESCALATION_NOT_APPROVED' }).catch((err) => ({ ok: false, reasonCode: String(err?.message ?? err) }));
            if (!released?.ok) console.warn(`[a2a-guard] could not release claimed authorization ${signed.authorizationId} after an unapproved grant (${released?.reasonCode ?? 'unknown'}) — nothing executed; it settles by reconciliation`);
            return final;
          }
          permitted = { ...final, decision: 'allow', reasonCode: 'ESCALATION_APPROVED', escalatedFor: final.reasonCode };
        }
        // The grant states the digest the hold is bound to (null = unbound), so it must be the one this claim stated. The issuer
        // already refused a claim whose digest differed; this catches an issuer that did NOT compare — one that predates payload
        // binding ignores the header and its grant carries no digest, which is "not enforced", never "fine". Only reachable when
        // the agent bound a payload, a flow an issuer that predates binding cannot honour anyway.
        if ((claim.payloadDigest ?? null) !== (claimDigest ?? null)) return refuseClaimed('PAYLOAD_DIGEST_MISMATCH');
        if (claim.agentDid !== undefined && claim.agentDid !== agentDid) return refuseClaimed('AUTHORIZATION_AGENT_MISMATCH');
        if (claim.action !== undefined && claim.action !== action) return refuseClaimed('AUTHORIZATION_ACTION_MISMATCH');
        if (claim.amount !== undefined && Number(claim.amount) !== Number(amount)) return refuseClaimed('AUTHORIZATION_AMOUNT_MISMATCH');
        if (claim.currency !== undefined && claim.currency !== currency) return refuseClaimed('AUTHORIZATION_CURRENCY_MISMATCH');
        if (claim.merchant !== undefined && claim.merchant !== merchant) return refuseClaimed('AUTHORIZATION_MERCHANT_MISMATCH');
      }
      return withClaim(permitted, signed.authorizationId, claimToken, claimAuthenticated);
    } catch (err) {
      // The issuer could not be reached for the bundle: GATE_UNREACHABLE, as the agent guard says it (eval 2026-10-03, N-6).
      return { decision: 'block', reasonCode: err?.code === 'GATE_UNREACHABLE' ? 'GATE_UNREACHABLE' : 'GUARD_ERROR', error: String(err?.message ?? err) };
    }
  }

  /**
   * Wrap the handler for ONE A2A skill so it runs only after trustless verification permits it.
   * `skillId` is authoritative — never a claim read out of the incoming message — the same
   * confused-deputy fix `guardIncomingTool`'s own comment documents, one layer down: a guard
   * registered for many skills must not let a cheap skill's valid envelope run an expensive one's
   * handler.
   *
   * Unlike `guardIncomingTool`, this NEVER throws on a policy decision — A2A tasks have a formal
   * state machine, and a refusal is a valid, structured response (`TaskStatus`), not an
   * exception. It still throws on a genuine programming error (a malformed `message` argument).
   *
   * @param {string} skillId the AgentSkill.id this handler serves
   * @param {(message, task, ...rest) => any} handler your real skill logic
   * @returns {(message, task, ...rest) => Promise<any>} returns the handler's result on permit,
   *   or a `TaskStatus`-shaped refusal object otherwise (see buildTaskStatus) — the caller's own
   *   A2A server code decides how to fold that into its response, since this package does not
   *   assume any particular A2A server SDK.
   */
  function guardA2ATask(skillId, handler, { settle: settleClaim = false, trustedContext, bindPayload = false, bindScope, requirePayloadBinding = false, requireContextSignature, x402 = false, allowedAgents: skillAgents } = {}) {
    if (skillAgents !== undefined) assertProfileAgents(skillAgents, `skill "${skillId}"`);
    // `requirePayloadBinding` only checks that the AGENT bound something; the comparison with what this skill executes needs a
    // digest of it. Without `bindPayload` there is nothing to compare, so the option would give assurance it does not provide.
    if (requirePayloadBinding && !bindPayload) {
      throw new Error(`guardA2ATask("${skillId}"): requirePayloadBinding needs bindPayload — without a digest of what the skill executes there is nothing to compare the binding with`);
    }
    if (bindScope !== undefined && bindScope !== 'parts' && bindScope !== 'message') {
      throw new Error(`guardA2ATask("${skillId}"): bindScope must be 'parts' or 'message'`);
    }
    // The default scope binds only `parts`; a handler reading metadata/referenceTaskIds/extensions reads them unbound. Say so
    // once per skill, until the default changes at the next breaking release (owner decision 2026-09-24).
    if (bindPayload === true && bindScope === undefined) {
      console.warn(`[a2a-guard] guardA2ATask("${skillId}"): bindPayload binds only the message's parts by default; metadata, referenceTaskIds and extensions reach the handler unbound. Pass bindScope: 'message' to bind them too (it becomes the default at the next major release), or bindScope: 'parts' to keep this and silence the warning.`);
    }
    const scope = bindScope ?? 'parts';
    return async (message, task, ...rest) => {
      const envelope = extractEnvelope(message);
      // `trustedContext` (an object, or `(envelope, message, task) => object`) is what this skill's author derived
      // from the real call — never the agent's claim.
      // A refusal is always a structured TaskStatus here, never a throw — so a deriver that THROWS, or is configured
      // but yields nothing usable (a function that returned undefined, a junk riskLevel), becomes a GUARD_ERROR block
      // rather than an exception, and never falls back to the agent's word.
      let decision;
      if (!envelope) {
        decision = { decision: 'block', reasonCode: 'MAGP_ENVELOPE_MISSING' };
      } else {
        try {
          // Payload binding (spec 8.3.9): the digest of what THIS call is about to execute. `bindPayload: true` digests the task's
          // input — the message's `parts` — and hands the handler that same JSON snapshot, so what is digested is what runs; a
          // function `(envelope, message, task) => value` chooses what to digest (and then owns making the handler execute exactly
          // that). Computed BEFORE the request is verified, so a payload JSON cannot carry refuses the task rather than skipping the check.
          let executorDigest;
          if (bindPayload) {
            try {
              const value = typeof bindPayload === 'function' ? await bindPayload(envelope, message, task) : a2aBindingValue(message, scope);
              const wire = toWireJson(value);
              executorDigest = payloadDigestOf(wire);
              // Hand the handler the snapshot that was digested, so what is digested is what runs.
              if (typeof bindPayload !== 'function') {
                if (scope === 'parts') message = { ...message, parts: wire };
                else {
                  const env = message?.metadata?.[MAGP_A2A_EXTENSION_URI];
                  message = {
                    ...message,
                    parts: wire.parts,
                    metadata: { ...(wire.metadata ?? {}), ...(env !== undefined ? { [MAGP_A2A_EXTENSION_URI]: env } : {}) },
                    ...(wire.referenceTaskIds !== undefined ? { referenceTaskIds: wire.referenceTaskIds } : {}),
                    ...(message?.extensions !== undefined ? { extensions: [...(wire.extensions ?? []), ...(message.extensions.includes(MAGP_A2A_EXTENSION_URI) ? [MAGP_A2A_EXTENSION_URI] : [])] } : {}),
                  };
                }
              }
            } catch (err) {
              decision = { decision: 'block', reasonCode: 'PAYLOAD_NOT_CANONICALIZABLE', error: String(err?.message ?? err) };
            }
          }
          if (!decision) {
            const derived = typeof trustedContext === 'function' ? await trustedContext(envelope, message, task) : trustedContext;
            if (trustedContext !== undefined) assertTrustedContext(derived === undefined ? null : derived, `skill "${skillId}"`);
            decision = await verifyRequest({ ...envelope, action: skillId }, { trustedContext: derived, payloadDigest: executorDigest, requirePayloadBinding, requireContextSignature, x402, ...(skillAgents !== undefined ? { allowedAgents: skillAgents } : {}) });
          }
        } catch (err) {
          decision = { decision: 'block', reasonCode: 'GUARD_ERROR', error: String(err?.message ?? err) };
        }
      }
      const { permitted } = mapDecisionToTaskState(decision.decision, decision.reasonCode);
      if (!permitted) {
        return buildTaskStatus({
          decision: decision.decision,
          reasonCode: decision.reasonCode,
          escalationId: decision.escalationId,
          contextId: message?.contextId,
          taskId: message?.taskId ?? task?.id,
        });
      }
      if (decision.decision === 'observe') {
        console.warn(`[a2a-guard] OBSERVE "${skillId}": ${decision.reasonCode} — served under monitoring`);
      }
      if (!requireAuthorization && Number(envelope?.amount) > 0) {
        console.warn(`[a2a-guard] "${skillId}" (amount=${envelope.amount}) permitted in trustless mode — rate-limit, circuit-breaker, replay, cumulative-spend, and spend-anomaly floors are stateful and were NOT re-verified against live issuer state. Set requireAuthorization:true for custodial/value-bearing skills.`);
      }
      // Opt-in settlement of a claimed hold (`requireAuthorization` + `{ settle: true }`): a handler
      // that returns is settled at the authorized amount; one that throws is reported UNKNOWN (a throw
      // does not prove nothing executed), never released. Off by default so existing embeds are unchanged.
      if (settleClaim && (decision.claimToken || decision.counterpartyAuthenticated)) {
        let result;
        try {
          result = await handler(message, task, ...rest);
        } catch (err) {
          await markAuthorizationUnknown({ authorizationId: decision.authorizationId, reason: 'HANDLER_THREW', claimToken: decision.claimToken });
          throw err;
        }
        await captureAuthorization({ authorizationId: decision.authorizationId, claimToken: decision.claimToken, amountCharged: Number(envelope?.amount) });
        return result;
      }
      return handler(message, task, ...rest);
    };
  }

  return { verifyRequest, guardA2ATask, claimAuthorization, lookupOutcome, captureAuthorization, releaseAuthorization, markAuthorizationUnknown, refundAuthorization, serviceDid: serviceDid ?? null, allowedAgents: allowedAgentsPinned, gatewayOwnerPrincipal: owner };
}

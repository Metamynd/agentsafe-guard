// agentsafe-mcp-guard.mjs — the SERVICE (MCP) side of MAGP governance.
//
// A Service is an identity-bearing peer (MAGP §4.6). This guard lets an MCP:
//   1. complete the mutual handshake (§8.2) — prove it controls its DID and verify
//      the counterparty controls theirs, with NO calls to the issuer (keys are in
//      the DIDs, §4.1.2); and
//   2. enforce TRUSTLESSLY (§9.3, §9.6) — independently re-evaluate the agent's
//      signed authorize request against the agent's issuer-hosted policy bundle
//      using the same deterministic policy-core the gate runs. The Service never
//      has to trust the agent's own guard.
//
// Dependencies are the two generated, zero-external-dependency bundles:
//   policy-core.mjs (deterministic evaluator) and magp-did.mjs (key-in-DID verify).
import crypto from 'node:crypto';
import { evaluate, buildAuthMessage, applySignedLast, operatingModeGate, buildRuleContext, riskFloorFor, maxRisk, normalizeRiskLevel } from './policy-core.mjs';
import { verifyDidSignature } from './magp-did.mjs';
import { buildPaymentRequirements, checkSettlementBinding } from './x402.mjs';
import { verifyBundle } from './magp-policy.mjs';
import { resolveKeyProvider } from './key-providers.mjs';
import { PAYLOAD_DIGEST_HEADER, buildPayloadBindingMessage, claimDigestField, isPayloadDigest, payloadDigestOf, toWireJson } from './payload-binding.mjs';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A `trustedContext` this Service configured must be a real object, and any `riskLevel` in it must be a real
 * level. One that is not (a lookup that missed and returned undefined, a typo, a junk value) means the deriver is
 * BROKEN — and the safe reading of a broken deriver is a refused call, never "carry on with the agent's word",
 * which is exactly what the deriver was there to avoid. `undefined` itself means "not configured".
 */
function assertTrustedContext(tc, where) {
  if (tc === undefined) return;
  if (tc === null || typeof tc !== 'object' || Array.isArray(tc)) throw new Error(`trustedContext${where ? ` for ${where}` : ''} must be an object (got ${tc === null ? 'null' : Array.isArray(tc) ? 'an array' : typeof tc})`);
  if (Object.prototype.hasOwnProperty.call(tc, 'riskLevel') && normalizeRiskLevel(tc.riskLevel) === null) {
    throw new Error(`trustedContext${where ? ` for ${where}` : ''}.riskLevel is not one of low|medium|high|critical`);
  }
}

/** Freshness window for signed requests and handshake nonces (spec §7.7). How far `issuedAt`
 *  may be BEHIND server time — network/processing delay. */
const FRESHNESS_MS = 5 * 60 * 1000;
/** How far a signed request's `issuedAt` may be AHEAD of server time — clock skew, not a window
 *  to pre-sign a request for later use. Checked separately from FRESHNESS_MS so `Math.abs()`
 *  can't fold both directions into one 10-minute window (found live: a request signed up to 5
 *  minutes in the future was accepted). Mirrors mandate.service.ts's CLOCK_SKEW_TOLERANCE_MS. */
const CLOCK_SKEW_TOLERANCE_MS = 30 * 1000;

/**
 * @param {object} cfg
 * @param {string}  cfg.serviceDid  the MCP's own did:hedera
 * @param {string} [cfg.serviceKey] the MCP's Ed25519 private key (Hedera DER hex) — needed to sign handshakes
 * @param {string} [cfg.issuerApi]  the issuer API base (e.g. https://metamynd.ai/api/v1) to fetch policy bundles
 * @param {(agentDid:string)=>Promise<object>} [cfg.fetchBundle] override bundle loading (tests / caching)
 * @param {string} [cfg.policyPublicKey] MetaMynd's Ed25519 policy-signing key (hex, from
 *   GET /magp/policy/pubkey). When set, the guard VERIFIES the bundle signature + freshness (Phase F,
 *   §5.3.2/§5.3.3) and fails closed for value-bearing actions on an unsigned/tampered/stale bundle —
 *   so per-request enforcement needs no live MetaMynd. Omit for the legacy hash-addressed + TLS mode —
 *   which is only as trustworthy as the transport: over plain http:// nothing authenticates the bundle,
 *   so a value-bearing action is refused (POLICY_BUNDLE_UNVERIFIED) unless `allowUnverifiedBundle` is set.
 * @param {boolean} [cfg.allowUnverifiedBundle] accept a value-bearing action on a bundle fetched over plain
 *   http:// with no `policyPublicKey` pinned. Off by default: a proxy on that path can rewrite the rules (an
 *   independent tester raised an over-cap $5,000 purchase that way). For local development only.
 * @param {boolean} [cfg.requireAuthorization] when true, a PERMIT verdict (allow/observe) is only
 *   actually granted if `signed.authorizationId` atomically claims single-use execution against the
 *   stateful issuer gate (see claimAuthorization below) — this is what closes REPLAY and CUMULATIVE
 *   SPEND, neither of which the stateless re-check above can enforce on its own. Off by default:
 *   it costs a network round trip per value-bearing call, so it's a deliberate choice, not a
 *   strictly-dominant one — a Service happy with per-request policy re-evaluation alone can skip it.
 *
 *   The stateless re-check ALSO cannot see the issuer's other STATEFUL floors — rate limits,
 *   circuit breakers, and spend-pattern anomaly detection all key off the agent's server-side
 *   history, which never travels to the edge. `requireAuthorization` is the one mechanism that
 *   closes all of these at once, because it forces the exact request through the stateful gate
 *   before this Service will execute it. A value-bearing call permitted here with
 *   `requireAuthorization` OFF logs a warning for exactly this reason — see guardIncomingTool.
 * @param {boolean} [cfg.requireCapability] when true AND `verifyCapability` is configured, a PERMIT
 *   verdict for a call with NO `signed.capability` is now BLOCKED (`CAPABILITY_REQUIRED`) rather than
 *   silently passing through unbound. Without this, capability binding is opt-in from the CALLER's
 *   side — an agent can simply omit `capability` and the "authorize $150, execute $5,000" check below
 *   never runs at all, since it only fires when the field is present. Off by default (an existing
 *   integrator's un-capability-aware callers must keep working); set true on any Service where
 *   capability binding is meant to be mandatory, not opt-in.
 */
export function createMcpGuard({ serviceDid, serviceKey, keyProvider: keyProviderOpt, daemonSocketPath, issuerApi, fetchBundle, policyPublicKey, settlementStore, verifyCapability, requireAuthorization = false, requireCapability = false, allowUnverifiedBundle = false } = {}) {
  if (!serviceDid) throw new Error('createMcpGuard requires { serviceDid }');
  const base = issuerApi ? issuerApi.replace(/\/$/, '') : null;
  // With no policyPublicKey, nothing but the transport vouches for the policy bundle. Over plain http:// nothing does:
  // a proxy on the path can drop the spend cap and the guard would enforce the forged rules. A custom fetchBundle is the
  // integrator's own source, so it is left to them.
  const bundleUnauthenticated = !policyPublicKey && typeof fetchBundle !== 'function' && !!base && !/^https:\/\//i.test(base);
  if (!policyPublicKey) {
    console.warn(
      bundleUnauthenticated
        ? `[mcp-guard] no policyPublicKey and the issuer is not https (${base}): nothing authenticates the policy bundle. Value-bearing actions are refused (POLICY_BUNDLE_UNVERIFIED)${allowUnverifiedBundle ? ' — except allowUnverifiedBundle is set, so they are NOT' : ''}. Pin policyPublicKey (GET /magp/policy/pubkey, out of band).`
        : '[mcp-guard] no policyPublicKey: the policy bundle is trusted on the strength of TLS alone. Pin policyPublicKey (GET /magp/policy/pubkey, out of band) so a rewritten bundle is refused.',
    );
  }
  // keyProvider seam (docs/design/agent-key-custody-local-signer-daemon-plan.md): null when
  // neither `serviceKey` nor `keyProvider` is configured — handshakeChallenge throws its own
  // clear error only if actually called, matching the original lazy-throw behavior exactly.
  const keyProvider = resolveKeyProvider({ keyProvider: keyProviderOpt, serviceKey, daemonSocketPath });
  const pending = new Map(); // handshakeId -> { fromDid, nonceB, expiresAt }

  // --- Mutual handshake, RESPONDER side (spec §8.2) ---
  //   A → B  HELLO      { fromDid, nonceA }
  //   B → A  CHALLENGE  { toDid, nonceB, sigB(nonceA) }   ← proves B controls toDid
  //   A → B  PROVE      { sigA(nonceB) }                   ← proves A controls fromDid
  //   B → A  READY      { channelId }

  /** Step 1 (B): on HELLO, sign nonceA to prove control of serviceDid, issue nonceB. */
  async function handshakeChallenge({ fromDid, nonceA, protoVersion } = {}) {
    if (!fromDid || !nonceA) throw new Error('HELLO requires { fromDid, nonceA }');
    if (!keyProvider) throw new Error('serviceKey (or keyProvider) is required to sign handshake messages');
    const handshakeId = crypto.randomUUID();
    const nonceB = crypto.randomUUID();
    pending.set(handshakeId, { fromDid, nonceB, expiresAt: Date.now() + FRESHNESS_MS });
    return { handshakeId, toDid: serviceDid, nonceB, sigB: await keyProvider.signHandshakeNonce(nonceA), protoVersion: protoVersion ?? '1.0' };
  }

  /** Step 2 (B): on PROVE, verify sigA over nonceB against fromDid's key-in-DID. */
  function handshakeVerify({ handshakeId, sigA } = {}) {
    const st = pending.get(handshakeId);
    pending.delete(handshakeId); // single-use, whatever the outcome
    if (!st) throw new Error('unknown or already-used handshake');
    if (Date.now() > st.expiresAt) throw new Error('handshake expired');
    if (!verifyDidSignature(st.fromDid, st.nonceB, sigA)) {
      const e = new Error('handshake PROVE signature invalid');
      e.name = 'HandshakeFailed';
      throw e;
    }
    return { channelId: crypto.randomUUID(), remoteDid: st.fromDid };
  }

  // --- Trustless re-evaluation (spec §9.3, §9.6) ---

  /**
   * Atomically claim a stateful authorization for single execution (AUTHORIZED -> DISPATCHING,
   * the effect-safety state machine in backend/src/features/policy/mandate/effect-machine.ts). A
   * SECOND claim of the SAME authorizationId — a replay, or a race — fails: that transition is only
   * legal once. This is what actually stops replay and enforces the mandate's cumulative budget at
   * a Service, because the authorizationId only exists because the agent's own authorize() call
   * against the stateful issuer gate already checked both (agentsafe-guard.mjs's authorizeLocal()
   * seals any value-bearing action through the real remote authorize() by default).
   *
   * On success, also returns the hold's OWN bound `agentDid`/`action`/`amount`/`currency`/
   * `merchant` — the caller MUST compare these to the request actually being executed. A claim
   * alone only proves "some real, unclaimed authorization exists"; without this check, a
   * legitimately-obtained authorization for a small, honest transaction (or a DIFFERENT action
   * entirely) could be presented to unlock a completely different one — the same confused-deputy
   * shape payload binding closes at the request layer, recurring one layer deeper.
   */
  /**
   * Headers that sign one settlement-surface call as THIS Service (`x-magp-service-*`), or `{}` when it
   * cannot: no `serviceKey`/`keyProvider` that can sign arbitrary messages, or a `serviceDid` that is not
   * self-certifying (only did:key and did:hedera embed the verification key, so the issuer needs no
   * registry to check them). The signed message is domain-separated from every other MAGP signature and
   * binds the action, the authorization id and the call's own values:
   *
   *   MAGP-SERVICE-v1 | action | authorizationId | ...fields | nonce | issuedAt   (each field "\" and "|" escaped)
   *
   * An authenticated claim records this Service's DID on the effect chain; from then on only this identity
   * may settle the hold below its amount, void it, or mark it unknown, and no bearer token is issued.
   */
  async function serviceAuthHeaders(action, authorizationId, fields = []) {
    if (!serviceDid || !/^did:(key|hedera):/.test(serviceDid)) return {};
    if (!keyProvider || typeof keyProvider.signServiceMessage !== 'function') return {};
    const escape = (v) => String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    const message = ['MAGP-SERVICE-v1', action, authorizationId, ...fields, nonce, issuedAt].map(escape).join('|');
    const signature = await keyProvider.signServiceMessage(message);
    return { 'x-magp-service-did': serviceDid, 'x-magp-service-nonce': nonce, 'x-magp-service-issued-at': issuedAt, 'x-magp-service-signature': signature };
  }

  /**
   * Claim the authorization, retrying ONCE when the answer is lost.
   *
   * A claim whose response never arrives (dropped connection, a 5xx from a proxy in front of the issuer) is
   * ambiguous: it may have landed. Without more, this Service could not tell "my claim landed" from "someone
   * else claimed", would refuse, and the hold would sit claimed — committed to the cap — with nobody executing
   * it. So every claim CALL carries a fresh unguessable `Idempotency-Key`, reused only for the retry of that
   * same call: the issuer recognises the retry as this claimant's own and returns the original grant
   * (`replayed: true`) instead of refusing. The key is per call and never persisted, so a restarted process, or a
   * later request for the same authorization, gets no replay — a claim is still single-use.
   *
   * Only an AMBIGUOUS failure is retried (no response, a 5xx, or the issuer's retryable
   * EFFECT_TRANSITION_CONTENDED). A definite answer, including AUTHORIZATION_ALREADY_CLAIMED, is final and is
   * returned as it is.
   */
  async function claimAuthorization({ authorizationId, payloadDigest } = {}) {
    if (!authorizationId) return { claimed: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    if (!base) throw new Error('issuerApi is required to claim an authorization');
    if (payloadDigest !== undefined && !isPayloadDigest(payloadDigest)) return { claimed: false, reasonCode: 'PAYLOAD_DIGEST_INVALID' };
    const idempotencyKey = crypto.randomUUID().replace(/-/g, '');
    const attempts = 2;
    let lastError;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      try {
        // Re-signed per attempt (a fresh nonce; the signature also covers the key, so it cannot be swapped or stripped).
        // `payloadDigest` — the digest of exactly what THIS Service is about to execute — is one more signed field and rides
        // as a header: the issuer compares it with the digest the AGENT signed for this authorization and refuses the claim
        // (leaving the hold unclaimed) on any difference. Payload binding, spec 8.3.9 / 8.7.11.
        const auth = await serviceAuthHeaders('claim', authorizationId, [idempotencyKey, ...(payloadDigest ? [claimDigestField(payloadDigest)] : [])]);
        const res = await fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/effect/dispatching`, {
          method: 'POST',
          headers: { ...auth, 'idempotency-key': idempotencyKey, ...(payloadDigest ? { [PAYLOAD_DIGEST_HEADER]: payloadDigest } : {}) },
        });
        const body = await res.json().catch(() => null);
        // Ambiguous, so worth one retry with the same key: a 5xx, or EFFECT_TRANSITION_CONTENDED — the issuer's
        // "an overlapping attempt of yours is mid-claim, ask again", which is not a refusal.
        const ambiguous = res.status >= 500 || (res.status === 409 && body?.message === 'EFFECT_TRANSITION_CONTENDED');
        if (ambiguous && attempt < attempts) { lastError = `HTTP ${res.status}`; await sleep(150); continue; }
        if (!res.ok) return { claimed: false, reasonCode: body?.message ?? body?.data?.reasonCode ?? `AUTHORIZATION_CLAIM_HTTP_${res.status}` };
        return {
          claimed: true,
          agentDid: body?.data?.agentDid,
          action: body?.data?.action,
          amount: body?.data?.amount,
          currency: body?.data?.currency,
          merchant: body?.data?.merchant,
          // The digest the agent signed for this authorization (null = unbound); absent from an issuer that predates it.
          payloadDigest: body?.data?.payloadDigest,
          // The settlement token the issuer hands ONLY the caller whose claim succeeded. Once a hold is
          // claimed it can be settled below its amount, or voided, only with this token — so the Service
          // that executes must keep it and present it (captureAuthorization / releaseAuthorization).
          claimToken: body?.data?.claimToken,
          // This claim was signed as this Service's own identity, so the issuer recorded it as the claimant.
          counterpartyAuthenticated: 'x-magp-service-did' in auth,
          // True when the issuer answered a RETRY with the grant of this call's own earlier attempt.
          replayed: body?.data?.replayed === true,
        };
      } catch (err) {
        lastError = String(err?.message ?? err);
        if (attempt < attempts) { await sleep(150); continue; }
      }
    }
    return { claimed: false, reasonCode: 'AUTHORIZATION_CLAIM_UNREACHABLE', error: lastError };
  }

  /**
   * What became of an authorization? Public, keyed by the authorization id (no signature needed). Use it when a
   * claim was refused with AUTHORIZATION_ALREADY_CLAIMED, or before deciding whether to retry anything:
   *
   *   `outcome`         not_started | expired | in_flight | settled | not_executed | unknown | reversing | reversed | reversal_failed
   *   `nothingExecuted` nothing has executed SO FAR (not_started, expired, not_executed)
   *   `retrySafe`       nothing can execute LATER either, so a fresh authorization cannot duplicate this one:
   *                     true ONLY for expired and not_executed
   *
   * Retry only on `retrySafe`. `not_started` is nothingExecuted but NOT retrySafe: the hold can still be claimed
   * until its window closes, so a request queued behind a slow gateway could run it too (void it first, then it
   * reads not_executed). `unknown` and `in_flight` are neither — an ambiguous outcome must be reconciled, never
   * retried blindly. Best-effort and non-throwing: `{ ok: false, reasonCode }` when the issuer cannot be asked.
   */
  async function lookupOutcome({ authorizationId } = {}) {
    if (!authorizationId) return { ok: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    if (!base) return { ok: false, reasonCode: 'ISSUER_API_REQUIRED' };
    try {
      const res = await fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/effect`);
      const body = await res.json().catch(() => null);
      if (!res.ok || !body?.data) return { ok: false, status: res.status, reasonCode: body?.message ?? `OUTCOME_HTTP_${res.status}` };
      return { ok: true, ...body.data };
    } catch (err) {
      return { ok: false, reasonCode: 'ISSUER_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }

  /**
   * Attach the claim to a PERMIT verdict as NON-ENUMERABLE properties. The verdict is routinely
   * echoed onward (logged, put in a response, spread into another object), and the calling agent
   * is exactly the party the claim token must be kept from: with it, the agent could void an
   * executed hold or settle it for less. A non-enumerable property survives normal use
   * (`decision.claimToken`) but not JSON.stringify or `{ ...decision }`.
   */
  function withClaim(verdict, authorizationId, claimToken, authenticated = false) {
    if (!claimToken && !authenticated) return verdict;
    const out = { ...verdict };
    if (claimToken) Object.defineProperty(out, 'claimToken', { value: claimToken, enumerable: false });
    // `true` when the claim was signed as this Service's own identity: there is then NO token, and the
    // settlement helpers below authenticate each call by signing it instead.
    if (authenticated) Object.defineProperty(out, 'counterpartyAuthenticated', { value: true, enumerable: false });
    Object.defineProperty(out, 'authorizationId', { value: authorizationId, enumerable: false });
    return out;
  }

  /**
   * One best-effort call to the issuer's settlement surface. Never throws. On success the response's `data` (e.g.
   * capture's `settlementEvidence`/`amountCharged`/`authorizedAmount`) is both kept at `.data` (unchanged, for any
   * existing caller) AND spread onto the top level — same convention `lookupOutcome` already used — so a caller can
   * read `result.settlementEvidence` directly instead of reaching into `.data` for it.
   */
  async function issuerPost(path, body, extraHeaders = {}) {
    if (!base) return { ok: false, reasonCode: 'ISSUER_API_REQUIRED' };
    try {
      const res = await fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...extraHeaders }, body: JSON.stringify(body ?? {}) });
      const payload = await res.json().catch(() => null);
      if (!res.ok) return { ok: false, status: res.status, reasonCode: payload?.message ?? payload?.data?.reasonCode ?? `ISSUER_HTTP_${res.status}` };
      // void answers 200 with success:false when the hold was not voidable (e.g. already settled)
      if (payload?.success === false) return { ok: false, status: res.status, reasonCode: payload?.data?.reasonCode ?? payload?.message ?? 'NOT_APPLIED', data: payload?.data ?? null };
      const data = payload?.data ?? null;
      return { ok: true, status: res.status, ...(data && typeof data === 'object' ? data : {}), data };
    } catch (err) {
      return { ok: false, reasonCode: 'ISSUER_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }

  /**
   * Settle a claimed hold once the Service has actually executed. `claimToken` is the one the
   * successful claim returned (`verdict.claimToken`); it is required to settle BELOW the authorized
   * amount, and unnecessary at the full amount. Best-effort and non-throwing: a failure here never
   * turns an executed call into an error, and a claimed hold stays committed to the mandate's cap
   * either way, so failing to settle can only over-count spend, never under-count it.
   */
  // `payTo`: the account this Service paid (a Hedera account id or an EVM address). Needed when settling BELOW the
  // authorized amount: the issuer checks it against the owner's merchant payee directory (MAGP §8.7.14, refused
  // PAYEE_NOT_REGISTERED otherwise) and the settlement observer only counts a credit to it. Not a signed field (adding one
  // would change the capture message every published signer computes); the issuer reads it only after this call has
  // proven it is the claimer.
  async function captureAuthorization({ authorizationId, claimToken, amountCharged, bookingRef, settlementTxHash, payTo } = {}) {
    if (!authorizationId) return { ok: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    if (!Number.isFinite(Number(amountCharged))) return { ok: false, reasonCode: 'AMOUNT_CHARGED_REQUIRED' };
    const amount = Number(amountCharged);
    const auth = await serviceAuthHeaders('capture', authorizationId, [String(amount), bookingRef ?? '', settlementTxHash ?? '']);
    return issuerPost(`/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/capture`, { amountCharged: amount, bookingRef, settlementTxHash, claimToken, ...(payTo ? { payTo: String(payTo) } : {}) }, auth);
  }

  /**
   * Release a claimed hold whose effect provably did NOT happen (the upstream cleanly rejected it),
   * returning its budget to the mandate. Requires the claim token: the issuer refuses to void a
   * claimed hold for anyone else, because the agent could otherwise wait for this Service to
   * execute and then void its own hold. Do NOT call this for an ambiguous outcome (a timeout, a 5xx,
   * a dropped connection) — use markAuthorizationUnknown so the spend stays committed.
   */
  async function releaseAuthorization({ authorizationId, claimToken, reason } = {}) {
    if (!authorizationId) return { ok: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    const auth = await serviceAuthHeaders('void', authorizationId, [reason ?? '']);
    return issuerPost(`/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/void`, { reason, claimToken }, auth);
  }

  /**
   * Report that the outcome of an executed-or-not call is unknown (response lost, 5xx, timeout).
   * The effect moves to UNKNOWN, which keeps the spend committed and hands it to reconciliation
   * instead of guessing in either direction.
   */
  // `claimToken`: an ANONYMOUS claim's token (from the claim), which the issuer now requires to prove this Service is the
  // claimer — it is no longer enough to know the authorization id. A signed claim needs none: the call is signed instead.
  async function markAuthorizationUnknown({ authorizationId, reason, claimToken } = {}) {
    if (!authorizationId) return { ok: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    const auth = await serviceAuthHeaders('unknown', authorizationId, [reason ?? '']);
    return issuerPost(`/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/effect/unknown`, { reason, ...(claimToken ? { claimToken } : {}) }, auth);
  }

  async function loadBundle(agentDid) {
    if (typeof fetchBundle === 'function') return fetchBundle(agentDid);
    if (!base) throw new Error('issuerApi (or fetchBundle) is required to load the policy bundle');
    const res = await fetch(`${base}/policy/bundle/${encodeURIComponent(agentDid)}`);
    const body = await res.json().catch(() => null);
    if (!res.ok || !body?.data) throw new Error(`policy bundle fetch failed (HTTP ${res.status})`);
    // Live containment (Phase 2.4) + operating mode (Phase 2.5b) ride as SIBLINGS of the
    // signed bundle. Expose them as NON-ENUMERABLE props so they never enter the
    // canonicalization verifyBundle signs over (Object.keys skips them) — the signature
    // stays valid, the flags are readable.
    Object.defineProperty(body.data, '__contained', { value: body?.contained ?? null, enumerable: false, configurable: true });
    Object.defineProperty(body.data, '__operatingMode', { value: body?.operatingMode ?? null, enumerable: false, configurable: true });
    return body.data;
  }

  /**
   * Evaluate the agent's bundle against the request via policy-core (signed fields last).
   *
   * `trustedContext` is context THIS SERVICE derived from the real request (never from the agent): it is applied
   * over the agent's claim and labelled `gateway_derived`, so a rule can require it (`requireProvenance`) and a
   * lie in the itinerary cannot outvote it. The mandate's own `riskTier` (in the signed bundle) is a risk floor
   * under whatever the agent claims, exactly as at the issuer's gate (spec §6.4.3).
   */
  function verdictFromBundle(bundle, req, trustedContext) {
    const { agentDid, action, amount = 0, currency = 'USD', merchant = '', resource = null, itinerary = {}, cumulativeSpend = amount, now } = req;
    const mandates = bundle.mandates ?? [];
    const mandate = mandates.find((m) => m.action === action)?.document;
    // No mandate covers this action at all — refuse outright, matching mandate.service.ts's
    // own first check (before signature/standards/anything else). Without this, `evaluate()`
    // treats an omitted `mandate` as "skip the mandate layer" (its own documented, intentional
    // behavior for a caller that never resolves one at all) — found live: an ungranted action
    // with no Standard/SOP molecule happening to also catch it was silently ALLOWED here,
    // while the hosted gate and the agent SDK both correctly refused the identical request.
    if (!mandate) {
      return { decision: 'block', reasonCode: mandates.length > 0 ? 'NO_PERMISSION_FOR_ACTION' : 'NO_MANDATE', authorizationId: null, remaining: null, proofRef: null };
    }
    return evaluate({
      standards: (bundle.standards ?? []).map((s) => ({ standardKey: s.key, document: s.document })),
      sops: (bundle.sops ?? []).map((s) => ({ standardKey: `sop:${s.id}`, document: s.document })),
      mandate,
      // currency/merchant/resource are signed fields, same as action/agentDid/amount above —
      // omitting them here (found live: they were) means a currency-scoped amount-over/
      // cumulative-over Standards/SOP atom always sees currency as absent and fires closed
      // (SOP_SPEND_CAP on a genuinely in-cap request), and a resource-scope atom never runs
      // at all. Mirrors mandate.service.ts's ruleCtx (PR #588), the parity target for this.
      context: buildRuleContext({
        unsigned: itinerary,
        signed: { action, agentDid, amount, currency, merchant, resource },
        gatewayDerived: trustedContext,
        riskFloor: riskFloorFor(mandate, action),
      }),
      mandateRequest: mandate
        ? {
            target: action,
            now: now ?? new Date().toISOString(),
            values: applySignedLast(itinerary, {
              'mm:payAmount': amount,
              'mm:cumulativeSpend': cumulativeSpend,
              'mm:merchant': merchant,
              // A payAmount/cumulativeSpend constraint issued with a `unit` (currency) is
              // only satisfied in that currency (see mandate-eval.ts's constraintSatisfied)
              // — omitting this would make EVERY unit-bearing cap fail regardless of amount.
              // Defaults to 'USD', matching verifyRequest()'s own default for this field.
              'mm:currency': currency,
              // Unprefixed `resource` (not `mm:resource`) to match the constraint's own
              // leftOperand (ResourceService.scopeConstraint()) — mirrors mandate.service.ts.
              resource,
            }),
          }
        : undefined,
    });
  }

  /**
   * Verify an agent's presented signed authorize request, then re-evaluate policy
   * locally against the agent's issuer-hosted bundle. Fails CLOSED: any bad
   * signature, staleness, fetch error, or evaluation error returns a block.
   * @param {{agentDid,action,amount?,currency?,merchant?,resource?,itinerary?,nonce,issuedAt,signature}} signed
   * @param {{ trustedContext?: Record<string, unknown> }} [options] `trustedContext`: context this Service derived
   *   from the real request (e.g. `{ riskLevel: 'high' }` for a wire-transfer route) — NEVER anything the agent sent.
   *   It outranks the agent's claim and is labelled `gateway_derived`; a risk it states can be raised by the agent
   *   but not lowered. Without it the rules see the agent's own claim, as before.
   * @returns {Promise<{decision:'allow'|'observe'|'block'|'escalate'|'suspend'|'quarantine',reasonCode:string|null}>}
   */
  async function verifyRequest(signed = {}, { trustedContext, payloadDigest, requirePayloadBinding } = {}) {
    try {
      assertTrustedContext(trustedContext); // a broken deriver is a refused request (GUARD_ERROR), never a quiet downgrade
      const { agentDid, action, amount = 0, currency = 'USD', merchant = '', resource = null, nonce, issuedAt, signature } = signed;
      if (!agentDid || !action || !nonce || !issuedAt || !signature) {
        return { decision: 'block', reasonCode: 'MALFORMED_REQUEST' };
      }
      // 1. Signature over the canonical message (§7.3), verified via key-in-DID (§4.1.2).
      // `resource` MUST be included — it's the 8th signed field (canonical.ts); omitting it
      // here (found live: it was) rejects every genuinely-valid resource-bearing signature.
      const message = buildAuthMessage({ agentDid, action, amount, currency, merchant, resource, nonce, issuedAt });
      if (!verifyDidSignature(agentDid, message, signature)) {
        return { decision: 'block', reasonCode: 'SIGNATURE_INVALID' };
      }
      // 1b. Payload binding (spec 8.3.9). A digest with no valid signature over it binds nothing — refuse it. When THIS Service
      // states the digest of what it is about to execute (`payloadDigest`), it must be the one the agent signed: a mismatch is
      // refused here, before any claim, so it costs no round trip. (The ISSUER re-checks the same thing against the digest it
      // stored at authorize time when the claim is made — this early check is only cheaper, never the authority.)
      const signedDigest = signed.payloadDigest;
      if (signedDigest !== undefined || signed.payloadSignature !== undefined) {
        const bound = isPayloadDigest(signedDigest) && typeof signed.payloadSignature === 'string'
          && verifyDidSignature(agentDid, buildPayloadBindingMessage({ agentDid, action, nonce, issuedAt, payloadDigest: signedDigest }), signed.payloadSignature);
        if (!bound) return { decision: 'block', reasonCode: 'PAYLOAD_BINDING_INVALID' };
      }
      if (payloadDigest !== undefined) {
        if (!isPayloadDigest(payloadDigest)) return { decision: 'block', reasonCode: 'PAYLOAD_DIGEST_INVALID' };
        if (signedDigest === undefined) {
          // The executor has a payload; the agent bound none. Refuse only when binding is REQUIRED — otherwise this is an
          // unbound request, exactly as before payload binding existed (and it is not claimed with a digest: see below).
          if (requirePayloadBinding) return { decision: 'block', reasonCode: 'PAYLOAD_BINDING_REQUIRED' };
        } else if (signedDigest !== payloadDigest) {
          return { decision: 'block', reasonCode: 'PAYLOAD_NOT_BOUND' };
        }
      } else if (requirePayloadBinding && signedDigest === undefined) {
        return { decision: 'block', reasonCode: 'PAYLOAD_BINDING_REQUIRED' };
      }
      // 2. Freshness. (Single-use nonce consumption stays the gate's job by default — a Service
      //    re-check is verification, not a second authorization. requireAuthorization below is
      //    the opt-in exception: it DOES give the Service its own single-use claim.)
      // Asymmetric: `age` positive = issuedAt in the past (tolerate FRESHNESS_MS); negative =
      // issuedAt in the future (tolerate only CLOCK_SKEW_TOLERANCE_MS) — see its own comment.
      const ts = Date.parse(issuedAt);
      const age = Date.now() - ts;
      if (Number.isNaN(ts) || age > FRESHNESS_MS || age < -CLOCK_SKEW_TOLERANCE_MS) {
        return { decision: 'block', reasonCode: 'REQUEST_EXPIRED' };
      }
      // 3. Re-evaluate against the issuer-hosted bundle (fetched over TLS from the issuer).
      const bundle = await loadBundle(agentDid);
      if (bundle?.subject && bundle.subject !== agentDid) {
        return { decision: 'block', reasonCode: 'BUNDLE_SUBJECT_MISMATCH' };
      }
      // 3a. Containment (Phase 2.4): a server-contained agent is refused regardless of
      // the action — the tool provider will not serve a suspended/quarantined agent.
      const contained = bundle?.__contained;
      if (contained && contained.status) {
        const decision = contained.status === 'quarantined' ? 'quarantine' : 'suspend';
        const reasonCode = contained.status === 'quarantined' ? 'AGENT_QUARANTINED' : 'AGENT_SUSPENDED';
        return { decision, reasonCode };
      }
      // 3a.5. Operating-mode autonomy ladder (Phase 2.5b): the trust-driven posture rides
      // as a non-enumerable sibling. READ_ONLY refuses a value-bearing action up-front;
      // SUPERVISED/RESTRICTED only ESCALATE, applied to the verdict below so a rule block
      // still outranks the floor (most-restrictive-wins, mirroring the gate).
      // The risk it judges is the EFFECTIVE one — the owner's tier (in the signed bundle) and this Service's own
      // derivation are floors under the agent's claim, so "low" cannot dodge the SUPERVISED high-risk escalation.
      const mandateForRisk = (bundle?.mandates ?? []).find((m) => m.action === action)?.document;
      const effectiveRisk = maxRisk(riskFloorFor(mandateForRisk, action), normalizeRiskLevel(trustedContext?.riskLevel), normalizeRiskLevel(signed?.itinerary?.riskLevel)) ?? undefined;
      const modeGate = operatingModeGate(bundle?.__operatingMode?.mode, { amount, riskLevel: effectiveRisk });
      if (modeGate.decision === 'block') return { decision: 'block', reasonCode: modeGate.reasonCode };
      // 3b. Signed-bundle verification + risk-tiered fail-closed (Phase F, §5.3.2/§5.3.3). When a
      // policy key is configured, a value-bearing action (amount > 0) MUST fail closed on an
      // unsigned / tampered / stale bundle — so enforcement needs no live MetaMynd. A bad SIGNATURE
      // is a hard fail even for non-value reads.
      if (policyPublicKey) {
        const v = verifyBundle(bundle, { publicKey: policyPublicKey, valueBearing: Number(amount) > 0 });
        if (!v.ok) return { decision: 'block', reasonCode: v.reasonCode };
      } else if (bundleUnauthenticated && !allowUnverifiedBundle && Number(amount) > 0) {
        // Nothing authenticates these rules (no pinned key, no TLS): moving value on them is exactly the D-08 attack.
        return { decision: 'block', reasonCode: 'POLICY_BUNDLE_UNVERIFIED' };
      }
      const verdict = verdictFromBundle(bundle, { ...signed, itinerary: signed.itinerary ?? {} }, trustedContext);
      // Mode ESCALATE floor lifts an otherwise-PERMIT (allow or observe) to human review
      // (escalate outranks observe, so a flag never masks it) — mirrors the backend gate.
      const final = (verdict.decision === 'allow' || verdict.decision === 'observe') && modeGate.decision === 'escalate'
        ? { ...verdict, decision: 'escalate', reasonCode: modeGate.reasonCode }
        : verdict;
      // 4. Stateful claim (opt-in). Re-evaluating policy per request (above) does not by itself
      // stop REPLAY or CUMULATIVE SPEND past the mandate total — both are the stateful issuer
      // gate's job. Only claim on an actual PERMIT: escalate/block/suspend/quarantine execute
      // nothing, so there is nothing to protect and no reason to spend the hold's single use.
      let claimToken; let claimAuthenticated = false;
      if (requireAuthorization && (final.decision === 'allow' || final.decision === 'observe')) {
        // The claim states the digest of what THIS Service is about to execute — only when the agent bound one (a digest for
        // an unbound authorization is refused by the issuer: this Service would be asserting a binding that does not exist).
        const claimDigest = payloadDigest !== undefined && signedDigest !== undefined ? payloadDigest : undefined;
        const claim = await claimAuthorization({ authorizationId: signed.authorizationId, payloadDigest: claimDigest });
        claimToken = claim.claimToken; claimAuthenticated = claim.counterpartyAuthenticated === true;
        if (!claim.claimed) return { decision: 'block', reasonCode: claim.reasonCode };
        // The grant states the digest the hold is bound to (null = unbound), so it must be the one this claim stated. The issuer
        // already refused a claim whose digest differed; this catches an issuer that did NOT compare — one that predates payload
        // binding ignores the header and its grant carries no digest at all, which is "not enforced", never "fine". Only
        // reachable when the agent bound a payload, a flow an issuer that predates binding cannot honour anyway.
        if ((claim.payloadDigest ?? null) !== (claimDigest ?? null)) return { decision: 'block', reasonCode: 'PAYLOAD_DIGEST_MISMATCH' };
        // The claim alone only proves SOME real, unclaimed authorization exists — it must also
        // be FOR this agent and these exact values, or a cheap legitimate hold's id could be
        // presented to unlock a completely different, more expensive execution. Each check is
        // skipped when the claim response omits that field — tolerated for a Service pinned
        // against an older, not-yet-migrated issuer whose response predates the field (see
        // backend markEffect()'s own note) — but a value-bearing request with a real signed
        // amount/merchant omitted from the claim is exactly the "field genuinely absent vs.
        // issuer regressed" ambiguity that note warns about, so it's surfaced rather than
        // silently trusted: this is the ONE place a future backend change could quietly
        // re-open the confused-deputy gap this claim exists to close, and nothing else here
        // would notice.
        if (claim.agentDid === undefined) console.warn('[mcp-guard] claim response omitted agentDid — binding degraded to "some valid unclaimed authorization exists"');
        if (claim.action === undefined) console.warn('[mcp-guard] claim response omitted action — action binding degraded');
        if (Number(amount) > 0 && claim.amount === undefined) console.warn('[mcp-guard] claim response omitted amount for a value-bearing request — amount binding degraded');
        if (Number(amount) > 0 && claim.currency === undefined) console.warn('[mcp-guard] claim response omitted currency for a value-bearing request — currency binding degraded');
        if (merchant && claim.merchant === undefined) console.warn('[mcp-guard] claim response omitted merchant for a request that signed one — merchant binding degraded');
        if (claim.agentDid !== undefined && claim.agentDid !== agentDid) return { decision: 'block', reasonCode: 'AUTHORIZATION_AGENT_MISMATCH' };
        if (claim.action !== undefined && claim.action !== action) return { decision: 'block', reasonCode: 'AUTHORIZATION_ACTION_MISMATCH' };
        if (claim.amount !== undefined && Number(claim.amount) !== Number(amount)) return { decision: 'block', reasonCode: 'AUTHORIZATION_AMOUNT_MISMATCH' };
        if (claim.currency !== undefined && claim.currency !== currency) return { decision: 'block', reasonCode: 'AUTHORIZATION_CURRENCY_MISMATCH' };
        if (claim.merchant !== undefined && claim.merchant !== merchant) return { decision: 'block', reasonCode: 'AUTHORIZATION_MERCHANT_MISMATCH' };
      }
      // On a claimed permit the Service that executes needs the claim token to settle or release the
      // hold afterwards (non-enumerable — see withClaim).
      return withClaim(final, signed.authorizationId, claimToken, claimAuthenticated);
    } catch (err) {
      return { decision: 'block', reasonCode: 'GUARD_ERROR', error: String(err?.message ?? err) };
    }
  }

  /**
   * Wrap a Service tool so it runs only after trustless verification allows. The
   * agent's signed request must be passed as the first argument. Throws
   * GovernanceBlocked on any non-allow decision.
   */
  function guardIncomingTool(action, handler, { settle: settleClaim = false, trustedContext, bindPayload = false, requirePayloadBinding = false } = {}) {
    // `requirePayloadBinding` only checks that the AGENT bound something; the comparison with what this tool executes needs a
    // digest of it. Without `bindPayload` there is nothing to compare, so the option would give assurance it does not provide.
    if (requirePayloadBinding && !bindPayload) {
      throw new Error(`guardIncomingTool("${action}"): requirePayloadBinding needs bindPayload — without a digest of what the tool executes there is nothing to compare the binding with`);
    }
    return async (signed, ...rest) => {
      // Payload binding (spec 8.3.9): the digest of what THIS call is about to execute. `bindPayload: true` digests the tool's
      // single argument after the signed request and hands the handler that same JSON snapshot, so what is digested is what
      // runs (a `toJSON()` or a later mutation cannot make them differ); a tool with any other shape passes a function that
      // returns what to digest, and then owns making the handler execute exactly that. Computed BEFORE the request is verified
      // so a payload JSON cannot carry refuses the call rather than skipping the check.
      let executorDigest;
      if (bindPayload) {
        try {
          let payload;
          if (typeof bindPayload === 'function') {
            payload = await bindPayload(signed, ...rest);
          } else {
            if (rest.length !== 1) throw new Error(`bindPayload: true digests exactly one argument after the signed request, got ${rest.length}; pass a function to say what to digest`);
            payload = rest[0];
          }
          const wire = toWireJson(payload);
          executorDigest = payloadDigestOf(wire);
          if (typeof bindPayload !== 'function') rest = [wire];
        } catch (err) {
          const e = new Error(`MCP guard BLOCK "${action}": PAYLOAD_NOT_CANONICALIZABLE`);
          e.name = 'GovernanceBlocked';
          e.governance = { decision: 'block', reasonCode: 'PAYLOAD_NOT_CANONICALIZABLE', error: String(err?.message ?? err) };
          throw e;
        }
      }
      // The WRAPPED TOOL's own `action` is authoritative — never `signed?.action` (the caller's
      // own claim). A Service that wraps more than one tool with ONE guard instance (the normal
      // MCP-server shape: many tools, one guard) previously let a genuinely-valid signature for
      // action A verify successfully — correctly, it really was valid for A — and then run
      // action B's handler, because verifyRequest was asked to check whatever the SIGNED payload
      // claimed instead of which wrapped function was actually being invoked. A caller with a
      // real, cheap, in-policy authorization (e.g. a $0 read) could invoke ANY other tool sharing
      // this guard (e.g. a wire transfer) and have it execute under that unrelated verification.
      // Mirrors gateway.mjs's `route.action ?? signed.action` — "the route pins the action ...
      // the client can't pick it" — for exactly the same reason, one layer down at the tool call.
      // `trustedContext` (an object, or `(signed, ...rest) => object`) is what THIS tool's author derived from
      // the real call — the risk of wiring money vs reading a report — never the agent's claim. A throwing
      // deriver fails the call closed (a governance error, not a silent downgrade to the agent's word).
      const derived = typeof trustedContext === 'function' ? await trustedContext(signed, ...rest) : trustedContext;
      // Configured but yielding nothing usable (a function that returned undefined) is a broken deriver, not "no
      // trusted context": refuse rather than fall back to the agent's word. `undefined` option = not configured.
      if (trustedContext !== undefined) assertTrustedContext(derived === undefined ? null : derived, `"${action}"`);
      const decision = await verifyRequest({ ...signed, action }, { trustedContext: derived, payloadDigest: executorDigest, requirePayloadBinding });
      // allow/observe both PERMIT the tool call; observe is permit-but-flag (SAFR §11).
      if (decision.decision !== 'allow' && decision.decision !== 'observe') {
        const err = new Error(`MCP guard ${decision.decision.toUpperCase()} "${action}": ${decision.reasonCode}`);
        err.name = 'GovernanceBlocked';
        err.governance = decision;
        throw err;
      }
      // Commitment-bound capability (decision token, §7.7/§20, Phase-4 PR-5). When the request
      // carries a signed capability AND a verifier is configured, the token must authorize THIS
      // exact transaction — the host reconstructs the tx + verifies MetaMynd's signature OFFLINE,
      // so "authorize $150, execute $5,000" (authorize-A / execute-B) is rejected HERE, in the
      // prod guard, not just the demo gateway. No verifier configured → unchanged (opt-in).
      //
      // Presenting a capability is the CALLER's choice, not this guard's: an agent can simply
      // omit `signed.capability` and this whole check is skipped, verifier or not — that is
      // exactly the omission `requireCapability` closes. Without it, capability binding is
      // opt-in from the wrong side of the trust boundary.
      if (typeof verifyCapability === 'function') {
        if (signed?.capability) {
          let bind;
          try { bind = await verifyCapability(signed); }
          catch (err) { bind = { ok: false, reasonCode: 'CAPABILITY_CHECK_ERROR', error: String(err?.message ?? err) }; }
          if (!bind?.ok) {
            const err = new Error(`MCP guard CAPABILITY "${action}": ${bind?.reasonCode ?? 'CAPABILITY_INVALID'}`);
            err.name = 'GovernanceBlocked';
            err.governance = { decision: 'block', reasonCode: bind?.reasonCode ?? 'CAPABILITY_INVALID' };
            throw err;
          }
        } else if (requireCapability) {
          const err = new Error(`MCP guard CAPABILITY "${action}": CAPABILITY_REQUIRED`);
          err.name = 'GovernanceBlocked';
          err.governance = { decision: 'block', reasonCode: 'CAPABILITY_REQUIRED' };
          throw err;
        }
      }
      if (decision.decision === 'observe') {
        console.warn(`[mcp-guard] OBSERVE "${action}": ${decision.reasonCode} — served under monitoring`);
      }
      // Trustless mode cannot see the issuer's stateful floors (see requireAuthorization's own
      // doc above) — surface that as a loud, per-call signal rather than a silent gap, so an
      // operator serving real value through this path finds out from their own logs rather
      // than from an incident. Gated on value-bearing (amount > 0): a free/read action has
      // nothing for those floors to protect, so warning on it would just be noise.
      if (!requireAuthorization && Number(signed?.amount) > 0) {
        console.warn(`[mcp-guard] "${action}" (amount=${signed.amount}) permitted in trustless mode — rate-limit, circuit-breaker, replay, cumulative-spend, and spend-anomaly floors are stateful and were NOT re-verified against live issuer state. Set requireAuthorization:true for custodial/value-bearing surfaces.`);
      }
      // Opt-in settlement of a claimed hold (`requireAuthorization` + `{ settle: true }`): a handler
      // that returns is settled at the authorized amount; one that throws is reported UNKNOWN, not
      // released — a thrown error does not prove nothing was executed, and UNKNOWN keeps the spend
      // committed until reconciliation decides. Off by default so existing embeds are unchanged.
      if (settleClaim && (decision.claimToken || decision.counterpartyAuthenticated)) {
        let result;
        try {
          result = await handler(signed, ...rest);
        } catch (err) {
          await markAuthorizationUnknown({ authorizationId: decision.authorizationId, reason: 'HANDLER_THREW', claimToken: decision.claimToken });
          throw err;
        }
        await captureAuthorization({ authorizationId: decision.authorizationId, claimToken: decision.claimToken, amountCharged: Number(signed?.amount) });
        return result;
      }
      return handler(signed, ...rest);
    };
  }

  // --- x402 payment binding (spec §7a). MAGP authorizes; x402 moves the money;
  //     this binds a settlement to exactly one authorization. No custody (§7a.5). ---
  // Durable anti-reuse (Phase-4 PR-5): a `settlementStore` may be injected to persist the
  // "one settlement per authorization" invariant across instances + restarts (SAFR §34) —
  // e.g. one backed by POST /magp/settlement/{reserve,finalize,release}. The DEFAULT keeps the
  // original in-process behaviour so existing embeds are unchanged; it is single-instance only.
  const store = settlementStore ?? (() => {
    const claimed = new Set();
    return {
      async reserve(id) { if (claimed.has(id)) return { ok: false, reasonCode: 'SETTLEMENT_REUSED' }; claimed.add(id); return { ok: true }; },
      async release(id) { claimed.delete(id); },
      async finalize() { /* the id stays claimed */ },
    };
  })();

  /**
   * Build the 402 PaymentRequirements bound to a MAGP authorization (§7a.2). The
   * Service returns this after a value-bearing tool call whose authorization it has
   * verified (step 4 of §7a.1), before it will settle.
   * @param {{authorizationId,agentDid,amount,payTo,asset,resource,network?,decimals?}} p
   */
  function requirePayment(p) {
    return buildPaymentRequirements(p);
  }

  /**
   * Verify a presented settlement is bound to the authorization, then settle via the
   * injected facilitator (§7a.3). Enforces the amount binding (§7a.2.2) and anti-reuse
   * (one settlement per authorizationId). `settleFn` performs the actual x402
   * verify+settle and MUST return { settled:true, txHash } on success.
   * @returns {Promise<{settled:boolean, txHash?:string, reasonCode:string}>}
   */
  async function settle({ requirements, authorizationId, paidAmountMinor, xPayment, settleFn } = {}) {
    const binding = checkSettlementBinding(requirements, { authorizationId, paidAmountMinor });
    if (!binding.ok) return { settled: false, reasonCode: binding.reasonCode };
    if (typeof settleFn !== 'function') return { settled: false, reasonCode: 'NO_FACILITATOR' };
    // ATOMICALLY claim the authorization BEFORE settling (closes the check-then-settle race that
    // the old in-memory Set had: two concurrent settles could both pass a read-only check). A
    // durable store makes this correct across instances/restarts.
    const reserved = await store.reserve(authorizationId);
    if (!reserved?.ok) return { settled: false, reasonCode: reserved?.reasonCode ?? 'SETTLEMENT_REUSED' };
    let result;
    try {
      result = await settleFn({ requirements, authorizationId, paidAmountMinor, xPayment });
    } catch (err) {
      await store.release(authorizationId); // settle threw → free the claim so a legit retry works
      return { settled: false, reasonCode: 'SETTLEMENT_FAILED', error: String(err?.message ?? err) };
    }
    if (!result?.settled || !result?.txHash) {
      await store.release(authorizationId); // facilitator declined → free the claim
      return { settled: false, reasonCode: 'SETTLEMENT_FAILED' };
    }
    await store.finalize?.(authorizationId, { txHash: result.txHash, amountMinor: paidAmountMinor });
    return { settled: true, txHash: result.txHash, reasonCode: 'SETTLED' };
  }

  return { handshakeChallenge, handshakeVerify, verifyRequest, guardIncomingTool, requirePayment, settle, claimAuthorization, lookupOutcome, captureAuthorization, releaseAuthorization, markAuthorizationUnknown, serviceDid };
}

/**
 * Mutual-handshake INITIATOR helper (the agent/peer side of §8.2). Drives HELLO
 * then, given the responder's CHALLENGE, verifies the responder proved control of
 * its DID before producing PROVE.
 *
 * @param {{fromDid:string, sign:(msg:string)=>(string|Promise<string>)}} p  sign() uses the
 *   initiator's own key — may be sync (a raw local key) or async (e.g. a keyProvider backed by
 *   agentsafe-signer); `prove()` awaits it either way, see key-providers.mjs.
 */
export function createHandshakeInitiator({ fromDid, sign } = {}) {
  if (!fromDid || typeof sign !== 'function') throw new Error('createHandshakeInitiator requires { fromDid, sign }');
  return {
    /** Step 0 (A): build HELLO; keep nonceA to bind the responder's CHALLENGE. */
    hello() {
      const nonceA = crypto.randomUUID();
      return { nonceA, message: { fromDid, nonceA, protoVersion: '1.0' } };
    },
    /** Step 3 (A): verify CHALLENGE proves the responder controls toDid, then PROVE. */
    async prove({ nonceA, challenge } = {}) {
      const { toDid, nonceB, sigB, handshakeId } = challenge ?? {};
      if (!toDid || !nonceB || !sigB) throw new Error('malformed CHALLENGE');
      if (!verifyDidSignature(toDid, nonceA, sigB)) {
        const e = new Error('responder failed to prove control of its DID');
        e.name = 'HandshakeFailed';
        throw e;
      }
      return { handshakeId, sigA: await sign(nonceB), remoteDid: toDid };
    },
  };
}

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
import { evaluate, buildAuthMessage, applySignedLast, operatingModeGate } from './policy-core.mjs';
import { verifyDidSignature } from './magp-did.mjs';
import { buildPaymentRequirements, checkSettlementBinding } from './x402.mjs';
import { verifyBundle } from './magp-policy.mjs';

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
 *   so per-request enforcement needs no live MetaMynd. Omit for the legacy hash-addressed + TLS mode.
 * @param {boolean} [cfg.requireAuthorization] when true, a PERMIT verdict (allow/observe) is only
 *   actually granted if `signed.authorizationId` atomically claims single-use execution against the
 *   stateful issuer gate (see claimAuthorization below) — this is what closes REPLAY and CUMULATIVE
 *   SPEND, neither of which the stateless re-check above can enforce on its own. Off by default:
 *   it costs a network round trip per value-bearing call, so it's a deliberate choice, not a
 *   strictly-dominant one — a Service happy with per-request policy re-evaluation alone can skip it.
 */
export function createMcpGuard({ serviceDid, serviceKey, issuerApi, fetchBundle, policyPublicKey, settlementStore, verifyCapability, requireAuthorization = false } = {}) {
  if (!serviceDid) throw new Error('createMcpGuard requires { serviceDid }');
  const base = issuerApi ? issuerApi.replace(/\/$/, '') : null;
  const privateKey = serviceKey
    ? crypto.createPrivateKey({ key: Buffer.from(serviceKey, 'hex'), format: 'der', type: 'pkcs8' })
    : null;
  const pending = new Map(); // handshakeId -> { fromDid, nonceB, expiresAt }

  function sign(message) {
    if (!privateKey) throw new Error('serviceKey is required to sign handshake messages');
    return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('hex');
  }

  // --- Mutual handshake, RESPONDER side (spec §8.2) ---
  //   A → B  HELLO      { fromDid, nonceA }
  //   B → A  CHALLENGE  { toDid, nonceB, sigB(nonceA) }   ← proves B controls toDid
  //   A → B  PROVE      { sigA(nonceB) }                   ← proves A controls fromDid
  //   B → A  READY      { channelId }

  /** Step 1 (B): on HELLO, sign nonceA to prove control of serviceDid, issue nonceB. */
  function handshakeChallenge({ fromDid, nonceA, protoVersion } = {}) {
    if (!fromDid || !nonceA) throw new Error('HELLO requires { fromDid, nonceA }');
    const handshakeId = crypto.randomUUID();
    const nonceB = crypto.randomUUID();
    pending.set(handshakeId, { fromDid, nonceB, expiresAt: Date.now() + FRESHNESS_MS });
    return { handshakeId, toDid: serviceDid, nonceB, sigB: sign(nonceA), protoVersion: protoVersion ?? '1.0' };
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
   * On success, also returns the hold's OWN bound `agentDid`/`amount`/`currency`/`merchant` — the
   * caller MUST compare these to the request actually being executed. A claim alone only proves
   * "some real, unclaimed authorization exists"; without this check, a legitimately-obtained
   * authorization for a small, honest transaction could be presented to unlock a completely
   * different one — the same confused-deputy shape payload binding closes at the request layer,
   * recurring one layer deeper.
   */
  async function claimAuthorization({ authorizationId } = {}) {
    if (!authorizationId) return { claimed: false, reasonCode: 'AUTHORIZATION_REQUIRED' };
    if (!base) throw new Error('issuerApi is required to claim an authorization');
    try {
      const res = await fetch(`${base}/policy/mandate/authorize/${encodeURIComponent(authorizationId)}/effect/dispatching`, { method: 'POST' });
      const body = await res.json().catch(() => null);
      if (!res.ok) return { claimed: false, reasonCode: body?.message ?? body?.data?.reasonCode ?? `AUTHORIZATION_CLAIM_HTTP_${res.status}` };
      return { claimed: true, agentDid: body?.data?.agentDid, amount: body?.data?.amount, currency: body?.data?.currency, merchant: body?.data?.merchant };
    } catch (err) {
      return { claimed: false, reasonCode: 'AUTHORIZATION_CLAIM_UNREACHABLE', error: String(err?.message ?? err) };
    }
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

  /** Evaluate the agent's bundle against the request via policy-core (signed fields last). */
  function verdictFromBundle(bundle, req) {
    const { agentDid, action, amount = 0, currency = 'USD', merchant = '', itinerary = {}, cumulativeSpend = amount, now } = req;
    const mandate = (bundle.mandates ?? []).find((m) => m.action === action)?.document;
    return evaluate({
      standards: (bundle.standards ?? []).map((s) => ({ standardKey: s.key, document: s.document })),
      sops: (bundle.sops ?? []).map((s) => ({ standardKey: `sop:${s.id}`, document: s.document })),
      mandate,
      context: applySignedLast(itinerary, { action, agentDid, amount }),
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
            }),
          }
        : undefined,
    });
  }

  /**
   * Verify an agent's presented signed authorize request, then re-evaluate policy
   * locally against the agent's issuer-hosted bundle. Fails CLOSED: any bad
   * signature, staleness, fetch error, or evaluation error returns a block.
   * @param {{agentDid,action,amount?,currency?,merchant?,itinerary?,nonce,issuedAt,signature}} signed
   * @returns {Promise<{decision:'allow'|'observe'|'block'|'escalate'|'suspend'|'quarantine',reasonCode:string|null}>}
   */
  async function verifyRequest(signed = {}) {
    try {
      const { agentDid, action, amount = 0, currency = 'USD', merchant = '', nonce, issuedAt, signature } = signed;
      if (!agentDid || !action || !nonce || !issuedAt || !signature) {
        return { decision: 'block', reasonCode: 'MALFORMED_REQUEST' };
      }
      // 1. Signature over the canonical message (§7.3), verified via key-in-DID (§4.1.2).
      const message = buildAuthMessage({ agentDid, action, amount, currency, merchant, nonce, issuedAt });
      if (!verifyDidSignature(agentDid, message, signature)) {
        return { decision: 'block', reasonCode: 'SIGNATURE_INVALID' };
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
      const modeGate = operatingModeGate(bundle?.__operatingMode?.mode, { amount, riskLevel: signed?.itinerary?.riskLevel });
      if (modeGate.decision === 'block') return { decision: 'block', reasonCode: modeGate.reasonCode };
      // 3b. Signed-bundle verification + risk-tiered fail-closed (Phase F, §5.3.2/§5.3.3). When a
      // policy key is configured, a value-bearing action (amount > 0) MUST fail closed on an
      // unsigned / tampered / stale bundle — so enforcement needs no live MetaMynd. A bad SIGNATURE
      // is a hard fail even for non-value reads.
      if (policyPublicKey) {
        const v = verifyBundle(bundle, { publicKey: policyPublicKey, valueBearing: Number(amount) > 0 });
        if (!v.ok) return { decision: 'block', reasonCode: v.reasonCode };
      }
      const verdict = verdictFromBundle(bundle, { ...signed, itinerary: signed.itinerary ?? {} });
      // Mode ESCALATE floor lifts an otherwise-PERMIT (allow or observe) to human review
      // (escalate outranks observe, so a flag never masks it) — mirrors the backend gate.
      const final = (verdict.decision === 'allow' || verdict.decision === 'observe') && modeGate.decision === 'escalate'
        ? { ...verdict, decision: 'escalate', reasonCode: modeGate.reasonCode }
        : verdict;
      // 4. Stateful claim (opt-in). Re-evaluating policy per request (above) does not by itself
      // stop REPLAY or CUMULATIVE SPEND past the mandate total — both are the stateful issuer
      // gate's job. Only claim on an actual PERMIT: escalate/block/suspend/quarantine execute
      // nothing, so there is nothing to protect and no reason to spend the hold's single use.
      if (requireAuthorization && (final.decision === 'allow' || final.decision === 'observe')) {
        const claim = await claimAuthorization({ authorizationId: signed.authorizationId });
        if (!claim.claimed) return { decision: 'block', reasonCode: claim.reasonCode };
        // The claim alone only proves SOME real, unclaimed authorization exists — it must also
        // be FOR this agent and these exact values, or a cheap legitimate hold's id could be
        // presented to unlock a completely different, more expensive execution.
        if (claim.agentDid !== undefined && claim.agentDid !== agentDid) return { decision: 'block', reasonCode: 'AUTHORIZATION_AGENT_MISMATCH' };
        if (claim.amount !== undefined && Number(claim.amount) !== Number(amount)) return { decision: 'block', reasonCode: 'AUTHORIZATION_AMOUNT_MISMATCH' };
        if (claim.currency !== undefined && claim.currency !== currency) return { decision: 'block', reasonCode: 'AUTHORIZATION_CURRENCY_MISMATCH' };
        if (claim.merchant !== undefined && claim.merchant !== merchant) return { decision: 'block', reasonCode: 'AUTHORIZATION_MERCHANT_MISMATCH' };
      }
      return final;
    } catch (err) {
      return { decision: 'block', reasonCode: 'GUARD_ERROR', error: String(err?.message ?? err) };
    }
  }

  /**
   * Wrap a Service tool so it runs only after trustless verification allows. The
   * agent's signed request must be passed as the first argument. Throws
   * GovernanceBlocked on any non-allow decision.
   */
  function guardIncomingTool(action, handler) {
    return async (signed, ...rest) => {
      const decision = await verifyRequest({ ...signed, action: signed?.action ?? action });
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
      if (signed?.capability && typeof verifyCapability === 'function') {
        let bind;
        try { bind = await verifyCapability(signed); }
        catch (err) { bind = { ok: false, reasonCode: 'CAPABILITY_CHECK_ERROR', error: String(err?.message ?? err) }; }
        if (!bind?.ok) {
          const err = new Error(`MCP guard CAPABILITY "${action}": ${bind?.reasonCode ?? 'CAPABILITY_INVALID'}`);
          err.name = 'GovernanceBlocked';
          err.governance = { decision: 'block', reasonCode: bind?.reasonCode ?? 'CAPABILITY_INVALID' };
          throw err;
        }
      }
      if (decision.decision === 'observe') {
        console.warn(`[mcp-guard] OBSERVE "${action}": ${decision.reasonCode} — served under monitoring`);
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

  return { handshakeChallenge, handshakeVerify, verifyRequest, guardIncomingTool, requirePayment, settle, claimAuthorization, serviceDid };
}

/**
 * Mutual-handshake INITIATOR helper (the agent/peer side of §8.2). Drives HELLO
 * then, given the responder's CHALLENGE, verifies the responder proved control of
 * its DID before producing PROVE.
 *
 * @param {{fromDid:string, sign:(msg:string)=>string}} p  sign() uses the initiator's own key
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
    prove({ nonceA, challenge } = {}) {
      const { toDid, nonceB, sigB, handshakeId } = challenge ?? {};
      if (!toDid || !nonceB || !sigB) throw new Error('malformed CHALLENGE');
      if (!verifyDidSignature(toDid, nonceA, sigB)) {
        const e = new Error('responder failed to prove control of its DID');
        e.name = 'HandshakeFailed';
        throw e;
      }
      return { handshakeId, sigA: sign(nonceB), remoteDid: toDid };
    },
  };
}

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
import { evaluate, buildAuthMessage, applySignedLast } from './policy-core.mjs';
import { verifyDidSignature } from './magp-did.mjs';

/** Freshness window for signed requests and handshake nonces (spec §7.7). */
const FRESHNESS_MS = 5 * 60 * 1000;

/**
 * @param {object} cfg
 * @param {string}  cfg.serviceDid  the MCP's own did:hedera
 * @param {string} [cfg.serviceKey] the MCP's Ed25519 private key (Hedera DER hex) — needed to sign handshakes
 * @param {string} [cfg.issuerApi]  the issuer API base (e.g. https://metamynd.ai/api/v1) to fetch policy bundles
 * @param {(agentDid:string)=>Promise<object>} [cfg.fetchBundle] override bundle loading (tests / caching)
 */
export function createMcpGuard({ serviceDid, serviceKey, issuerApi, fetchBundle } = {}) {
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
    return { handshakeId, toDid: serviceDid, nonceB, sigB: sign(nonceA), protoVersion: protoVersion ?? '0.4' };
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

  async function loadBundle(agentDid) {
    if (typeof fetchBundle === 'function') return fetchBundle(agentDid);
    if (!base) throw new Error('issuerApi (or fetchBundle) is required to load the policy bundle');
    const res = await fetch(`${base}/policy/bundle/${encodeURIComponent(agentDid)}`);
    const body = await res.json().catch(() => null);
    if (!res.ok || !body?.data) throw new Error(`policy bundle fetch failed (HTTP ${res.status})`);
    return body.data;
  }

  /** Evaluate the agent's bundle against the request via policy-core (signed fields last). */
  function verdictFromBundle(bundle, req) {
    const { agentDid, action, amount = 0, merchant = '', itinerary = {}, cumulativeSpend = amount, now } = req;
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
   * @returns {Promise<{decision:'allow'|'block'|'escalate',reasonCode:string|null}>}
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
      // 2. Freshness. (Single-use nonce consumption stays the gate's job — a Service
      //    re-check is verification, not a second authorization.)
      const ts = Date.parse(issuedAt);
      if (Number.isNaN(ts) || Math.abs(Date.now() - ts) > FRESHNESS_MS) {
        return { decision: 'block', reasonCode: 'REQUEST_EXPIRED' };
      }
      // 3. Re-evaluate against the issuer-hosted bundle (fetched over TLS from the issuer).
      const bundle = await loadBundle(agentDid);
      if (bundle?.subject && bundle.subject !== agentDid) {
        return { decision: 'block', reasonCode: 'BUNDLE_SUBJECT_MISMATCH' };
      }
      return verdictFromBundle(bundle, { ...signed, itinerary: signed.itinerary ?? {} });
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
      if (decision.decision !== 'allow') {
        const err = new Error(`MCP guard ${decision.decision.toUpperCase()} "${action}": ${decision.reasonCode}`);
        err.name = 'GovernanceBlocked';
        err.governance = decision;
        throw err;
      }
      return handler(signed, ...rest);
    };
  }

  return { handshakeChallenge, handshakeVerify, verifyRequest, guardIncomingTool, serviceDid };
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
      return { nonceA, message: { fromDid, nonceA, protoVersion: '0.4' } };
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

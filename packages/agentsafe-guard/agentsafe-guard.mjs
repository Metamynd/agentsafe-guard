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
import { evaluate, buildAuthMessage, applySignedLast, operatingModeGate } from './policy-core.mjs';
import { envelopeHashFor } from './governance-envelope.mjs';
import { verifyDidSignature } from './magp-did.mjs';
import { checkSettlementBinding } from './x402.mjs';

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
 * Async loader — build a guard from the portable config the one-call `POST /onboarding/agent`
 * endpoint returns: a URL, a file path, or the config object itself. Overrides win over the config.
 *   const guard = await createGuardFromConfig('./agent.metamynd.json');
 */
export async function createGuardFromConfig(source, overrides = {}) {
  let cfg = source;
  if (typeof source === 'string') {
    cfg = /^https?:\/\//.test(source) ? await (await fetch(source)).json() : JSON.parse(readFileSync(source, 'utf8'));
  }
  if (cfg && cfg.data && !cfg.agentDid) cfg = cfg.data; // unwrap a { success, data } API response
  return createGuard({ config: cfg, ...overrides });
}

export function createGuard(opts = {}) {
  // Accept a portable agent config (from /onboarding/agent) via `config` or `configPath`, in
  // addition to explicit { api, agentDid, agentKey }. Explicit fields win over the config.
  let cfg = opts.config ?? null;
  if (!cfg && opts.configPath) {
    try { cfg = JSON.parse(readFileSync(opts.configPath, 'utf8')); }
    catch (e) { throw new Error(`createGuard: cannot read configPath "${opts.configPath}": ${e.message}`); }
  }
  if (cfg && cfg.data && !cfg.agentDid) cfg = cfg.data; // unwrap a { success, data } API response
  const api = opts.api ?? cfg?.apiBase ?? cfg?.api;
  const agentDid = opts.agentDid ?? cfg?.agentDid;
  const agentKey = opts.agentKey ?? cfg?.agentKey;
  if (!api || !agentDid || !agentKey) throw new Error('createGuard requires { api, agentDid, agentKey } — directly, or via { config } / { configPath } / createGuardFromConfig()');
  const base = api.replace(/\/$/, '');
  // ExecutionAdapter seam (SAFR §19): an explicit opt wins, else the AGENTSAFE_EXECUTION_MODE env,
  // else live. Applies to every guarded tool unless a tool passes its own adapter.
  const defaultExecutionAdapter = opts.executionAdapter ?? executionAdapterFromEnv() ?? liveExecutionAdapter;
  const privateKey = crypto.createPrivateKey({ key: Buffer.from(agentKey, 'hex'), format: 'der', type: 'pkcs8' });

  // Ed25519 over the exact canonical message the backend verifies.
  function sign(message) {
    return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('hex');
  }

  // Tier 1 context-claim binding (opt-in, docs/design/context-claim-binding.md): when
  // on, sign the GovernanceEnvelope hash too, so a counterparty/gate can prove the
  // agent's OWN key attested to the context it submitted — not just the signed action
  // subset. Off by default: a bare request stays a valid degenerate envelope, exactly
  // like today, and the wire body carries no envelopeSignature field at all.
  const signContext = opts.signContext ?? cfg?.signContext ?? false;
  function envelopeSignatureFor({ action, amount, currency, merchant, context, trace, materiality, nonce, issuedAt }) {
    if (!signContext) return undefined;
    // The hash is independent of `signature` (excluded from what it commits to — see
    // governance-envelope.ts), so an empty placeholder here is exact, not approximate.
    const hash = envelopeHashFor({ agentDid, action, amount, currency, merchant, itinerary: context, trace, materiality, nonce, issuedAt, signature: '' });
    return sign(hash);
  }

  // --- Enforcement mode (spec §9.2 + local-first plan) --------------------------------------
  // 'local' (DEFAULT): decide the rule layer LOCALLY against a cached signed bundle — a
  //   block/escalate needs no network; an allowed VALUE action is still sealed by the remote
  //   gate (two-phase hold + cumulative cap + evidence). 'remote': every call hits the gate.
  const mode = opts.mode ?? cfg?.mode ?? 'local';
  const bundleUrl = opts.bundleUrl ?? cfg?.bundleUrl ?? `${base}/policy/bundle/${encodeURIComponent(agentDid)}`;
  const sealValueActions = opts.sealValueActions !== false; // default true
  // Build B — trustless currency check. When on, the guard trusts its local bundle ONLY if that
  // bundle is the LATEST one anchored on the agent's Hedera topic (read from a public mirror);
  // otherwise it defers to the authoritative remote gate. Opt-in for now.
  const verifyOnChain = opts.verifyOnChain ?? cfg?.verifyOnChain ?? false;
  const _anchorTtlMs = opts.anchorTtlMs ?? 60_000;
  let _bundle = null;
  let _bundleAt = 0;
  let _bundleMaxAgeMs = 10 * 60 * 1000; // overwritten by the bundle's maxStaleness
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
  function buildSignedRequest({ action, amount = 0, currency = 'USD', merchant = '', context = {}, trace, materiality }) {
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    const message = buildAuthMessage({ agentDid, action, amount, currency, merchant, nonce, issuedAt });
    // trace/materiality are GovernanceEnvelope fields (SAFR §5) — unsigned metadata; the
    // signed message stays the action subset, so verification is unchanged.
    return {
      agentDid, action, amount, currency, merchant, itinerary: context, trace, materiality, nonce, issuedAt,
      signature: sign(message),
      envelopeSignature: envelopeSignatureFor({ action, amount, currency, merchant, context, trace, materiality, nonce, issuedAt }),
    };
  }

  /**
   * Ask the gate whether an action is authorized. Never throws on a policy decision —
   * returns { decision:'allow'|'block'|'escalate', reasonCode, authorizationId, remaining }.
   * A network/gate failure returns a fail-CLOSED block so the agent can't proceed blind.
   */
  async function authorize({ action, amount = 0, currency = 'USD', merchant = '', context = {}, trace, materiality }) {
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    // Build the canonical signed message with policy-core so the guard and the
    // backend gate produce byte-identical input to Ed25519 (spec §7.3).
    const message = buildAuthMessage({ agentDid, action, amount, currency, merchant, nonce, issuedAt });
    try {
      const res = await fetch(`${base}/policy/mandate/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // trace/materiality (SAFR §5 envelope) and envelopeSignature (Tier 1, opt-in) ride
        // as unsigned-message metadata; JSON.stringify drops them when undefined, so an
        // agent that omits them (or leaves signContext off) sends the legacy body.
        body: JSON.stringify({
          agentDid, action, amount, currency, merchant, itinerary: context, trace, materiality, nonce, issuedAt,
          signature: sign(message),
          envelopeSignature: envelopeSignatureFor({ action, amount, currency, merchant, context, trace, materiality, nonce, issuedAt }),
        }),
      });
      const body = await res.json().catch(() => null);
      return body?.data ?? { decision: 'block', reasonCode: `GATE_HTTP_${res.status}` };
    } catch (err) {
      return { decision: 'block', reasonCode: 'GATE_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }

  /**
   * Settle an approved hold (two-phase). Call after the real action succeeds with the
   * amount actually charged (≤ the authorized amount). Pass the x402 `settlementTxHash`
   * to record the on-chain payment proof against the capture (§7a.3.2). Optional —
   * skip for non-payment tools.
   */
  async function capture(authorizationId, amountCharged, bookingRef, settlementTxHash) {
    const res = await fetch(`${base}/policy/mandate/authorize/${authorizationId}/capture`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amountCharged, bookingRef, settlementTxHash }),
    });
    return res.json().catch(() => ({}));
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
   * @param {{action:string,amount?:number,merchant?:string,context?:object,cumulativeSpend?:number,now?:string}} p.request
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
    const { action, amount = 0, currency = 'USD', merchant = '', context = {}, cumulativeSpend = amount, now } = request;
    // Operating-mode autonomy ladder (Phase 2.5b): the trust-driven posture rides as a
    // SIBLING (like `contained`) and biases the edge verdict identically to the gate.
    // READ_ONLY denies a value-bearing action up-front; SUPERVISED/RESTRICTED only
    // ESCALATE, applied to the verdict below so a rule block/escalate still outranks it.
    const modeGate = operatingModeGate(operatingMode?.mode, { amount, riskLevel: context?.riskLevel });
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
      context: applySignedLast(context, { action, agentDid, amount }),
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
            }),
          }
        : undefined,
    });
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

  /** Map a fetched bundle into the shape evaluateLocally expects, for one action. */
  function _bundleFor(b, action) {
    return {
      contained: b.contained ?? null,
      operatingMode: b.operatingMode ?? null,
      standards: (b.standards ?? []).map((s) => ({ standardKey: s.id ?? s.standardKey ?? 'standard', document: s.document })).filter((s) => s.document),
      sops: (b.sops ?? []).map((s) => ({ standardKey: s.id ?? s.sopId ?? 'sop', document: s.document })).filter((s) => s.document),
      mandate: ((b.mandates ?? []).find((m) => m.action === action) ?? (b.mandates ?? [])[0])?.document,
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

  /**
   * LOCAL-FIRST decision (the default). Evaluates the rule layer against the cached
   * bundle with the same policy-core the gate runs — so a block/escalate is decided
   * with NO network. An allowed VALUE action (amount > 0) is then sealed by the remote
   * gate (two-phase hold + cumulative-spend cap + anchored evidence — the parts that
   * MUST be server-side); set `sealValueActions:false` for pure offline. If the bundle
   * can't be loaded, defers to the authoritative remote gate rather than blind-allow.
   */
  async function authorizeLocal(input) {
    const { action, amount = 0 } = input;
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
      const sig = b?.proof?.signature;
      if (!anchor?.sigDigest || !sig || _sha256(sig) !== anchor.sigDigest) return authorize(input);
    }
    const local = evaluateLocally({ ..._bundleFor(b, action), request: input });
    // allow/observe both PERMIT; block/escalate/contain are decided locally with no network.
    const permits = local.decision === 'allow' || local.decision === 'observe';
    if (!permits) return local; // denied/escalated locally, no network
    if (amount > 0 && sealValueActions) return authorize(input); // seal value action remotely (allow or observe)
    return local; // non-value permit — local is sufficient
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
        const { amount, currency, merchant, context } = mapArgs(args);
        const bundle = typeof getBundle === 'function' ? await getBundle(args) : getBundle;
        decision = evaluateLocally({ ...bundle, request: { action, amount, currency, merchant, context } });
      } catch (err) {
        decision = { decision: 'block', reasonCode: 'LOCAL_EVAL_ERROR', error: String(err?.message ?? err) };
      }
      // allow/observe both PERMIT execution; observe is permit-but-flag (SAFR §11) — the
      // handler receives the `decision` so a caller can surface/log the observation.
      if (decision.decision !== 'allow' && decision.decision !== 'observe') {
        const err = new Error(`AgentSafe ${decision.decision.toUpperCase()} "${action}": ${decision.reasonCode}`);
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
   * @param {(args:any)=>{amount?:number,currency?:string,merchant?:string,context?:object}} mapArgs
   *   maps the tool's call args to the gate inputs (amount/merchant + the context the rules need)
   */
  function guardTool(action, handler, mapArgs = (a) => a, toolOpts = {}) {
    const adapter = toolOpts.executionAdapter ?? defaultExecutionAdapter;
    return async (args) => {
      const decision = await check({ action, ...mapArgs(args) });
      // allow/observe both PERMIT execution; observe is permit-but-flag (SAFR §11) — the
      // handler receives the `decision` so a caller can surface/log the observation.
      if (decision.decision !== 'allow' && decision.decision !== 'observe') {
        const err = new Error(`AgentSafe ${decision.decision.toUpperCase()} "${action}": ${decision.reasonCode}`);
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
   * Mutual-handshake INITIATOR (spec §8.2). Prove control of this agent's DID to a
   * Service and verify the Service controls its DID — no issuer calls (keys are in
   * the DIDs, §4.1.2). Returns { hello, prove } to drive the exchange:
   *   const hs = guard.handshake();
   *   const { nonceA, message } = hs.hello();           // → send HELLO to the Service
   *   const { sigA, handshakeId } = hs.prove({ nonceA, challenge });  // verifies the Service, → send PROVE
   * `prove` throws HandshakeFailed if the Service's CHALLENGE does not verify.
   */
  function handshake() {
    return {
      hello() {
        const nonceA = crypto.randomUUID();
        return { nonceA, message: { fromDid: agentDid, nonceA, protoVersion: '1.0' } };
      },
      prove({ nonceA, challenge } = {}) {
        const { toDid, nonceB, sigB, handshakeId } = challenge ?? {};
        if (!toDid || !nonceB || !sigB) throw new Error('malformed CHALLENGE');
        if (!verifyDidSignature(toDid, nonceA, sigB)) {
          const e = new Error('Service failed to prove control of its DID');
          e.name = 'HandshakeFailed';
          throw e;
        }
        return { handshakeId, sigA: sign(nonceB), remoteDid: toDid };
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
   * before the side-effecting call, effectDispatched() when the connector accepts, and —
   * critically — effectUnknown() when the response is lost/timed out (instead of guessing).
   * Once UNKNOWN, capture/void are refused by the gate until the effect is reconciled.
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
  const effectUnknown = (authorizationId, reason) => _effectPost(authorizationId, 'unknown', { reason });
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
      body: JSON.stringify({ signature: sign(challenge) }),
    });
    const body = await res.json().catch(() => null);
    if (!res.ok) {
      const e = new Error(body?.message || `verify-key HTTP ${res.status}`);
      e.name = 'KeyVerificationFailed';
      throw e;
    }
    return body?.data ?? { verified: true };
  }

  /** Sign a BYOK challenge with the agent's key (hex) — for integrators who submit verify-key themselves. */
  function signChallenge(challenge) {
    if (!challenge) throw new Error('signChallenge requires the challenge nonce');
    return sign(challenge);
  }

  return { authorize, authorizeLocal, check, loadBundle, policyAnchor: _currentAnchor, watchPolicy, mode, verifyOnChain, buildSignedRequest, capture, guardTool, evaluateLocally, guardToolLocal, handshake, preparePayment, escalationStatus, proof, effectDispatching, effectDispatched, effectUnknown, effectStatus, verifyKey, signChallenge, agentDid, executionAdapter: defaultExecutionAdapter };
}

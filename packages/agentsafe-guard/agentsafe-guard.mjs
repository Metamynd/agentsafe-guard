// agentsafe-guard.mjs — drop-in runtime governance for any Node agent (OpenClaw, LangChain, custom).
//
// ZERO dependencies: uses Node's built-in Ed25519 (node:crypto) + fetch (Node 18+).
// Before an agent performs a governed action, call the AgentSafe authorize gate; it
// deterministically returns allow / block / escalate after checking the agent's
// mandate, the enforced Standards, and the assigned SOPs. The gate is the same one
// the platform enforces — you can't bypass it, and rules change live from the UI.
//
// The agent's private key is a Hedera Ed25519 DER key (the AGENT_KEY the seed prints).
import crypto from 'node:crypto';

/**
 * @param {{ api: string, agentDid: string, agentKey: string }} cfg
 *   api      e.g. "http://localhost:9926/api/v1" or "https://metamynd.ai/api/v1"
 *   agentDid the agent's did:hedera
 *   agentKey the agent's Ed25519 private key (Hedera DER hex, held only by the agent)
 */
export function createGuard({ api, agentDid, agentKey }) {
  if (!api || !agentDid || !agentKey) throw new Error('createGuard requires { api, agentDid, agentKey }');
  const base = api.replace(/\/$/, '');
  const privateKey = crypto.createPrivateKey({ key: Buffer.from(agentKey, 'hex'), format: 'der', type: 'pkcs8' });

  // Ed25519 over the exact canonical message the backend verifies.
  function sign(message) {
    return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('hex');
  }

  /**
   * Ask the gate whether an action is authorized. Never throws on a policy decision —
   * returns { decision:'allow'|'block'|'escalate', reasonCode, authorizationId, remaining }.
   * A network/gate failure returns a fail-CLOSED block so the agent can't proceed blind.
   */
  async function authorize({ action, amount = 0, currency = 'USD', merchant = '', context = {} }) {
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    const message = `${agentDid}|${action}|${amount}|${currency}|${merchant}|${nonce}|${issuedAt}`;
    try {
      const res = await fetch(`${base}/policy/mandate/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentDid, action, amount, currency, merchant, itinerary: context, nonce, issuedAt, signature: sign(message) }),
      });
      const body = await res.json().catch(() => null);
      return body?.data ?? { decision: 'block', reasonCode: `GATE_HTTP_${res.status}` };
    } catch (err) {
      return { decision: 'block', reasonCode: 'GATE_UNREACHABLE', error: String(err?.message ?? err) };
    }
  }

  /**
   * Settle an approved hold (two-phase). Call after the real action succeeds with the
   * amount actually charged (≤ the authorized amount). Optional — skip for non-payment tools.
   */
  async function capture(authorizationId, amountCharged, bookingRef) {
    const res = await fetch(`${base}/policy/mandate/authorize/${authorizationId}/capture`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amountCharged, bookingRef }),
    });
    return res.json().catch(() => ({}));
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
  function guardTool(action, handler, mapArgs = (a) => a) {
    return async (args) => {
      const decision = await authorize({ action, ...mapArgs(args) });
      if (decision.decision !== 'allow') {
        const err = new Error(`AgentSafe ${decision.decision.toUpperCase()} "${action}": ${decision.reasonCode}`);
        err.name = 'GovernanceBlocked';
        err.governance = decision;
        throw err;
      }
      return handler(args, decision);
    };
  }

  return { authorize, capture, guardTool, agentDid };
}

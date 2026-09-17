// credential-vault.smoke.mjs — proves the Credential Vault hook (Module G,
// resolveCredential option on createHttpGateway):
//   a permitted request with a configured resolveCredential gets the resolved header injected
//   into the FORWARDED request without mutating the caller's original req object; a denied
//   request never calls resolveCredential or forward at all; a resolveCredential failure (throw,
//   or a null result) forwards WITHOUT the header rather than failing the whole call; omitting
//   resolveCredential entirely reproduces today's exact behavior.
//
//   node credential-vault.smoke.mjs   → PASS when every case matches.
import { createHttpGateway } from './gateway.mjs';

let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };

const routes = [{ method: 'POST', path: '/book/*', action: 'flight-purchase', bind: false }];
const guardFor = (decision, reasonCode = 'X') => ({ verifyRequest: async (r) => ({ decision, reasonCode, seenAction: r.action }) });
const signedHeader = (over = {}) => ({
  'x-magp-request': JSON.stringify({ agentDid: 'did:key:zA', amount: 100, action: 'flight-purchase', nonce: 'n', issuedAt: new Date().toISOString(), signature: 'sig', authorizationId: 'auth-123', ...over }),
});

async function main() {
  // Permitted + resolveCredential succeeds → the FORWARDED req carries the injected header;
  // the ORIGINAL req object passed to the gateway is untouched (no mutation).
  {
    let forwardedHeaders = null;
    const originalReq = { method: 'POST', path: '/book/42', headers: signedHeader(), body: {} };
    const forward = async (req) => { forwardedHeaders = req.headers; return { status: 200, body: { upstream: true } }; };
    const resolveCredential = async ({ request }) => (request.authorizationId === 'auth-123' ? { header: 'Authorization', value: 'Bearer secret-token' } : null);
    const gw = createHttpGateway({ guard: guardFor('allow'), routes, forward, resolveCredential });
    const res = await gw(originalReq);
    ok(res.status === 200, 'permitted request with a resolved credential still succeeds');
    ok(forwardedHeaders?.Authorization === 'Bearer secret-token', 'the forwarded request carries the injected header');
    ok(originalReq.headers.Authorization === undefined, 'the ORIGINAL req object is never mutated');
  }

  // Denied request → resolveCredential and forward are never called (no credential release
  // for a call the guard refused, and no upstream call at all).
  {
    let resolveCalled = false;
    let forwardCalled = false;
    const resolveCredential = async () => { resolveCalled = true; return { header: 'Authorization', value: 'x' }; };
    const forward = async () => { forwardCalled = true; return { status: 200, body: {} }; };
    const gw = createHttpGateway({ guard: guardFor('block', 'SOP_SPEND_CAP'), routes, forward, resolveCredential });
    const res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 403, 'a denied request is still refused with resolveCredential configured');
    ok(!resolveCalled, 'resolveCredential is never invoked for a denied request');
    ok(!forwardCalled, 'forward is never invoked for a denied request');
  }

  // resolveCredential throws → logged and swallowed; the call still forwards, just without
  // the header (a safe, honest failure — the upstream will reject for lack of auth).
  {
    let forwardedHeaders = null;
    const forward = async (req) => { forwardedHeaders = req.headers; return { status: 200, body: {} }; };
    const resolveCredential = async () => { throw new Error('vault unreachable'); };
    const gw = createHttpGateway({ guard: guardFor('allow'), routes, forward, resolveCredential });
    const res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 200, 'a resolveCredential failure does not fail the gateway call itself');
    ok(forwardedHeaders?.Authorization === undefined, 'no header is injected when resolveCredential throws');
  }

  // resolveCredential returns null (vault said no, e.g. no active credential for the
  // connector) → same safe fallback, forwards without the header.
  {
    let forwardedHeaders = null;
    const forward = async (req) => { forwardedHeaders = req.headers; return { status: 200, body: {} }; };
    const gw = createHttpGateway({ guard: guardFor('allow'), routes, forward, resolveCredential: async () => null });
    const res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 200 && forwardedHeaders?.Authorization === undefined, 'a null resolveCredential result forwards with no injected header');
  }

  // resolveCredential OMITTED entirely → identical to every version of this package before
  // this feature existed.
  {
    let forwardedHeaders = null;
    const forward = async (req) => { forwardedHeaders = req.headers; return { status: 200, body: {} }; };
    const gw = createHttpGateway({ guard: guardFor('allow'), routes, forward });
    const res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 200 && forwardedHeaders?.Authorization === undefined, 'omitting resolveCredential changes nothing for existing consumers');
  }

  if (failed === 0) { console.log('\nPASS — Credential Vault hook injects/withholds the upstream credential correctly'); process.exit(0); }
  else { console.error(`\nFAIL — ${failed} check(s) failed`); process.exit(1); }
}

main().catch((e) => { console.error('ERROR', e); process.exit(1); });

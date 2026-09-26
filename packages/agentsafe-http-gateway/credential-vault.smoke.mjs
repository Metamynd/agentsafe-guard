// credential-vault.smoke.mjs — proves the Credential Vault hook (Module G,
// resolveCredential option on createHttpGateway):
//   a permitted request with a configured resolveCredential gets the resolved header injected
//   into the FORWARDED request without mutating the caller's original req object; a denied
//   request never calls resolveCredential or forward at all; a resolveCredential failure (throw,
//   a null result, or a malformed one) FAILS CLOSED — nothing is forwarded, the caller gets 502
//   CREDENTIAL_UNAVAILABLE and a claimed hold is released; `route.credential: false` opts a route
//   out of the hook; omitting resolveCredential entirely reproduces the old behavior.
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

  // resolveCredential throws, resolves null (the vault refused), or resolves something that is not a
  // {header, value} pair → FAIL CLOSED: nothing is forwarded, the caller gets 502 CREDENTIAL_UNAVAILABLE.
  // (Before 0.13.0 the call was forwarded WITHOUT a credential.)
  for (const [label, resolveCredential] of [
    ['throws', async () => { throw new Error('vault unreachable'); }],
    ['resolves null', async () => null],
    ['resolves undefined', async () => undefined],
    ['resolves an empty value', async () => ({ header: 'Authorization', value: '' })],
    ['resolves no header', async () => ({ value: 'Bearer x' })],
    ['resolves a non-string value', async () => ({ header: 'Authorization', value: 42 })],
  ]) {
    let forwardCalled = false;
    const forward = async () => { forwardCalled = true; return { status: 200, body: {} }; };
    const gw = createHttpGateway({ guard: guardFor('allow'), routes, forward, resolveCredential });
    const res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 502 && res.body?.reasonCode === 'CREDENTIAL_UNAVAILABLE' && res.body?.decision === 'block', `resolveCredential ${label} → 502 CREDENTIAL_UNAVAILABLE`);
    ok(!forwardCalled, `resolveCredential ${label} → the upstream is never called`);
    ok(!JSON.stringify(res).includes('vault unreachable'), `resolveCredential ${label} → the vault's own error is not echoed to the caller`);
  }

  // A refused credential RELEASES the hold the request claimed (nothing was forwarded, so nothing
  // executed) — and with settle:false the hold is left alone, as on every other path.
  {
    const TOKEN = 'ab'.repeat(32);
    const calls = [];
    const claimingGuard = {
      async verifyRequest(r) {
        const d = { decision: 'allow', reasonCode: 'AUTHORIZED' };
        Object.defineProperty(d, 'claimToken', { value: TOKEN, enumerable: false });
        Object.defineProperty(d, 'authorizationId', { value: r.authorizationId, enumerable: false });
        return d;
      },
      async releaseAuthorization(a) { calls.push(['release', a]); return { ok: true }; },
      async markAuthorizationUnknown(a) { calls.push(['unknown', a]); return { ok: true }; },
      async captureAuthorization(a) { calls.push(['capture', a]); return { ok: true }; },
    };
    const forward = async () => ({ status: 200, body: {} });
    let gw = createHttpGateway({ guard: claimingGuard, routes, forward, resolveCredential: async () => null });
    let res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 502, 'a claimed request whose credential is refused is still refused');
    ok(calls.length === 1 && calls[0][0] === 'release' && calls[0][1].authorizationId === 'auth-123' && calls[0][1].claimToken === TOKEN && calls[0][1].reason === 'CREDENTIAL_UNAVAILABLE',
      'the claimed hold is RELEASED with the claim token and reason CREDENTIAL_UNAVAILABLE', calls.map((c) => c[0]).join(','));
    ok(!JSON.stringify(res).includes(TOKEN), 'the refusal never carries the claim token');
    calls.length = 0;
    gw = createHttpGateway({ guard: claimingGuard, routes, forward, resolveCredential: async () => null, settle: false });
    res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 502 && calls.length === 0, 'settle:false → refused, and the hold is not touched');
    calls.length = 0;
    const failingRelease = { ...claimingGuard, async releaseAuthorization() { throw new Error('issuer down'); } };
    gw = createHttpGateway({ guard: failingRelease, routes, forward, resolveCredential: async () => null });
    res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 502 && res.body?.reasonCode === 'CREDENTIAL_UNAVAILABLE', 'a failing release never changes the refusal the caller gets');
  }

  // route.credential:false → the hook is not called for that route and the call forwards as before.
  {
    let resolveCalled = false;
    let forwardedHeaders = null;
    const forward = async (req) => { forwardedHeaders = req.headers; return { status: 200, body: {} }; };
    const openRoutes = [{ ...routes[0], credential: false }];
    const gw = createHttpGateway({ guard: guardFor('allow'), routes: openRoutes, forward, resolveCredential: async () => { resolveCalled = true; return null; } });
    const res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 200 && !resolveCalled && forwardedHeaders?.Authorization === undefined, 'route.credential:false skips the vault and forwards with no credential');
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

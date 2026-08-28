// gateway.smoke.mjs — proves the generic HTTP interception gateway (SAFR §17):
//   route matching (method + path wildcards), pass-through for unprotected routes, governed
//   forwarding for protected ones (allow → upstream, block/escalate → 403), a missing signed
//   request → 401, the route pins the action, a governance error fails closed, and an allow-list
//   (denyByDefault) posture blocks unmatched routes.
//
//   node gateway.smoke.mjs   → PASS when every case matches.
import { pathMatches, matchRoute, methodMatches } from './route-match.mjs';
import { createHttpGateway } from './gateway.mjs';

let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };

// ─── route matching (pure) ─────────────────────────────────────────────────────────────────
ok(pathMatches('/book', '/book'), 'exact path matches');
ok(!pathMatches('/book', '/book/123'), 'exact path does not match a longer path');
ok(pathMatches('/book/*', '/book/123'), 'single-segment wildcard matches one segment');
ok(!pathMatches('/book/*', '/book/123/extra'), 'single-segment wildcard does not span segments');
ok(pathMatches('/api/**', '/api/a/b/c'), 'tail ** absorbs the rest');
ok(pathMatches('/quote', '/quote?ccy=USD'), 'query string is ignored');
ok(methodMatches('*', 'POST') && !methodMatches('GET', 'POST'), 'method match ( * any / exact )');

const routes = [{ method: 'POST', path: '/book/*', action: 'flight-purchase' }, { method: 'GET', path: '/quote', action: 'quote-read' }];
ok(matchRoute(routes, 'POST', '/book/99')?.action === 'flight-purchase', 'matchRoute picks the protected route');
ok(matchRoute(routes, 'GET', '/book/99') === null, 'wrong method → no match');
ok(matchRoute(routes, 'GET', '/health') === null, 'unprotected path → no match');

// ─── gateway handler (with fakes) ──────────────────────────────────────────────────────────
const forwarded = [];
const forward = async (req) => { forwarded.push(req.path); return { status: 200, body: { upstream: true, path: req.path } }; };
const guardFor = (decision, reasonCode = 'X') => ({ verifyRequest: async (r) => ({ decision, reasonCode, seenAction: r.action }) });
const signedHeader = (over = {}) => ({ 'x-magp-request': JSON.stringify({ agentDid: 'did:key:zA', amount: 100, action: 'CLIENT-CLAIMED', nonce: 'n', issuedAt: new Date().toISOString(), signature: 'sig', ...over }) });

async function main() {
  // Unprotected route → passes through untouched.
  {
    const gw = createHttpGateway({ guard: guardFor('block'), routes, forward });
    const res = await gw({ method: 'GET', path: '/health', headers: {}, body: null });
    ok(res.status === 200 && res.body.upstream === true, 'unprotected route passes through to upstream');
    ok(res.governance === undefined, 'pass-through carries no governance verdict');
  }

  // Protected + allow → forwarded upstream, carrying the verdict.
  {
    forwarded.length = 0;
    const guard = guardFor('allow', 'AUTHORIZED');
    const gw = createHttpGateway({ guard, routes, forward });
    const res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 200 && forwarded.includes('/book/42'), 'protected + allow → forwarded upstream');
    ok(res.governance?.decision === 'allow', 'allow verdict is attached');
    // The route pins the action — the client's 'CLIENT-CLAIMED' is overridden with 'flight-purchase'.
    ok(res.governance?.seenAction === 'flight-purchase', 'route pins the governed action (client cannot relabel)');
  }

  // Protected + block → 403, upstream never called.
  {
    forwarded.length = 0;
    const gw = createHttpGateway({ guard: guardFor('block', 'SOP_SPEND_CAP'), routes, forward });
    const res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 403 && res.body.reasonCode === 'SOP_SPEND_CAP', 'protected + block → 403 with the reason', res.body.reasonCode);
    ok(forwarded.length === 0, 'a blocked request never reaches upstream');
  }

  // Protected but no signed request → 401.
  {
    const gw = createHttpGateway({ guard: guardFor('allow'), routes, forward });
    const res = await gw({ method: 'POST', path: '/book/42', headers: {}, body: {} });
    ok(res.status === 401 && res.body.reasonCode === 'MISSING_GOVERNANCE', 'protected + no signed request → 401');
  }

  // Governance error → fail closed (502), upstream not called.
  {
    forwarded.length = 0;
    const guard = { verifyRequest: async () => { throw new Error('gate down'); } };
    const gw = createHttpGateway({ guard, routes, forward });
    const res = await gw({ method: 'POST', path: '/book/42', headers: signedHeader(), body: {} });
    ok(res.status === 502 && res.body.reasonCode === 'GOVERNANCE_ERROR', 'governance error fails closed (502)');
    ok(forwarded.length === 0, 'fail-closed does not reach upstream');
  }

  // Allow-list posture: an unmatched route is blocked instead of forwarded.
  {
    const gw = createHttpGateway({ guard: guardFor('allow'), routes, forward, denyByDefault: true });
    const res = await gw({ method: 'GET', path: '/health', headers: {}, body: null });
    ok(res.status === 403 && res.body.reasonCode === 'ROUTE_NOT_ALLOWED', 'denyByDefault blocks an unmatched route');
  }

  if (failed === 0) { console.log('\nPASS — generic HTTP interception gateway governs protected routes'); process.exit(0); }
  else { console.error(`\nFAIL — ${failed} check(s) failed`); process.exit(1); }
}

main().catch((e) => { console.error('ERROR', e); process.exit(1); });

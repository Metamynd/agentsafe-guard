// bundle-cache.smoke.mjs — the opt-in policy-bundle cache (bundle-cache.mjs, createMcpGuard({ allowedAgents: 'any', bundleCache })).
//
// A: the cache's rules, against a fake event stream: nothing is reused until the agent's stream is up; a push, a drop
//    and a (re)open each retire the entry; in-flight fetches are shared; a failure is never cached; an entry never
//    outlives half the bundle's maxStaleness; least-recently-used agents are evicted with their streams; close() ends all.
// B: through createMcpGuard against a fake issuer with a real SSE endpoint: requests reuse the bundle, and a
//    containment pushed on the stream is honoured on the very next request.
// C: an un-closed guard with live streams does not keep the process alive.
//
//   node bundle-cache.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createBundleCache } from './bundle-cache.mjs';
import { createMcpGuard, keepAliveFetch } from './agentsafe-mcp-guard.mjs';

let failed = 0;
const check = (name, ok, detail) => {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail !== undefined ? `  →  ${detail}` : ''}`);
};
const tick = () => new Promise((r) => setImmediate(r));
const waitFor = async (cond, ms = 3000) => {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) return false;
    await new Promise((r) => setTimeout(r, 20));
  }
  return true;
};

// ── A. The cache's rules, with a fake stream and a fake clock ──────────────────────────────────────────────────────
{
  let clock = 1_000_000;
  const streams = new Map(); // url → { handlers, closed }
  const openStream = (url, handlers) => {
    const s = { handlers, closed: false };
    streams.set(url, s);
    return () => {
      s.closed = true;
    };
  };
  const loads = [];
  let failNext = false;
  const load = async (did) => {
    loads.push(did);
    if (failNext) {
      failNext = false;
      throw new Error('issuer down');
    }
    return { subject: did, maxStaleness: 'PT20S' };
  };
  const url = (did) => `http://issuer/policy/events/${did}`;
  const cache = createBundleCache({ load, eventsUrl: url, maxAgeMs: 30_000, maxAgents: 2, now: () => clock, openStream });
  const open = (did) => streams.get(url(did)).handlers.onOpen();

  await cache.get('a');
  await cache.get('a');
  check('stream not yet connected: nothing is reused (every request fetches)', loads.length === 2, loads.length);
  check('the first request opened the agent\'s event stream', streams.has(url('a')));

  open('a');
  loads.length = 0;
  await cache.get('a');
  await cache.get('a');
  await cache.get('a');
  check('stream live: fetched once, then reused', loads.length === 1, loads.length);

  streams.get(url('a')).handlers.onEvent('policy:changed', '{"reason":"agent-contained"}');
  await cache.get('a');
  check('a policy:changed push retires the entry: the next request re-fetches', loads.length === 2, loads.length);

  streams.get(url('a')).handlers.onEvent('something-else', '');
  await cache.get('a');
  check('another event type does not', loads.length === 2, loads.length);

  streams.get(url('a')).handlers.onDrop();
  await cache.get('a');
  await cache.get('a');
  check('stream dropped: the entry is gone and the cache steps aside (both requests fetched)', loads.length === 4, loads.length);
  open('a');
  await cache.get('a');
  await cache.get('a');
  check('stream reopened: anything cached before it is discarded, then reuse resumes', loads.length === 5, loads.length);

  loads.length = 0;
  cache.invalidate('a');
  const [x, y] = await Promise.all([cache.get('a'), cache.get('a')]);
  check('concurrent requests share one in-flight fetch', loads.length === 1 && x === y, loads.length);

  loads.length = 0;
  clock += 11_000; // past half of PT20S, inside maxAgeMs
  await cache.get('a');
  check('an entry never outlives half the bundle\'s maxStaleness (PT20S → 10 s)', loads.length === 1, loads.length);

  loads.length = 0;
  cache.invalidate('a');
  failNext = true;
  await cache.get('a').catch(() => {});
  await tick();
  await cache.get('a');
  check('a failed fetch is never cached (the next request fetches again)', loads.length === 2, loads.length);

  await cache.get('b');
  open('b'); // b's own stream opening drops b's entry — b is still in use and must not look idle for it
  await cache.get('c');
  check('maxAgents 2: the least recently used agent (a) is evicted with its stream; b, whose entry its own stream just retired, is kept',
    streams.get(url('a')).closed === true && streams.get(url('b')).closed === false && cache.stats().streams === 2,
    JSON.stringify(cache.stats()));
  open('c');
  await cache.get('b');
  await cache.get('a');
  check('...and the next agent evicted is then the least recently REQUESTED one (c), not the least recently cached',
    streams.get(url('c')).closed === true && streams.get(url('b')).closed === false, JSON.stringify(cache.stats()));

  cache.close();
  check('close() ends every stream and empties the cache', [...streams.values()].every((s) => s.closed) && cache.stats().agents === 0 && cache.stats().streams === 0, JSON.stringify(cache.stats()));

  const ttl = createBundleCache({ load, watch: false, maxAgeMs: 5_000, now: () => clock });
  loads.length = 0;
  await ttl.get('t');
  await ttl.get('t');
  clock += 6_000;
  await ttl.get('t');
  check('watch: false is a plain TTL cache (no stream; re-fetched after maxAgeMs)', loads.length === 2, loads.length);

  let threw = false;
  try {
    createBundleCache({ load, watch: true });
  } catch {
    threw = true;
  }
  check('watch without an issuer events URL is refused at construction', threw);
}

// ── B. Through createMcpGuard, against a fake issuer with a real SSE endpoint ─────────────────────────────────────
function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), topic);
  return { did, sign: (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex') };
}
const agent = mint('0.0.100');
const service = mint('0.0.200');
const ACTION = 'message.send';
let contained = null;
let bundleFetches = 0;
const sse = new Set();
const server = http.createServer((req, res) => {
  if (req.url === `/api/v1/policy/bundle/${encodeURIComponent(agent.did)}`) {
    bundleFetches++;
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({
      success: true,
      data: { subject: agent.did, standards: [], sops: [], maxStaleness: 'PT5M', mandates: [{ action: ACTION, document: { permission: [{ target: ACTION, constraint: [] }] } }] },
      contained,
    }));
  }
  if (req.url === `/api/v1/policy/events/${encodeURIComponent(agent.did)}`) {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(': connected\n\n');
    sse.add(res);
    req.on('close', () => sse.delete(res));
    return;
  }
  res.writeHead(404).end();
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const issuerApi = `http://127.0.0.1:${server.address().port}/api/v1`;

function signed() {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const merchant = 'support-queue';
  const signature = agent.sign(buildAuthMessage({ agentDid: agent.did, action: ACTION, amount: 0, currency: 'USD', merchant, nonce, issuedAt }));
  return { agentDid: agent.did, action: ACTION, amount: 0, currency: 'USD', merchant, itinerary: { riskLevel: 'low' }, nonce, issuedAt, signature };
}

const realWarn = console.warn;
console.warn = () => {}; // the unpinned-over-http construction warning is expected here
try {
  // allowUnverifiedBundle: this exercises caching over a local plain-http issuer, not bundle authentication (0.18.3 refuses
// every action on an unpinned http bundle without it — bundle-authentication.smoke.mjs).
const plain = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, issuerApi, allowUnverifiedBundle: true });
  bundleFetches = 0;
  await plain.verifyRequest(signed());
  await plain.verifyRequest(signed());
  check('without bundleCache: every request fetches the bundle, as before', bundleFetches === 2, bundleFetches);

  const guard = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, issuerApi, bundleCache: true, allowUnverifiedBundle: true });
  bundleFetches = 0;
  let v = await guard.verifyRequest(signed());
  check('a request is allowed on the bundle', v.decision === 'allow', `${v.decision}/${v.reasonCode}`);
  check('bundleCache: the guard opened the agent\'s event stream', await waitFor(() => sse.size === 1), sse.size);
  await new Promise((r) => setTimeout(r, 50)); // the open has been seen client-side
  await guard.verifyRequest(signed());
  await guard.verifyRequest(signed());
  await guard.verifyRequest(signed());
  check('with the stream live: 4 requests, 2 bundle fetches (one before the stream opened, one after)', bundleFetches === 2, bundleFetches);

  contained = { status: 'suspended', reason: 'operator', at: new Date().toISOString() };
  for (const s of sse) s.write('event: policy:changed\ndata: {"reason":"agent-contained"}\n\n');
  await new Promise((r) => setTimeout(r, 100));
  v = await guard.verifyRequest(signed());
  check('a containment pushed on the stream is honoured on the very next request', v.decision === 'suspend' && v.reasonCode === 'AGENT_SUSPENDED', `${v.decision}/${v.reasonCode}`);

  contained = null;
  guard.invalidateBundle(agent.did);
  v = await guard.verifyRequest(signed());
  check('invalidateBundle(did) forces a re-fetch (reinstated)', v.decision === 'allow', `${v.decision}/${v.reasonCode}`);

  guard.close();
  check('close() ends the event stream', await waitFor(() => sse.size === 0), sse.size);

  check('keepAliveFetch is exported from the package', typeof keepAliveFetch === 'function');
} finally {
  console.warn = realWarn;
}

// ── C. Streams never keep the process alive ───────────────────────────────────────────────────────────────────────
{
  const here = fileURLToPath(new URL('./agentsafe-mcp-guard.mjs', import.meta.url));
  const script = `
    import { createMcpGuard } from ${JSON.stringify('file://' + here.replace(/\\/g, '/'))};
    import { buildAuthMessage } from ${JSON.stringify('file://' + fileURLToPath(new URL('./policy-core.mjs', import.meta.url)).replace(/\\/g, '/'))};
    console.warn = () => {};
    const g = createMcpGuard({ allowedAgents: 'any', serviceDid: ${JSON.stringify(service.did)}, issuerApi: ${JSON.stringify(issuerApi)}, bundleCache: true, allowUnverifiedBundle: true });
    await g.verifyRequest(${JSON.stringify(signed())});
    await new Promise((r) => setTimeout(r, 300)); // the stream is open now; no close()
    console.log('done');`;
  const t0 = Date.now();
  const code = await new Promise((resolve) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'inherit'] });
    const timer = setTimeout(() => {
      child.kill();
      resolve('timeout');
    }, 6000);
    child.on('exit', (c) => {
      clearTimeout(timer);
      resolve(c);
    });
  });
  check('a guard with an open event stream and no close() still lets the process exit', code === 0, `${code} after ${Date.now() - t0} ms`);
}

server.closeAllConnections?.();
server.close();
if (failed) {
  console.log(`\nFAIL — ${failed} case(s)`);
  process.exit(1);
}
console.log('\nPASS — bundle cache with push invalidation');
process.exit(0);

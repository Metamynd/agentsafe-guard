// watch-policy.smoke.mjs — push invalidation end to end: a `policy:changed` event on GET /policy/events/:did reaches
// watchPolicy(), and the guard drops its cached bundle so the next call re-fetches the new rules.
//
// Regression guard for 0.17.1–0.17.2: keepAliveFetch resolved a response only when its body ENDED, and an SSE stream
// never ends, so watchPolicy() never saw an event and every guard fell back to waiting out maxStaleness. Nothing tested
// watchPolicy, which is how it shipped.   node watch-policy.smoke.mjs → PASS
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { createGuard } from './agentsafe-guard.mjs';

const AGENT = 'did:key:z6MkwatchPolicySmoke';
let bundleFetches = 0;
const streams = new Set();
const server = http.createServer((req, res) => {
  if (req.url === `/api/v1/policy/bundle/${encodeURIComponent(AGENT)}`) {
    bundleFetches++;
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ data: { subject: AGENT, mandates: [], sops: [], standards: [], maxStaleness: 'PT5M', issuedAt: new Date().toISOString() } }));
  }
  if (req.url === `/api/v1/policy/events/${encodeURIComponent(AGENT)}`) {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(': connected\n\n');
    streams.add(res);
    req.on('close', () => streams.delete(res));
    return;
  }
  res.writeHead(404).end();
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const api = `http://127.0.0.1:${server.address().port}/api/v1`;

const agentKey = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
const guard = createGuard({ api, agentDid: AGENT, agentKey });
const waitFor = async (what, cond, ms = 3000) => {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error(`timed out after ${ms} ms waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
};

let failed = 0;
const watch = (() => {
  const events = [];
  const handle = guard.watchPolicy((payload) => events.push(payload));
  return { events, handle };
})();
try {
  await guard.loadBundle();
  await guard.loadBundle();
  assert.equal(bundleFetches, 1, 'the second call is served from the cache');

  await waitFor('the guard to open the event stream', () => streams.size === 1);
  for (const s of streams) s.write('event: policy:changed\ndata: {"reason":"agent-contained"}\n\n');
  await waitFor('watchPolicy to deliver the push', () => watch.events.length === 1);
  assert.deepEqual(watch.events[0], { reason: 'agent-contained' });

  await guard.loadBundle();
  assert.equal(bundleFetches, 2, 'the push dropped the cached bundle, so the next call re-fetched it');

  // Heartbeats and comments are not changes.
  for (const s of streams) s.write(': ping\n\n');
  await new Promise((r) => setTimeout(r, 150));
  await guard.loadBundle();
  assert.equal(bundleFetches, 2, 'a heartbeat does not invalidate');
  console.log('  ok   a policy:changed push reaches watchPolicy and invalidates the cached bundle; heartbeats do not');
} catch (err) {
  failed++;
  console.log(`  FAIL ${err?.stack ?? err}`);
} finally {
  watch.handle.close();
}

try {
  await waitFor('close() to end the event stream', () => streams.size === 0);
  console.log('  ok   close() ends the event stream');
} catch (err) {
  failed++;
  console.log(`  FAIL ${err?.stack ?? err}`);
}

server.closeAllConnections?.();
server.close();
if (failed) {
  console.log(`\nFAIL — ${failed}`);
  process.exit(1);
}
console.log('\nPASS — watchPolicy push invalidation');
process.exit(0);

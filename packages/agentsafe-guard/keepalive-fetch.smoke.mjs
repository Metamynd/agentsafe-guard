// keepalive-fetch.smoke.mjs — the keep-alive fetch keeps an idle connection past undici's 4 s default, and otherwise
// behaves like fetch for what these packages use.   node keepalive-fetch.smoke.mjs → PASS
import assert from 'node:assert/strict';
import http from 'node:http';
import { keepAliveFetch as fetch } from './keepalive-fetch.mjs';

const sockets = new Set();
const server = http.createServer((req, res) => {
  sockets.add(req.socket);
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    if (req.url === '/redirect-303') return res.writeHead(303, { location: '/echo' }).end();
    if (req.url === '/redirect-307') return res.writeHead(307, { location: '/echo' }).end();
    if (req.url === '/slow') return setTimeout(() => res.end('late'), 2000);
    if (req.url === '/empty') return res.writeHead(204).end();
    res.writeHead(req.url === '/missing' ? 404 : 200, { 'content-type': 'application/json', 'x-multi': ['a', 'b'] });
    res.end(JSON.stringify({ method: req.method, url: req.url, body, contentType: req.headers['content-type'] ?? null, encoding: req.headers['accept-encoding'] }));
  });
});
server.keepAliveTimeout = 120_000;
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

test('GET and POST round-trip as a standard Response', async () => {
  const g = await fetch(`${base}/echo`);
  assert.equal(g.ok, true);
  assert.equal(g.status, 200);
  assert.equal((await g.json()).method, 'GET');
  const p = await fetch(`${base}/echo`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ a: 1 }) });
  const j = await p.json();
  assert.deepEqual([j.method, j.body, j.contentType, j.encoding], ['POST', '{"a":1}', 'application/json', 'identity']);
  assert.equal(p.headers.get('x-multi'), 'a, b');
});

test('a non-2xx is a Response with ok=false, not a throw; 204 has no body', async () => {
  const r = await fetch(`${base}/missing`);
  assert.equal(r.ok, false);
  assert.equal(r.status, 404);
  const e = await fetch(`${base}/empty`);
  assert.equal(e.status, 204);
  assert.equal(await e.text(), '');
});

test('the same connection is reused after 5 s idle (undici would have dropped it after 4 s)', async () => {
  sockets.clear();
  await (await fetch(`${base}/echo`)).text();
  await new Promise((r) => setTimeout(r, 5000));
  await (await fetch(`${base}/echo`)).text();
  assert.equal(sockets.size, 1, `connections used: ${sockets.size}`);
});

test('redirects: 303 becomes a GET, 307 keeps the method and body; manual returns the 3xx', async () => {
  const a = await (await fetch(`${base}/redirect-303`, { method: 'POST', body: 'x' })).json();
  assert.deepEqual([a.method, a.url, a.body], ['GET', '/echo', '']);
  const b = await (await fetch(`${base}/redirect-307`, { method: 'POST', body: 'x' })).json();
  assert.deepEqual([b.method, b.body], ['POST', 'x']);
  const m = await fetch(`${base}/redirect-303`, { redirect: 'manual' });
  assert.equal(m.status, 303);
});

test('an AbortSignal aborts; a refused connection throws "fetch failed" with a cause, like fetch', async () => {
  await assert.rejects(fetch(`${base}/slow`, { signal: AbortSignal.timeout(100) }), (e) => e.name === 'TimeoutError' || e.name === 'AbortError');
  await assert.rejects(fetch('http://127.0.0.1:1/'), (e) => e instanceof TypeError && e.message === 'fetch failed' && !!e.cause);
});

test('a stubbed globalThis.fetch is honoured (the packages\' tests rely on this)', async () => {
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response('stubbed', { status: 200 });
  try {
    assert.equal(await (await fetch(`${base}/echo`)).text(), 'stubbed');
  } finally {
    globalThis.fetch = real;
  }
  assert.equal((await (await fetch(`${base}/echo`)).json()).method, 'GET', 'restored: back to the keep-alive path');
});

let failed = 0;
for (const [name, fn] of tests) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failed++;
    console.log(`  FAIL ${name}\n       ${err?.stack ?? err}`);
  }
}
server.closeAllConnections?.();
server.close();
if (failed) {
  console.log(`\nFAIL — ${failed} of ${tests.length}`);
  process.exit(1);
}
console.log(`\nPASS — keep-alive fetch (${tests.length} cases)`);
process.exit(0);

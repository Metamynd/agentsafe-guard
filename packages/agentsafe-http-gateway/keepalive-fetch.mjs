// keepalive-fetch.mjs — a fetch() that keeps idle connections for 60 s. Zero dependencies (node:http / node:https).
//
// CANONICAL COPY. Identical copies ship in agentsafe-mcp-guard, agentsafe-a2a-guard and agentsafe-http-gateway;
// scripts/check-shared-copies.mjs (CI) fails if they drift. Edit this file, then copy it over.
//
// Why: Node's built-in fetch (undici) drops an idle connection after 4 s unless the server sends
// `Keep-Alive: timeout=N` — and metamynd.ai sits behind Cloudflare, which strips that header. So sporadic agent traffic
// (a call, a pause, the next call) paid a new TCP + TLS handshake (~200 ms from Asia) on almost every call. Cloudflare's
// edge keeps an idle client connection for 400 s, so holding one for 60 s is safe; undici's own keep-alive can only be
// tuned through the `undici` package, which these zero-dependency packages do not take on.
//
// What it is: the fetch() subset these packages use — method, headers, a string/bytes body, AbortSignal, redirects
// (follow by default, `redirect: 'manual'` | 'error') — returning a standard Response. It asks for no compression
// (identity), so no decoding is needed. Anything else (a non-http(s) URL, a Request with a streaming body) goes to the
// built-in fetch unchanged.
//
// Tests that stub `globalThis.fetch` keep working: when the global has been replaced since this module loaded, calls go
// to the replacement.

import http from 'node:http';
import https from 'node:https';

export const IDLE_KEEPALIVE_MS = 60_000;
const MAX_REDIRECTS = 20;

const nativeFetch = globalThis.fetch;
const agents = {
  'https:': new https.Agent({ keepAlive: true, timeout: IDLE_KEEPALIVE_MS, scheduling: 'lifo' }),
  'http:': new http.Agent({ keepAlive: true, timeout: IDLE_KEEPALIVE_MS, scheduling: 'lifo' }),
};

function headersToObject(h) {
  const out = {};
  if (!h) return out;
  const entries = typeof h.entries === 'function' && !Array.isArray(h) ? h.entries() : Array.isArray(h) ? h : Object.entries(h);
  for (const [k, v] of entries) if (v !== undefined) out[k.toLowerCase()] = String(v);
  return out;
}

function bodyBytes(body) {
  if (body === undefined || body === null) return null;
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  if (body instanceof URLSearchParams) return Buffer.from(body.toString(), 'utf8');
  return undefined; // a stream, FormData, Blob… — leave it to the built-in fetch
}

function fetchFailed(cause) {
  return Object.assign(new TypeError('fetch failed'), { cause });
}

function abortError(signal) {
  return signal?.reason instanceof Error ? signal.reason : Object.assign(new Error('This operation was aborted'), { name: 'AbortError' });
}

function once(url, method, headers, bytes, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError(signal));
    const req = (url.protocol === 'https:' ? https : http).request(
      url,
      { method, headers: { ...headers, ...(bytes ? { 'content-length': String(bytes.length) } : {}) }, agent: agents[url.protocol] },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          signal?.removeEventListener?.('abort', onAbort);
          resolve({ status: res.statusCode ?? 0, statusText: res.statusMessage ?? '', headers: res.headers, body: Buffer.concat(chunks) });
        });
        res.on('error', (e) => reject(fetchFailed(e)));
      },
    );
    const onAbort = () => req.destroy(abortError(signal));
    signal?.addEventListener?.('abort', onAbort, { once: true });
    req.on('error', (e) => {
      signal?.removeEventListener?.('abort', onAbort);
      reject(signal?.aborted ? abortError(signal) : fetchFailed(e));
    });
    if (bytes) req.write(bytes);
    req.end();
  });
}

export async function keepAliveFetch(input, init = {}) {
  // A test (or the host) replaced the global fetch since this module loaded: honour it.
  if (globalThis.fetch !== nativeFetch) return globalThis.fetch(input, init);

  const isRequest = typeof input === 'object' && input !== null && typeof input.url === 'string' && !(input instanceof URL);
  let url;
  try {
    url = new URL(isRequest ? input.url : String(input));
  } catch {
    return nativeFetch(input, init);
  }
  const bytes = bodyBytes(init.body);
  if (!agents[url.protocol] || bytes === undefined || (isRequest && input.body)) return nativeFetch(input, init);

  let method = String(init.method ?? (isRequest ? input.method : 'GET')).toUpperCase();
  let headers = { accept: '*/*', 'accept-encoding': 'identity', ...headersToObject(isRequest ? input.headers : undefined), ...headersToObject(init.headers) };
  let body = bytes;
  const redirect = init.redirect ?? 'follow';

  for (let hop = 0; ; hop++) {
    const r = await once(url, method, headers, body, init.signal);
    const location = r.headers.location;
    if ([301, 302, 303, 307, 308].includes(r.status) && location && redirect !== 'manual') {
      if (redirect === 'error') throw fetchFailed(new Error(`unexpected redirect to ${location}`));
      if (hop >= MAX_REDIRECTS) throw fetchFailed(new Error('redirect count exceeded'));
      const next = new URL(location, url);
      // As fetch does: 303 → GET; 301/302 turn a POST into a GET; 307/308 keep the method and body.
      if (r.status === 303 || ((r.status === 301 || r.status === 302) && method === 'POST')) {
        method = 'GET';
        body = null;
        delete headers['content-type'];
      }
      if (next.origin !== url.origin) delete headers.authorization;
      url = next;
      continue;
    }
    const resHeaders = new Headers();
    for (const [k, v] of Object.entries(r.headers)) {
      if (v === undefined) continue;
      for (const one of Array.isArray(v) ? v : [v]) resHeaders.append(k, one);
    }
    const nullBody = r.status === 204 || r.status === 304 || method === 'HEAD' || (r.status >= 100 && r.status < 200);
    const response = new Response(nullBody ? null : r.body, { status: r.status, statusText: r.statusText, headers: resHeaders });
    Object.defineProperty(response, 'url', { value: url.href });
    return response;
  }
}

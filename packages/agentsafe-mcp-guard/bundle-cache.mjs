// bundle-cache.mjs — per-agent policy-bundle cache for agentsafe-mcp-guard, invalidated by the issuer's push stream.
//
// Without it the guard fetches the calling agent's signed bundle from the issuer on EVERY request: one round trip per
// governed call (~300 ms from Asia to metamynd.ai). Integrators were writing their own TTL caches around the
// `fetchBundle` hook to avoid that (the OpenShell POC's purchasing gateway did), each choosing its own trade-off on
// how long a containment or rule change could go unseen.
//
// What this does instead:
//   - Caches each agent's bundle (in-flight fetches are shared; a failed fetch is never cached), at most `maxAgents`
//     agents, least-recently-used out first.
//   - Watches GET /policy/events/:did for each cached agent and drops that agent's entry on every `policy:changed`
//     (the issuer publishes one on recompile, mandate revocation, containment — operator or automatic —, reinstatement
//     and operating-mode changes), so a change reaches this guard in about a second.
//   - With `watch` on (the default), a cached bundle is reused ONLY while that agent's stream is connected. A stream
//     that drops — or never connects (an events endpoint behind a buffering proxy, say) — makes the cache step aside
//     for that agent and every request fetches, exactly as with no cache. Events missed while disconnected cannot
//     leave a stale bundle in use: the entry is dropped on disconnect and again when the stream reopens.
//   - Never holds a bundle longer than half its own `maxStaleness`, so the guard's per-request staleness check is
//     never tripped by the cache. Signature, staleness, subject and containment are still checked on every request.
//   - The streams never keep the process alive (their sockets and reconnect timers are unref'd); `close()` ends them.
//
// `watch: false` is a plain TTL cache (`maxAgeMs`): a change can go unseen for up to that long at this guard.
//
// Uses node:http / node:https directly for the stream (not fetch) so the socket can be unref'd. Zero dependencies.

import http from 'node:http';
import https from 'node:https';
import { parseDurationMs } from './magp-policy.mjs';

export const DEFAULT_BUNDLE_MAX_AGE_MS = 30_000;
export const DEFAULT_BUNDLE_MAX_AGENTS = 1000;
const RECONNECT_MS = 2_000;

/**
 * Open a Server-Sent Events stream and keep it open (reconnecting after a drop) until the returned close() is called.
 * @param {string} url
 * @param {{ onOpen: () => void, onEvent: (event: string, data: string) => void, onDrop: () => void }} handlers
 * @returns {() => void} close
 */
export function openEventStream(url, { onOpen, onEvent, onDrop }) {
  let closed = false;
  let req = null;
  let timer = null;
  const connect = () => {
    if (closed) return;
    let dropped = false;
    const drop = () => {
      if (dropped) return;
      dropped = true;
      onDrop();
      if (!closed) {
        timer = setTimeout(connect, RECONNECT_MS);
        timer.unref?.();
      }
    };
    const u = new URL(url);
    req = (u.protocol === 'https:' ? https : http).get(u, { headers: { accept: 'text/event-stream', 'cache-control': 'no-cache' }, agent: false }, (res) => {
      res.socket?.unref?.();
      if (res.statusCode !== 200) {
        res.resume();
        return drop();
      }
      onOpen();
      res.setEncoding('utf8');
      let buf = '';
      res.on('data', (chunk) => {
        buf += chunk;
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const frame = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const event = /^event:\s*(.+)$/m.exec(frame)?.[1]?.trim();
          if (!event) continue; // a comment (": ping") or a data-only frame
          const data = frame.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).join('\n');
          onEvent(event, data);
        }
      });
      res.on('end', drop);
      res.on('close', drop);
      res.on('error', drop);
    });
    req.on('socket', (s) => s.unref?.());
    req.on('error', drop);
  };
  connect();
  return () => {
    closed = true;
    clearTimeout(timer);
    try {
      req?.destroy();
    } catch {
      /* already gone */
    }
  };
}

/**
 * @param {{
 *   load: (agentDid: string) => Promise<any>,
 *   eventsUrl?: ((agentDid: string) => string) | null,
 *   maxAgeMs?: number,
 *   maxAgents?: number,
 *   watch?: boolean,
 *   now?: () => number,
 *   openStream?: typeof openEventStream,
 * }} opts
 */
export function createBundleCache({ load, eventsUrl = null, maxAgeMs = DEFAULT_BUNDLE_MAX_AGE_MS, maxAgents = DEFAULT_BUNDLE_MAX_AGENTS, watch = true, now = Date.now, openStream = openEventStream }) {
  if (typeof load !== 'function') throw new TypeError('bundle cache: load must be a function');
  if (!(Number.isFinite(maxAgeMs) && maxAgeMs > 0)) throw new TypeError('bundleCache.maxAgeMs must be a positive number of milliseconds');
  if (!(Number.isInteger(maxAgents) && maxAgents > 0)) throw new TypeError('bundleCache.maxAgents must be a positive integer');
  if (watch && typeof eventsUrl !== 'function') throw new TypeError('bundleCache.watch needs the issuer events URL (issuerApi)');

  /** @type {Map<string, { promise: Promise<any>, at: number, ttlMs: number }>} */
  const entries = new Map();
  /** @type {Map<string, { live: boolean, close: () => void }>} */
  const watchers = new Map();
  /** Agents in order of last request, least recent first — what eviction goes by. An agent whose entry a push (or its
   *  own stream opening) just dropped is still in use, so recency is tracked apart from what happens to be cached. */
  const recency = new Set();

  const forget = (agentDid) => entries.delete(agentDid);
  const unwatch = (agentDid) => {
    watchers.get(agentDid)?.close();
    watchers.delete(agentDid);
  };

  function ensureWatcher(agentDid) {
    if (!watch || watchers.has(agentDid)) return;
    const w = { live: false, close: () => {} };
    watchers.set(agentDid, w);
    w.close = openStream(eventsUrl(agentDid), {
      // Anything cached before the stream was up may predate a change the stream will never replay.
      onOpen: () => {
        forget(agentDid);
        w.live = true;
      },
      onEvent: (event) => {
        if (event === 'policy:changed') forget(agentDid);
      },
      onDrop: () => {
        w.live = false;
        forget(agentDid);
      },
    });
  }

  function servable(agentDid, entry) {
    if (!entry || now() - entry.at >= entry.ttlMs) return false;
    return !watch || watchers.get(agentDid)?.live === true;
  }

  return {
    /** The agent's bundle: cached when fresh (and, with watch, while its stream is up), else fetched. */
    get(agentDid) {
      recency.delete(agentDid);
      recency.add(agentDid); // most recently used
      while (recency.size > maxAgents) {
        const [oldest] = recency;
        recency.delete(oldest);
        forget(oldest);
        unwatch(oldest);
      }
      const hit = entries.get(agentDid);
      if (servable(agentDid, hit)) return hit.promise;
      ensureWatcher(agentDid);
      const promise = Promise.resolve().then(() => load(agentDid));
      const entry = { promise, at: now(), ttlMs: maxAgeMs };
      entries.set(agentDid, entry);
      promise.then(
        (bundle) => {
          const staleMs = parseDurationMs(bundle?.maxStaleness);
          if (staleMs) entry.ttlMs = Math.min(maxAgeMs, staleMs / 2);
        },
        () => {
          if (entries.get(agentDid) === entry) forget(agentDid); // a failure is never cached
        },
      );
      return promise;
    },
    /** Drop one agent's cached bundle, or every agent's. */
    invalidate(agentDid) {
      if (agentDid === undefined) entries.clear();
      else forget(agentDid);
    },
    /** End every event stream and empty the cache. */
    close() {
      for (const did of [...watchers.keys()]) unwatch(did);
      entries.clear();
      recency.clear();
    },
    /** For tests and diagnostics. */
    stats() {
      return { agents: entries.size, streams: watchers.size, live: [...watchers.values()].filter((w) => w.live).length };
    },
  };
}

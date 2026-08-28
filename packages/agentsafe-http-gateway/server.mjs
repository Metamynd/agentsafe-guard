// server.mjs — binds the generic HTTP interception gateway (SAFR §17, Phase-5 PR-4) to node:http
// with a fetch-based upstream forwarder + an MCP guard. ZERO external dependencies (node:http +
// built-in fetch + the zero-dep agentsafe-mcp-guard). Protected routes are re-evaluated through the
// guard before proxying; everything else passes through to the upstream service unchanged.
//
//   AGENTSAFE_UPSTREAM=https://api.example.com \
//   MAGP_API=https://metamynd.ai/api/v1 SERVICE_DID=did:hedera:... SERVICE_KEY=<hex> \
//   node server.mjs
//
// Protected routes are declared in agentsafe-routes.json (or AGENTSAFE_ROUTES path):
//   [{ "method": "POST", "path": "/book/*", "action": "flight-purchase" }]
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createMcpGuard } from '@metamynd/agentsafe-mcp-guard';
import { createHttpGateway } from './gateway.mjs';

const UPSTREAM = (process.env.AGENTSAFE_UPSTREAM || '').replace(/\/$/, '');
const PORT = Number(process.env.PORT || 4000);
const MAGP_API = process.env.MAGP_API || 'http://localhost:9926/api/v1';
const ROUTES_PATH = process.env.AGENTSAFE_ROUTES || 'agentsafe-routes.json';

function loadRoutes() {
  try {
    return JSON.parse(readFileSync(ROUTES_PATH, 'utf8'));
  } catch {
    console.warn(`[gateway] no routes file at ${ROUTES_PATH} — nothing is governed (all pass through)`);
    return [];
  }
}

/** Read the raw request body (bounded) as a Buffer. */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 5 * 1024 * 1024) reject(new Error('body too large'));
      else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** fetch-based forwarder to the configured upstream (preserves method, path, headers, body). */
async function forwardToUpstream(req) {
  if (!UPSTREAM) return { status: 502, body: { error: 'no AGENTSAFE_UPSTREAM configured' } };
  const url = UPSTREAM + req.path;
  const headers = { ...req.headers };
  delete headers.host; // let fetch set the upstream host
  const init = { method: req.method, headers };
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.rawBody?.length) init.body = req.rawBody;
  const r = await fetch(url, init);
  const buf = Buffer.from(await r.arrayBuffer());
  const out = {};
  r.headers.forEach((v, k) => (out[k] = v));
  return { status: r.status, headers: out, rawBody: buf };
}

async function main() {
  const guard = createMcpGuard({ serviceDid: process.env.SERVICE_DID, serviceKey: process.env.SERVICE_KEY, issuerApi: MAGP_API });
  const routes = loadRoutes();
  const gateway = createHttpGateway({ guard, routes, forward: forwardToUpstream });

  const server = http.createServer(async (req, res) => {
    try {
      const rawBody = await readBody(req);
      const normalized = { method: req.method, path: req.url, headers: req.headers, rawBody, body: null };
      const result = await gateway(normalized);
      const headers = result.headers ?? { 'content-type': 'application/json' };
      if (result.governance) headers['x-agentsafe-decision'] = result.governance.decision;
      res.writeHead(result.status, headers);
      if (result.rawBody) res.end(result.rawBody);
      else res.end(typeof result.body === 'string' ? result.body : JSON.stringify(result.body ?? {}));
    } catch (err) {
      // Fail CLOSED on any gateway error.
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ decision: 'block', reasonCode: 'GATEWAY_ERROR', error: String(err?.message ?? err) }));
    }
  });

  server.listen(PORT, () => {
    console.log(`[gateway] AgentSafe HTTP interception gateway on :${PORT} → upstream ${UPSTREAM || '(none)'} (${routes.length} protected route(s))`);
  });
}

main().catch((e) => { console.error('[gateway] fatal', e); process.exit(1); });

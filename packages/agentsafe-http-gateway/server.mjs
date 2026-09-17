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
//
// Two postures worth knowing before you deploy this, not after (both found live in testing):
//   AGENTSAFE_REQUIRE_AUTHORIZATION=false   opts OUT of replay + cumulative-spend protection
//     (default true — stateless per-request re-verification alone cannot stop a captured
//     request being replayed, or catch many separately-legal calls adding up past the
//     mandate's TOTAL budget)
//   AGENTSAFE_DENY_BY_DEFAULT=true          opts IN to treating the routes file as a complete
//     allow-list (default false — a path not listed there passes straight through to the
//     upstream, fully ungoverned; that's a legitimate posture for a proxy fronting a wider
//     API, but only when it's the posture you actually meant)
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createMcpGuard } from '@metamynd/agentsafe-mcp-guard';
import { createHttpGateway } from './gateway.mjs';

// The two packages' canonical signed-message format must match exactly (policy-core's
// buildAuthMessage) — mismatched versions verify signatures byte-for-byte differently for any
// field containing `\` or `|` (see agentsafe-mcp-guard 0.3.3's escaping fix). package.json's own
// `^0.3.3` floor keeps npm from resolving an older, incompatible mcp-guard, but a monorepo/lockfile
// override could still do it — logging what actually resolved at runtime makes that visible.
const require = createRequire(import.meta.url);
const RESOLVED_MCP_GUARD_VERSION = require('@metamynd/agentsafe-mcp-guard/package.json').version;

const UPSTREAM = (process.env.AGENTSAFE_UPSTREAM || '').replace(/\/$/, '');
const PORT = Number(process.env.PORT || 4000);
const MAGP_API = process.env.MAGP_API || 'http://localhost:9926/api/v1';
const ROUTES_PATH = process.env.AGENTSAFE_ROUTES || 'agentsafe-routes.json';
// Default ON: without it, this guard only does STATELESS per-request re-verification — it
// cannot stop a captured request being replayed, and cannot enforce the mandate's TOTAL budget
// across many separately-legal calls (found live: 5/5 replays executed; 50×$250 with no
// authorization at all cleared a $10,000 cap). The cost is a network round trip per
// value-bearing call (see agentsafe-mcp-guard's README) — opt out with the env var below only
// if you have measured that cost and accepted the gap it reopens.
const REQUIRE_AUTHORIZATION = process.env.AGENTSAFE_REQUIRE_AUTHORIZATION !== 'false';
// Default OFF, same as always: a reverse proxy fronting a wider API legitimately wants most
// routes to pass through untouched. But that also means an unsigned request to any path NOT in
// the routes file reaches the upstream fully ungoverned (found live: an undeclared
// POST /transfer-funds passed through, HTTP 200) — set this when the routes file is meant to be
// a complete allow-list, not a partial one.
const DENY_BY_DEFAULT = process.env.AGENTSAFE_DENY_BY_DEFAULT === 'true';
// Credential Vault (Module G) — OPTIONAL. Unset CREDENTIAL_VAULT_URL → no resolveCredential
// hook is built at all, identical to every version of this file before this feature existed.
//
// No CREDENTIAL_VAULT_OWNER_ID here — deliberately. This gateway process does not know, and
// does not need to know, which tenant a given call is for: the vault derives that itself from
// the Action Passport bound to the request's own claimed authorizationId, so ONE shared gateway
// deployment correctly serves MANY tenants (each running many agents) against the same
// connector, and a misconfigured or compromised gateway process can never misroute — or spoof —
// which tenant's credential a call receives. See credential-vault.service.ts's
// resolveForGateway for the full design.
const CREDENTIAL_VAULT_URL = (process.env.CREDENTIAL_VAULT_URL || '').replace(/\/$/, '');
const CREDENTIAL_VAULT_GATEWAY_TOKEN = process.env.CREDENTIAL_VAULT_GATEWAY_TOKEN || '';
const CREDENTIAL_VAULT_CONNECTOR_ID = process.env.CREDENTIAL_VAULT_CONNECTOR_ID || '';
const CREDENTIAL_VAULT_HEADER_NAME = process.env.CREDENTIAL_VAULT_HEADER_NAME || 'Authorization';

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

/**
 * Build the Credential Vault resolveCredential hook (Module G), or null when
 * CREDENTIAL_VAULT_URL is unset (the default — feature off, zero behavior change).
 * Calls the backend's gateway-only `/credential-vault/resolve` endpoint, authenticated
 * by CREDENTIAL_VAULT_GATEWAY_TOKEN (a secret this process holds and the agent never
 * does — see credential-vault.service.ts's resolveForGateway for why that extra factor
 * exists). Keyed off `request.authorizationId`, the signed request's own claimed
 * authorization — present only when the caller went through `requireAuthorization`'s
 * claim flow first, which is exactly the "currently-authorized action" the vault requires.
 *
 * No `ownerId` is ever sent — the vault derives the tenant server-side from the Action
 * Passport, so this same code path is correct whether this gateway serves one tenant or
 * many, without this process ever holding or guessing a tenant identity.
 */
function buildResolveCredential() {
  if (!CREDENTIAL_VAULT_URL) return undefined;
  if (!CREDENTIAL_VAULT_GATEWAY_TOKEN || !CREDENTIAL_VAULT_CONNECTOR_ID) {
    console.warn(
      '[gateway] CREDENTIAL_VAULT_URL is set but CREDENTIAL_VAULT_GATEWAY_TOKEN / ' +
      'CREDENTIAL_VAULT_CONNECTOR_ID are not both set — the credential vault hook is ' +
      'DISABLED, calls will forward with no injected credential.',
    );
    return undefined;
  }
  return async function resolveCredential({ request }) {
    const authorizationId = request?.authorizationId;
    if (!authorizationId) return null; // no claimed authorization to resolve against
    const res = await fetch(`${CREDENTIAL_VAULT_URL}/resolve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-credential-vault-token': CREDENTIAL_VAULT_GATEWAY_TOKEN },
      body: JSON.stringify({ connectorId: CREDENTIAL_VAULT_CONNECTOR_ID, authorizationId }),
    });
    if (!res.ok) return null; // vault refused (or is unreachable) — forward without the header
    const body = await res.json().catch(() => null);
    const value = body?.data?.value;
    if (!value) return null;
    return { header: CREDENTIAL_VAULT_HEADER_NAME, value };
  };
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
  if (!REQUIRE_AUTHORIZATION) {
    console.warn(
      `[gateway] AGENTSAFE_REQUIRE_AUTHORIZATION=false — replay and cumulative-spend protection ` +
      `are OFF. A captured request can be resent and will re-execute every time, and many ` +
      `separately-legal calls can add up past the mandate's TOTAL budget, because only ` +
      `stateless per-request re-verification is running. This is an explicit opt-out of the ` +
      `default, not a mistake to fix silently — unset the env var to restore it.`
    );
  }
  const guard = createMcpGuard({
    serviceDid: process.env.SERVICE_DID,
    serviceKey: process.env.SERVICE_KEY,
    issuerApi: MAGP_API,
    requireAuthorization: REQUIRE_AUTHORIZATION,
  });
  const routes = loadRoutes();
  if (!DENY_BY_DEFAULT) {
    console.warn(
      `[gateway] AGENTSAFE_DENY_BY_DEFAULT is off — a request to any path NOT listed in ` +
      `${ROUTES_PATH} passes straight through to ${UPSTREAM || '(no upstream configured)'}, ` +
      `fully ungoverned. This is a deliberate posture for a proxy fronting a wider API, not a ` +
      `mistake to fix silently — set AGENTSAFE_DENY_BY_DEFAULT=true if ${ROUTES_PATH} is meant ` +
      `to be a complete allow-list.`
    );
  }
  const resolveCredential = buildResolveCredential();
  if (resolveCredential) {
    console.log(`[gateway] Credential Vault hook ENABLED → ${CREDENTIAL_VAULT_URL} (connector "${CREDENTIAL_VAULT_CONNECTOR_ID}", header "${CREDENTIAL_VAULT_HEADER_NAME}")`);
  }
  const gateway = createHttpGateway({ guard, routes, forward: forwardToUpstream, denyByDefault: DENY_BY_DEFAULT, resolveCredential });

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
    console.log(`[gateway] resolved @metamynd/agentsafe-mcp-guard@${RESOLVED_MCP_GUARD_VERSION}`);
  });
}

main().catch((e) => { console.error('[gateway] fatal', e); process.exit(1); });

// generated-code-parses.smoke.mjs — every JavaScript file the scaffolder writes must at least PARSE.
//
// It exists because a template edit once put a second `const body` in the default financial scaffold's agent
// (`Identifier 'body' has already been declared`): every `npx create-metamynd-agent` run would have produced an agent that could
// not start, and every other test passed because they matched the generated source with regexes or ran only the gateway. The
// templates are JavaScript inside template literals, which no linter reads, so the only check that sees a broken one is to
// generate each shape and ask Node to parse the result.
//
//   node generated-code-parses.smoke.mjs   → PASS when every generated .mjs file parses.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
// The CLI children must NOT inherit the flag that stops index.mjs from running main() when it is imported as a library.
const cliEnv = { ...process.env };
delete cliEnv.CREATE_METAMYND_AGENT_NO_MAIN;
process.env.CREATE_METAMYND_AGENT_NO_MAIN = '1';
const mod = await import('./index.mjs');

let failed = 0;
const check = (name, fn) => {
  try { fn(); console.log(`ok    ${name}`); } catch (e) { failed++; console.log(`FAIL  ${name}\n      ${String(e.message).split('\n').slice(0, 6).join('\n      ')}`); }
};
const checkAsync = async (name, fn) => {
  try { await fn(); console.log(`ok    ${name}`); } catch (e) { failed++; console.log(`FAIL  ${name}\n      ${String(e.message).split('\n').slice(0, 6).join('\n      ')}`); }
};

function mjsFiles(dir) {
  return readdirSync(dir).flatMap((f) => {
    if (f === 'node_modules') return [];
    const p = join(dir, f);
    return statSync(p).isDirectory() ? mjsFiles(p) : (f.endsWith('.mjs') ? [p] : []);
  });
}

/** Ask Node to parse every generated module; the failure names the file and the line. */
function assertParses(dir) {
  const files = mjsFiles(dir);
  assert.ok(files.length > 0, 'the scaffold wrote no .mjs files');
  for (const file of files) {
    try {
      execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
    } catch (e) {
      throw new Error(`${file.slice(dir.length + 1)} does not parse:\n${String(e.stderr ?? e.message)}`);
    }
  }
  return files.length;
}

const quiet = (fn) => { const log = console.log; console.log = () => {}; try { return fn(); } finally { console.log = log; } };
const config = { apiBase: 'http://127.0.0.1:1', agentDid: 'did:key:zStub', ownerPrincipal: 'did:hedera:testnet:zOwnerStub_0.0.900', agentKey: 'aa', identityId: 'stub', keyVerified: true, mandate: { scope: 'flight-purchase' }, issuer: { policyKey: 'ab'.repeat(32), bbsKey: null } };

// --- the hosted scaffolds (agent, and gateway when there is one) ---
for (const [label, extra] of [
  ['hosted financial, with a gateway (the default)', { withGateway: true }],
  ['hosted financial, in-process (--no-gateway)', { withGateway: false }],
  ['hosted financial, daemon-backed key', { withGateway: true, daemon: true }],
  ['hosted non-financial, with a gateway', { withGateway: true, neutral: true }],
  ['hosted non-financial, in-process', { withGateway: false, neutral: true }],
]) {
  check(label, () => {
    const out = mkdtempSync(join(tmpdir(), 'metamynd-parse-'));
    try {
      quiet(() => mod.scaffoldProject({
        outDir: out,
        config: extra.daemon ? { ...config, keyProvider: 'daemon', daemonSocketPath: '/tmp/signer.sock', agentKey: null } : config,
        slug: 'parse-check', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false,
        withGateway: extra.withGateway, ...(extra.neutral ? { demo: mod.defaultNeutralDemo() } : {}),
      }));
      const n = assertParses(out);
      assert.ok(n >= (extra.withGateway ? 2 : 1), 'expected the agent' + (extra.withGateway ? ' and the gateway' : ''));
    } finally { rmSync(out, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  });
}

// --- the harness scaffolds (agent + optional gateway), through the real CLI ---
for (const [label, args] of [
  ['harness financial, in-process', ['--harness']],
  ['harness financial, with a gateway', ['--harness', '--gateway']],
  ['harness non-financial, in-process', ['--harness', '--non-financial']],
  ['harness non-financial, with a gateway', ['--harness', '--gateway', '--non-financial']],
]) {
  check(label, () => {
    const out = mkdtempSync(join(tmpdir(), 'metamynd-parse-h-'));
    try {
      execFileSync(process.execPath, [join(HERE, 'index.mjs'), ...args, '--yes', '--name', 'Parse Check', '--scope', 'flight-purchase', '--per-txn-max', '500', '--out', out], { stdio: 'pipe', env: cliEnv });
      assertParses(out);
    } finally { rmSync(out, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  });
}

// --- and the property this file was written for: the financial agent sends the body it signed, without redeclaring it ---
check('hosted financial agent: one `body`, and the signed payload is the body it sends', () => {
  const out = mkdtempSync(join(tmpdir(), 'metamynd-parse-'));
  try {
    quiet(() => mod.scaffoldProject({ outDir: out, config, slug: 'p', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false, withGateway: true }));
    const agent = readFileSync(join(out, 'index.mjs'), 'utf8');
    const decls = agent.match(/^\s*const body\b/gm) ?? [];
    assert.ok(decls.length <= 1, `\`const body\` is declared ${decls.length} times`);
    assert.match(agent, /payload,\r?\n\s*\}\);/, 'the request handed to the gateway signs `payload`');
    assert.match(agent, /body: JSON\.stringify\(payload\)/, 'and sends exactly that');
  } finally { rmSync(out, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
});

// --- the policy bundle is pinned to the issuer's OWN signing key, not trusted unverified (MITM finding) ---
for (const [label, extra] of [
  ['hosted financial gateway', {}],
  ['hosted non-financial gateway', { neutral: true }],
]) {
  check(`${label}: policyPublicKey is baked in from the provisioning response`, () => {
    const out = mkdtempSync(join(tmpdir(), 'metamynd-parse-'));
    try {
      quiet(() => mod.scaffoldProject({
        outDir: out, config, slug: 'p', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false,
        withGateway: true, ...(extra.neutral ? { demo: mod.defaultNeutralDemo() } : {}),
      }));
      const server = readFileSync(join(out, 'gateway', 'server.mjs'), 'utf8');
      assert.match(server, new RegExp(`policyPublicKey: '${config.issuer.policyKey}'`), 'the bundle is pinned to the real issuer key, baked in at scaffold time');
    } finally { rmSync(out, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  });

  // XT-1 (pre-beta evaluation 2026-10-03, rerun on v1.78.0): an unpinned gateway ran its owner's tool for another tenant's
  // agent whose own owner granted it the same action. Each gateway acts for the agent it was scaffolded for, and nobody else.
  check(`${label}: allowedAgents pins it to the provisioned agent, on a guard that enforces the pin`, () => {
    const out = mkdtempSync(join(tmpdir(), 'metamynd-parse-'));
    try {
      quiet(() => mod.scaffoldProject({
        outDir: out, config, slug: 'p', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false,
        withGateway: true, ...(extra.neutral ? { demo: mod.defaultNeutralDemo() } : {}),
      }));
      const server = readFileSync(join(out, 'gateway', 'server.mjs'), 'utf8');
      assert.ok(server.includes(`allowedAgents: ['${config.agentDid}'], gatewayOwnerPrincipal: '${config.ownerPrincipal}'`), 'the gateway admits exactly the agent it was scaffolded for, bound to its owner');
      assert.ok(server.includes('if (!Array.isArray(guard.allowedAgents) || !guard.gatewayOwnerPrincipal) throw'), 'and refuses to start on a guard that would ignore either');
      // A-1: what it runs or refuses reaches the owner's Activity Log, signed with its own registered identity (MAGP §16.4).
      assert.ok(server.includes('reportOutcomes: true'), 'the gateway reports its outcomes');
      assert.ok(server.includes('serviceKey: identity.serviceKey'), 'signed with its own key');
      const svc = JSON.parse(readFileSync(join(out, 'gateway', 'service.metamynd.json'), 'utf8'));
      assert.ok('serviceDid' in svc && 'serviceKey' in svc, 'its identity file is written on every hosted shape');
      const deps = JSON.parse(readFileSync(join(out, 'gateway', 'package.json'), 'utf8')).dependencies;
      // An mcp-guard below 0.20.0 ignores the option and serves every agent: the floor is part of the fix.
      assert.match(deps['@metamynd/agentsafe-mcp-guard'], /^\^0\.(2\d|[3-9]\d)\./, `mcp-guard floor ${deps['@metamynd/agentsafe-mcp-guard']} enforces allowedAgents`);
    } finally { rmSync(out, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  });
}

check('a gateway is never scaffolded without the agent it serves', () => {
  const out = mkdtempSync(join(tmpdir(), 'metamynd-parse-'));
  try {
    const { agentDid: _drop, ...noAgent } = config;
    assert.throws(
      () => quiet(() => mod.scaffoldProject({ outDir: out, config: noAgent, slug: 'p', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false, withGateway: true })),
      /agentDid/,
    );
    // Nor without the principal that owns its credentials (gatewayOwnerPrincipal, MAGP §16.3).
    const { ownerPrincipal: _o, ...noOwner } = config;
    assert.throws(
      () => quiet(() => mod.scaffoldProject({ outDir: out, config: noOwner, slug: 'p', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false, withGateway: true, force: true })),
      /ownerPrincipal/,
    );
    // The DID is written into the generated server as a string literal: anything but a plain DID is refused outright.
    assert.throws(
      () => quiet(() => mod.scaffoldProject({ outDir: out, config: { ...config, agentDid: "did:key:z6Mk'); process.exit(0); ('" }, slug: 'p', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false, withGateway: true, force: true })),
      /not a DID/,
    );
  } finally { rmSync(out, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
});

// Every scaffolded gateway is pinned (2026-10-02): an unpinned one takes an interceptor's bundle as its rules. With no
// key there is no gateway — the interactive flows fetch it first (ensurePolicyKey) or stop with the config saved.
for (const [label, extra] of [['financial', {}], ['non-financial', { demo: mod.defaultNeutralDemo() }]]) {
  check(`a config with no issuer.policyKey is REFUSED a ${label} gateway, never given an unpinned one`, () => {
    const out = mkdtempSync(join(tmpdir(), 'metamynd-parse-'));
    try {
      const { issuer: _drop, ...oldConfig } = config;
      assert.throws(
        () => quiet(() => mod.scaffoldProject({ outDir: out, config: oldConfig, slug: 'p', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false, withGateway: true, ...extra })),
        /policy-signing key/,
      );
      assert.ok(!existsSync(join(out, 'gateway', 'server.mjs')), 'no gateway written');
    } finally { rmSync(out, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  });
}

check('...but the single-process scaffold (withGateway: false) needs no key', () => {
  const out = mkdtempSync(join(tmpdir(), 'metamynd-parse-'));
  try {
    const { issuer: _drop, ...oldConfig } = config;
    quiet(() => mod.scaffoldProject({ outDir: out, config: oldConfig, slug: 'p', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false, withGateway: false }));
    assertParses(out);
  } finally { rmSync(out, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
});

// "Change the rules" points at the dashboard path that exists (L-1: it said "Legal Entity → SOPs", which no menu has), and a
// --sandbox scaffold — the SHARED agent, which nobody has dashboard access to — says how to get an agent you can change (L-7).
for (const [label, extra] of [
  ['hosted financial, in-process', {}],
  ['hosted non-financial, in-process', { demo: mod.defaultNeutralDemo() }],
]) {
  for (const sandbox of [false, true]) {
    check(`${label}${sandbox ? ', --sandbox' : ''}: the rules-change copy names a path the user can reach`, () => {
      const out = mkdtempSync(join(tmpdir(), 'metamynd-parse-'));
      const lines = [];
      const log = console.log;
      console.log = (...a) => lines.push(a.join(' '));
      try {
        mod.scaffoldProject({ outDir: out, config, slug: 'p', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox, withGateway: false, ...extra });
      } finally { console.log = log; }
      try {
        assertParses(out);
        const agent = readFileSync(join(out, 'index.mjs'), 'utf8');
        const readme = readFileSync(join(out, 'README.md'), 'utf8');
        const printed = lines.join('\n');
        for (const [what, text] of [['agent', agent], ['README', readme], ['printed Next: text', printed]]) {
          assert.doesNotMatch(text, /Legal Entity (→|->) SOPs/, `${what} still names the nonexistent "Legal Entity → SOPs" path`);
          if (sandbox) {
            assert.match(text, /shared sandbox agent/i, `${what} says the sandbox agent is shared`);
            assert.match(text, /without --sandbox/, `${what} says how to get an agent whose rules you can change`);
          } else {
            assert.match(text, /VeriFAI (→|->) Legal Entities (→|->) SOPs/, `${what} names the real dashboard path`);
          }
        }
      } finally { rmSync(out, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
    });
  }
}

// ensurePolicyKey: the provisioning response's key wins; otherwise GET /magp/policy/pubkey on the same API; otherwise null.
{
  const http = await import('node:http');
  let served = 'cd'.repeat(32);
  const srv = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(req.url === '/api/v1/magp/policy/pubkey' ? JSON.stringify({ success: true, data: { publicKey: served } }) : '{}');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}/api/v1`;
  try {
    await checkAsync('ensurePolicyKey keeps the provisioning response key', async () => {
      const cfg = { issuer: { policyKey: 'ab'.repeat(32) } };
      assert.equal(await mod.ensurePolicyKey(cfg, base), 'ab'.repeat(32));
    });
    await checkAsync('ensurePolicyKey falls back to GET /magp/policy/pubkey and saves it into the config', async () => {
      const cfg = {};
      assert.equal(await mod.ensurePolicyKey(cfg, base), 'cd'.repeat(32));
      assert.equal(cfg.issuer.policyKey, 'cd'.repeat(32));
    });
    await checkAsync('ensurePolicyKey returns null for a missing or malformed key (the caller then scaffolds no gateway)', async () => {
      served = 'not-a-key';
      assert.equal(await mod.ensurePolicyKey({}, base), null);
      assert.equal(await mod.ensurePolicyKey({}, 'http://127.0.0.1:1/api/v1'), null);
    });
  } finally {
    srv.close();
  }
}

if (failed) { console.log(`\n${failed} check(s) FAILED`); process.exit(1); }
console.log('\nPASS — every generated JavaScript file parses.');

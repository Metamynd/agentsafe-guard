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
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
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
const config = { apiBase: 'http://127.0.0.1:1', agentDid: 'did:key:zStub', agentKey: 'aa', identityId: 'stub', keyVerified: true, mandate: { scope: 'flight-purchase' } };

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

if (failed) { console.log(`\n${failed} check(s) FAILED`); process.exit(1); }
console.log('\nPASS — every generated JavaScript file parses.');

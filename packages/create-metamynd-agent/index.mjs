#!/usr/bin/env node
// create-metamynd-agent — scaffold a MetaMynd/AgentSafe-governed agent in one command.
//
// Logs a KYB-verified owner in, provisions the agent in ONE call
// (POST /onboarding/agent → identity + mandate + starter SOP + enforced Standards),
// writes the portable `agent.metamynd.json`, and drops a runnable example that gates a
// tool through the guard (allow / block / escalate).
//
// ZERO dependencies: Node ≥ 18 built-ins only (fetch, readline).
//
//   npm create metamynd-agent@latest
//   npx create-metamynd-agent
//   npx create-metamynd-agent --api http://localhost:9926/api/v1 --email you@x.com \
//       --name "Support Bot" --scope flight-purchase --per-txn-max 500 --out ./support-bot --yes
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import readline from 'node:readline';
import crypto from 'node:crypto';

const GUARD_PKG = '@metamynd/agentsafe-guard';
// Must track the guard's MINOR line, not just its major. On a 0.x package `^0.4.0` means
// >=0.4.0 <0.5.0, so leaving this at ^0.4.0 would scaffold an agent whose `npm test` runs
// `agentsafe-guard verify` against a guard that has no such command.
const GUARD_VERSION = '^0.5.0';
const DEFAULT_API = 'https://metamynd.ai/api/v1';

// ---------- tiny ANSI ----------
const c = {
  b: (s) => `\x1b[1m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};

// ---------- args ----------
function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { out.help = true; continue; }
    if (a === '-v' || a === '--version') { out.version = true; continue; }
    if (a === '-y' || a === '--yes' || a === '--non-interactive') { out.yes = true; continue; }
    // Explicit, so `--force ./dir` cannot swallow the path as this flag's value.
    if (a === '-f' || a === '--force') { out.force = true; continue; }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) { out[a.slice(2, eq)] = a.slice(eq + 1); continue; }
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('-')) { out[key] = true; }
      else { out[key] = next; i++; }
    } else { out._.push(a); }
  }
  return out;
}

const HELP = `${c.b('create-metamynd-agent')} — scaffold a governed AI agent

${c.b('Usage')}
  npm create metamynd-agent@latest
  npx create-metamynd-agent [options]

${c.b('Options')}
  --sandbox            No login, no KYB: scaffold against the shared sandbox agent (fastest start)
  --request            Delegated: request an agent for an owner's org (--owner <email>, +--byok)
  --claim [--watch]    Delegated: claim the config once the owner approves (reads metamynd-request.json)
  --owner <email>      Target owner's email (with --request)
  --force, -f          Scaffold into a non-empty directory, overwriting existing files
  --api <url>          API base (default ${DEFAULT_API})
  --email <email>      Owner login email
  --password <pw>      Owner password (prefer the interactive prompt or METAMYND_PASSWORD)
  --name <name>        Agent name (e.g. "Support Bot")
  --scope <scope>      Mandate action scope (e.g. flight-purchase)
  --per-txn-max <n>    Per-transaction cap (default 500)
  --max-amount <n>     Total mandate budget (default 10000)
  --currency <cur>     Currency (default USD)
  --merchants <a,b>    Allowed merchants, comma-separated (optional)
  --byok               Bring-your-own-key: generate the keypair locally, provision + prove control
                       (MetaMynd never sees the private key). Overridden by --public-key.
  --public-key <hex>   BYOK with a key you already hold (SPKI/raw hex); you prove control yourself
  --out <dir>          Output project directory (default ./<agent-slug>)
  --yes, -y            Non-interactive: use flags/env/defaults, never prompt
  -h, --help           Show this help
  -v, --version        Show version

${c.b('Environment')}
  METAMYND_API, METAMYND_EMAIL, METAMYND_PASSWORD  — fallbacks for the flags above

${c.b('What it does')}
  1. Logs in as a KYB-verified owner       → owner access token
  2. POST /onboarding/agent (one call)      → identity + mandate + SOP + Standards
  3. Writes agent.metamynd.json + a runnable example that gates a tool through the guard.
`;

// ---------- prompts ----------
function makeRl() {
  return readline.createInterface({ input: process.stdin, output: process.stdout });
}
function ask(rl, query, def) {
  const suffix = def !== undefined && def !== '' ? c.dim(` (${def})`) : '';
  return new Promise((res) => rl.question(`${query}${suffix}: `, (a) => res(a.trim() || (def ?? ''))));
}
// Hidden input (password) — raw mode, masks with '*', handles backspace/paste/Ctrl-C.
function askHidden(query) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stdout.write(`${query}: `);
    const wasRaw = stdin.isRaw;
    if (stdin.setRawMode) stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let input = '';
    const done = () => {
      if (stdin.setRawMode) stdin.setRawMode(Boolean(wasRaw));
      stdin.pause();
      stdin.removeListener('data', onData);
      process.stdout.write('\n');
      resolve(input);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        const code = ch.charCodeAt(0);
        if (code === 13 || code === 10 || code === 4) { done(); return; } // Enter / Ctrl-D
        if (code === 3) { process.stdout.write('\n'); process.exit(130); } // Ctrl-C
        if (code === 127 || code === 8) { if (input.length) { input = input.slice(0, -1); process.stdout.write('\b \b'); } continue; } // backspace
        if (code < 32) continue; // ignore other control chars
        input += ch;
        process.stdout.write('*');
      }
    };
    stdin.on('data', onData);
  });
}

function fail(msg) {
  console.error(`\n${c.red('✖')} ${msg}\n`);
  process.exit(1);
}

function slugify(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'metamynd-agent';
}

// ---------- BYOK (bring-your-own-key) ----------
// Generate an Ed25519 keypair CLIENT-SIDE — the private key never leaves this machine, so MetaMynd
// never sees it. The public key is sent as SPKI DER hex (algorithm-tagged Ed25519, unambiguous to
// the Hedera SDK); the private key is PKCS8 DER hex, the exact format the guard's createGuard loads.
function generateAgentKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyHex: publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
    privateKeyHex: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex'),
  };
}

// Sign a BYOK challenge exactly as the gate verifies it: Ed25519 over the UTF-8 bytes of the raw
// challenge nonce, hex-encoded. Mirrors agentsafe-guard's sign().
function signChallengeHex(privateKeyHex, challenge) {
  const key = crypto.createPrivateKey({ key: Buffer.from(privateKeyHex, 'hex'), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(challenge, 'utf8'), key).toString('hex');
}

// ---------- API ----------
async function apiPost(base, path, body, token) {
  let res;
  try {
    res = await fetch(`${base}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    });
  } catch (e) {
    fail(`Cannot reach ${base}${path} — is the API up? (${e.message})`);
  }
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  if (!res.ok) {
    const detail = json?.message ? (typeof json.message === 'string' ? json.message : JSON.stringify(json.message)) : text.slice(0, 300);
    fail(`${path} → HTTP ${res.status}${detail ? `: ${detail}` : ''}`);
  }
  return json;
}

// ---------- scaffolding ----------
function exampleIndex(scope, perTxnMax) {
  const under = Math.max(1, Math.round(perTxnMax * 0.5));
  const over = Math.round(perTxnMax + 100);
  return `// index.mjs — your agent, governed by MetaMynd/AgentSafe.
// Every governed tool call is checked (allow / block / escalate) before it runs.
import { createGuardFromConfig } from '${GUARD_PKG}';

// Loads agent.metamynd.json: the agent's DID, its signing key, and the gate to call.
const guard = await createGuardFromConfig('./agent.metamynd.json'); // no env vars

// --- Your real tool. Replace the body with your actual implementation. ---
async function bookFlight(args) {
  return { pnr: 'PNR-DEMO', ...args };
}

// --- The GATED version. Register THIS with your agent instead of the raw handler. ---
const gatedBookFlight = guard.guardTool(
  '${scope}',                                   // = your mandate scope
  bookFlight,
  (a) => ({                                     // map tool args → gate inputs
    amount: a.amount,
    currency: 'USD',
    merchant: a.merchant,
    context: { tool: 'book-flight', riskLevel: a.riskLevel ?? 'low' },
  }),
);

// --- A tool the agent was NEVER granted. Wrapping it is the demonstration: there is no
// --- rule anywhere forbidding this. The mandate simply never mentioned the action.
async function raiseOwnLimit(args) {
  return { updated: true, ...args };          // never runs, and that is the point
}

const gatedRaiseOwnLimit = guard.guardTool(
  'permissions.update',                       // an action NOT in the mandate
  raiseOwnLimit,
  (a) => ({
    amount: a.amount,
    currency: 'USD',
    merchant: a.merchant,
    context: { tool: 'permissions-update' },
  }),
);

const dim = (t) => '\\x1b[2m' + t + '\\x1b[0m';
const bold = (t) => '\\x1b[1m' + t + '\\x1b[0m';
const rule = (n) => '  ' + '-'.repeat(n);

// Plain-English meaning for the reason codes this demo can produce.
const WHY = {
  AUTHORIZED: 'inside the mandate and under the SOP spend cap',
  SOP_SPEND_CAP: 'your SOP caps a single transaction at $${perTxnMax}',
  RISK_REVIEW: 'your SOP sends high-risk actions to a human first',
  MERCHANT_NOT_ALLOWED: 'the mandate lists which merchants this agent may pay',
  // Both say the same thing from where you are standing: the mandate does not cover that
  // action. Which one you see depends on whether the verdict was reached here or at the
  // gate, and neither of them depends on the amount.
  NO_PERMISSION_FOR_ACTION: 'the mandate never granted this action - at any amount',
  NO_MANDATE: 'there is no mandate for this action at all',
};

// ---------------------------------------------------------------- 1. CONTEXT
console.log('');
console.log(bold('  What this simulation shows'));
console.log('');
console.log('  An agent should not be the thing that decides what it is allowed to do.');
console.log('  This run makes that concrete. Three attempts take the SAME code path and');
console.log('  produce three different outcomes. The fourth asks for something the agent');
console.log('  was never granted at all - and that is the one a prompt could not have');
console.log('  stopped, because the decision is not made inside your program.');

// ---------------------------------------------------------------- 2. MECHANISM
console.log('');
console.log(bold('  How it does that'));
console.log('');
console.log(dim('   1. this project holds an agent identity (a DID) and its signing key'));
console.log(dim('   2. that agent has a mandate - a scope it may act in, and a spend cap'));
console.log(dim('   3. guardTool() wraps your tool, so nothing calls the raw handler'));
console.log(dim('   4. each attempt is signed here, then decided by MetaMynd remotely'));
console.log(dim('   5. your tool runs ONLY if that decision is ALLOW'));
console.log('');
console.log(dim('  scope  ${scope}'));
console.log(dim('  cap    $${perTxnMax} per transaction, set by your SOP'));

// ---------------------------------------------------------------- 3. THE STEPS
async function attempt(n, intent, args, tool = gatedBookFlight) {
  console.log('');
  console.log(bold('  Step ' + n + ' of 4') + ' - ' + intent);
  console.log(dim('     signing the request locally, then asking the gate to decide...'));
  try {
    const r = await tool(args);
    console.log('\\x1b[32m     ALLOWED\\x1b[0m  your tool ran and returned ' + (r.pnr ?? 'ok'));
    console.log(dim('     ' + WHY.AUTHORIZED));
  } catch (e) {
    const g = e.governance ?? {};
    const why = WHY[g.reasonCode] ?? e.message;
    if (g.decision === 'escalate') {
      console.log('\\x1b[33m     ESCALATED\\x1b[0m  held for a human - ' + g.reasonCode);
      console.log(dim('     ' + why));
      console.log(dim('     not a failure: approve it in the dashboard and the action resumes.'));
    } else {
      console.log('\\x1b[31m     BLOCKED\\x1b[0m  ' + (g.reasonCode ?? 'refused'));
      console.log(dim('     ' + why));
      console.log(dim('     your tool never ran - the gate refused before execution.'));
    }
  }
}

console.log('');
console.log(rule(66));
await attempt(1, 'a $${under} booking, low risk. Expected to pass.', { amount: ${under}, merchant: 'skyward-air', riskLevel: 'low' });
await attempt(2, 'a $${over} booking, deliberately over the cap.', { amount: ${over}, merchant: 'skyward-air', riskLevel: 'low' });
await attempt(3, 'a $${under} booking, but flagged high risk.', { amount: ${under}, merchant: 'skyward-air', riskLevel: 'high' });
await attempt(
  4,
  'the agent stops booking flights and asks to raise its OWN limit.',
  { amount: 100000, merchant: 'skyward-air' },
  gatedRaiseOwnLimit,
);
console.log('');
console.log(rule(66));

// ---------------------------------------------------------------- 4. RESULT
console.log('');
console.log(bold('  What this proved'));
console.log('');
console.log(dim('   - one code path, three outcomes. The rules decided, not this file'));
console.log(dim('     and not the model driving it.'));
console.log(dim('   - step 4 needed no rule to stop it. The agent could not widen its own'));
console.log(dim('     authority, because it cannot name an action nobody delegated to it.'));
console.log(dim('   - the blocked call never reached your tool at all.'));
console.log(dim('   - every decision was recorded as tamper-evident evidence.'));
console.log(dim('   - if the gate were unreachable the guard fails CLOSED: it blocks.'));
console.log('');
console.log('  Change the cap in the dashboard (Legal Entity -> SOPs) and run again.');
console.log(dim('  The outcome changes. This file does not. That is the point.'));
console.log('');
`;
}

function examplePackageJson(slug) {
  return JSON.stringify(
    {
      name: slug,
      version: '0.1.0',
      private: true,
      type: 'module',
      // `verify` is scaffolded in because governance that lives only in a dashboard is a
      // thing someone has to remember to look at. As a build step it is a control: a change
      // that widens this agent's authority fails `npm test`.
      scripts: { start: 'node index.mjs', test: 'agentsafe-guard verify' },
      dependencies: { [GUARD_PKG]: GUARD_VERSION },
    },
    null,
    2,
  ) + '\n';
}

function exampleReadme(slug, scope) {
  return `# ${slug}

A MetaMynd/AgentSafe-governed agent, scaffolded with \`create-metamynd-agent\`.

## Run

\`\`\`bash
npm install
npm start
\`\`\`

You should see an ALLOW, a BLOCK (over the per-transaction cap), and an ESCALATE (high risk).

## Files

- \`agent.metamynd.json\` — your portable guard config (identity, mandate scope \`${scope}\`, issuer keys).
  **Contains the agent's secret key — never commit it.** It is already in \`.gitignore\`.
- \`index.mjs\` — wraps a tool with \`guard.guardTool(...)\`; the tool only runs when the gate allows.

## Change the rules

Edit the agent's SOPs in the dashboard (Legal Entity → SOPs). The agent's behaviour changes live —
no redeploy. An \`escalate\` verdict is held for an owner to approve; poll \`guard.escalationStatus(id)\`.

Full integration guide: \`docs/integration/INTEGRATE-WITH-METAMYND.md\`.
`;
}

function gitignore() {
  return `node_modules/\nagent.metamynd.json\n.env\n`;
}

function writeFileSafe(dir, name, content, force = false) {
  const p = join(dir, name);
  const exists = existsSync(p);
  if (exists && !force) { console.log(`  ${c.yellow('skip')}  ${name} ${c.dim('(exists)')}`); return; }
  writeFileSync(p, content);
  console.log(`  ${exists ? c.yellow('overwrite') : c.green('create')} ${name}`);
}

/**
 * Refuse to scaffold into a non-empty directory unless --force.
 *
 * Silently skipping an existing agent.metamynd.json is worse than it sounds:
 * provisioning has already minted a NEW agent server-side, so the scaffold prints
 * success while leaving the OLD config in place. Every later gate call then runs as
 * the previous identity, against whatever apiBase that file happens to carry — which
 * is exactly how a stale http:// base survived a re-scaffold and 404'd every call.
 */
function assertScaffoldTarget(outDir, force) {
  if (force || !existsSync(outDir)) return;
  const entries = readdirSync(outDir);
  if (entries.length === 0) return;
  const rel = outDir.replace(resolve('.'), '.').replace(/\\/g, '/');
  fail(
    `${rel} is not empty (${entries.length} item${entries.length === 1 ? '' : 's'}).\n\n` +
      `  Scaffolding here would KEEP the existing files — including any agent.metamynd.json —\n` +
      `  so this project would keep running as the identity in that file, against the apiBase\n` +
      `  in that file, and the newly provisioned agent would go unused.\n\n` +
      `  Scaffold somewhere new:        --out ./another-dir\n` +
      `  or overwrite this one on purpose: --force`,
  );
}

/** Write the scaffolded project + print next steps. Shared by the provision and sandbox paths. */
function scaffoldProject({ outDir, config, slug, scope, perTxnMax, sandbox, force = false }) {
  assertScaffoldTarget(outDir, force);
  console.log(`\n  ${c.b('Scaffolding')} ${c.dim(outDir)}`);
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  writeFileSafe(outDir, 'agent.metamynd.json', JSON.stringify(config, null, 2) + '\n', force);
  writeFileSafe(outDir, 'index.mjs', exampleIndex(scope, perTxnMax), force);
  writeFileSafe(outDir, 'package.json', examplePackageJson(slug), force);
  writeFileSafe(outDir, '.gitignore', gitignore(), force);
  writeFileSafe(outDir, 'README.md', exampleReadme(slug, scope), force);

  const rel = outDir.replace(resolve('.'), '.').replace(/\\/g, '/');
  console.log(`\n${c.green(c.b('  ✓ Done.'))} Your governed agent is ready.\n`);
  if (sandbox) {
    console.log(`  ${c.dim('Shared sandbox agent — for trying MetaMynd only. Provision your own (drop --sandbox) for anything real.')}\n`);
  } else if (config.agentKey) {
    console.log(`  ${c.yellow('⚠ agent.metamynd.json holds the agent secret key')} — it is gitignored; never commit it.\n`);
  }
  console.log(`  Next:`);
  console.log(c.cyan(`    cd ${rel}`));
  console.log(c.cyan(`    npm install`));
  // The example runs FOUR attempts. This summary promised three, so the one carrying the
  // whole argument — the agent asking to raise its own limit — arrived unannounced.
  console.log(c.cyan(`    npm start`) + c.dim('   → ALLOW · BLOCK (over cap) · ESCALATE (high risk)'));
  console.log(c.dim('                 · BLOCK (the agent asking to raise its OWN limit)\n'));
  console.log(c.cyan(`    npm test`) + c.dim('    → assert it CANNOT exceed its mandate. Put this in CI.\n'));
  console.log(c.dim(`  Change the rules any time in the dashboard (Legal Entity → SOPs) — no redeploy.\n`));
}

/** --sandbox: no login, no KYB — fetch the shared sandbox agent config and scaffold. */
async function runSandbox(args) {
  const apiRaw = (typeof args.api === 'string' ? args.api : undefined) ?? process.env.METAMYND_API ?? DEFAULT_API;
  const base = String(apiRaw).replace(/\/+$/, '');
  // Check the target BEFORE provisioning: refusing afterwards would mint an agent
  // server-side and then throw it away.
  const outDir = resolve(String(args.out || './metamynd-sandbox'));
  assertScaffoldTarget(outDir, !!args.force);
  console.log(c.dim(`  → requesting a sandbox agent from ${base} …`));
  const provisioned = await apiPost(base, '/onboarding/sandbox', {}, null);
  const config = provisioned?.data;
  if (!config?.agentDid) fail('Sandbox did not return a config with an agentDid.');
  console.log(`  ${c.green('✓')} sandbox agent ${c.b(config.agentDid)} ${c.dim('(shared test identity)')}`);
  const scope = config.mandate?.scope || 'flight-purchase';
  const perTxnMax = Number(config.perTxnMax) || 500;
  scaffoldProject({ outDir, config, slug: 'metamynd-sandbox', scope, perTxnMax, sandbox: true, force: !!args.force });
}

// ---------- delegated issuance (#6) ----------
async function apiGet(base, path, { claimToken } = {}) {
  let res;
  try {
    res = await fetch(`${base}${path}`, { headers: { ...(claimToken ? { 'x-claim-token': claimToken } : {}) } });
  } catch (e) {
    fail(`Cannot reach ${base}${path} — is the API up? (${e.message})`);
  }
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  if (!res.ok) fail(`${path} → HTTP ${res.status}${json?.message ? `: ${json.message}` : ''}`);
  return json;
}

// Minimal auth for the request flow (flags/env, interactive fallback) — mirrors main()'s login.
async function authFlow(args) {
  const apiRaw = (typeof args.api === 'string' ? args.api : undefined) ?? process.env.METAMYND_API ?? DEFAULT_API;
  const base = String(apiRaw).replace(/\/+$/, '');
  const interactive = !args.yes && process.stdin.isTTY;
  const rl = interactive ? makeRl() : null;
  let email = (typeof args.email === 'string' ? args.email : undefined) ?? process.env.METAMYND_EMAIL;
  if (!email && interactive) email = await ask(rl, 'Your email', '');
  if (!email) { rl?.close(); fail('An email is required (--email or METAMYND_EMAIL).'); }
  let password = typeof args.password === 'string' ? args.password : process.env.METAMYND_PASSWORD;
  if (password === undefined) {
    if (!interactive) { rl?.close(); fail('A password is required (--password or METAMYND_PASSWORD).'); }
    rl?.pause();
    password = await askHidden('Password');
    rl?.resume();
  }
  rl?.close();
  const login = await apiPost(base, '/auth/login', { username: email, password }, null);
  const token = login?.data?.accessToken;
  if (!token) fail('Login succeeded but no access token was returned.');
  return { base, token, email };
}

const REQUEST_STATE_FILE = 'metamynd-request.json';

// --request: a developer requests an agent for an owner's org (the owner approves in the dashboard).
// Writes metamynd-request.json (requestId + one-time claim token, and the local private key for --byok)
// so `--claim` can finish once the owner approves.
async function runRequest(args) {
  const owner = (typeof args.owner === 'string' ? args.owner : undefined) ?? process.env.METAMYND_OWNER;
  if (!owner) fail('--owner <ownerEmail> is required for a delegated request.');
  const { base, token } = await authFlow(args);

  const name = (typeof args.name === 'string' ? args.name : undefined) ?? 'Delegated Agent';
  const scope = (typeof args.scope === 'string' ? args.scope : undefined) ?? 'flight-purchase';
  const perTxnMax = Number(args['per-txn-max']) || 500;
  let publicKey, generated;
  if (args.byok) {
    generated = generateAgentKeypair();
    publicKey = generated.publicKeyHex;
    console.log(`  ${c.green('✓')} generated an Ed25519 keypair locally ${c.dim('(private key stays on this machine)')}`);
  }

  console.log(c.dim(`  → requesting "${name}" for ${owner} …`));
  const res = await apiPost(base, '/onboarding/requests', { ownerEmail: owner, name, scope, perTxnMax, ...(publicKey ? { publicKey } : {}) }, token);
  const d = res.data;
  const state = { api: base, requestId: d.requestId, claimToken: d.claimToken, byok: !!generated, privateKey: generated?.privateKeyHex ?? null, name, scope, perTxnMax };
  const file = resolve(String(args.out || '.'), REQUEST_STATE_FILE);
  writeFileSync(file, JSON.stringify(state, null, 2) + '\n');

  console.log(`  ${c.green('✓')} request ${c.b(d.requestId)} submitted — awaiting ${owner}'s approval`);
  console.log(`  ${c.yellow('⚠ saved the one-time claim token to')} ${file.replace(resolve('.'), '.').replace(/\\/g, '/')} ${c.dim('(secret — do not commit)')}\n`);
  console.log(`  The owner approves in the dashboard (AgentSafe → Agent Requests). Then run:`);
  console.log(c.cyan(`    npx create-metamynd-agent --claim --watch\n`));
}

// --claim: poll for the owner's approval, then scaffold. Reads metamynd-request.json (or flags).
async function runClaim(args) {
  const file = resolve(String(args['request-file'] || `./${REQUEST_STATE_FILE}`));
  const state = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
  const base = String((typeof args.api === 'string' ? args.api : undefined) ?? state.api ?? DEFAULT_API).replace(/\/+$/, '');
  const requestId = (typeof args['request-id'] === 'string' ? args['request-id'] : undefined) ?? state.requestId;
  const claimToken = (typeof args.token === 'string' ? args.token : undefined) ?? state.claimToken;
  if (!requestId || !claimToken) fail(`Need a requestId + claim token (--request-id/--token, or a ${REQUEST_STATE_FILE}).`);

  const watch = !!args.watch;
  let claimed;
  for (;;) {
    const res = await apiGet(base, `/onboarding/requests/${encodeURIComponent(requestId)}/claim`, { claimToken });
    const d = res.data;
    if (d.status === 'approved') { claimed = d; break; }
    if (d.status === 'denied' || d.status === 'expired') fail(`Request was ${d.status}.`);
    if (!watch) {
      console.log(`  ${c.dim(`request is still ${d.status} — the owner hasn't approved yet. Re-run, or add --watch to poll.`)}`);
      return;
    }
    process.stdout.write(c.dim(`  · ${d.status}, waiting for approval …\r`));
    await new Promise((r) => setTimeout(r, 5000));
  }

  const config = claimed.config;
  if (!config?.agentDid) fail('Approved, but no config was returned.');
  console.log(`\n  ${c.green('✓')} approved — claimed config for ${c.b(config.agentDid)}`);

  // BYOK: inject the local private key and prove control via the claim token.
  if (state.byok && state.privateKey && config.challenge) {
    config.agentKey = state.privateKey;
    const signature = signChallengeHex(state.privateKey, config.challenge);
    await apiPost(base, `/onboarding/requests/${encodeURIComponent(requestId)}/verify-key`, { signature, claimToken }, null);
    config.keyVerified = true;
    delete config.challenge;
    console.log(`  ${c.green('✓')} key verified — MetaMynd never saw your private key`);
  }

  const slug = slugify(state.name || 'metamynd-agent');
  const outDir = resolve(String(args.out || `./${slug}`));
  scaffoldProject({ outDir, config, slug, scope: state.scope || config.mandate?.scope || 'flight-purchase', perTxnMax: Number(state.perTxnMax) || 500, sandbox: false, force: !!args.force });
}

// ---------- main ----------
async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(HELP); return; }
  if (args.version) {
    try { console.log(JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version); }
    catch { console.log('unknown'); }
    return;
  }

  console.log(`\n${c.b(c.cyan('  create-metamynd-agent'))}  ${c.dim('— provision a governed agent in ~2 minutes')}\n`);

  // --sandbox: skip login + provisioning entirely.
  if (args.sandbox) { await runSandbox(args); return; }
  // Delegated issuance (#6): request an agent for an owner's org / claim it once approved.
  if (args.request) { await runRequest(args); return; }
  if (args.claim) { await runClaim(args); return; }

  const interactive = !args.yes && process.stdin.isTTY;
  const rl = interactive ? makeRl() : null;
  const pick = async (flag, envVar, prompt, def) => {
    const fromFlag = typeof args[flag] === 'string' ? args[flag] : undefined;
    const fromEnv = envVar ? process.env[envVar] : undefined;
    if (fromFlag !== undefined) return fromFlag;
    if (fromEnv !== undefined && fromEnv !== '') return fromEnv;
    if (!interactive) return def;
    return ask(rl, prompt, def);
  };

  // 1. Connection + login
  const apiRaw = await pick('api', 'METAMYND_API', 'API base URL', DEFAULT_API);
  const base = String(apiRaw).replace(/\/+$/, '');
  const email = await pick('email', 'METAMYND_EMAIL', 'Owner email', '');
  if (!email) { rl?.close(); fail('An owner email is required (--email or METAMYND_EMAIL).'); }
  let password = typeof args.password === 'string' ? args.password : process.env.METAMYND_PASSWORD;
  if (password === undefined) {
    if (!interactive) { rl?.close(); fail('A password is required in --yes mode (--password or METAMYND_PASSWORD).'); }
    // Pause the readline interface so it doesn't consume the raw keystrokes.
    rl?.pause();
    password = await askHidden('Owner password');
    rl?.resume();
  }

  console.log(c.dim(`\n  → logging in to ${base} …`));
  const login = await apiPost(base, '/auth/login', { username: email, password }, null);
  const token = login?.data?.accessToken;
  if (!token) { rl?.close(); fail('Login succeeded but no access token was returned.'); }
  console.log(`  ${c.green('✓')} authenticated as ${email}`);

  // 2. Agent details
  const name = await pick('name', null, 'Agent name', 'Support Bot');
  const scope = await pick('scope', null, 'Mandate scope (governed action)', 'flight-purchase');
  const perTxnMax = Number(await pick('per-txn-max', null, 'Per-transaction cap', '500')) || 500;
  const maxAmount = Number(await pick('max-amount', null, 'Total mandate budget', '10000')) || 10000;
  const currency = (await pick('currency', null, 'Currency', 'USD')) || 'USD';
  const merchantsRaw = await pick('merchants', null, 'Allowed merchants (comma-sep, blank = any)', '');
  const merchants = String(merchantsRaw).split(',').map((s) => s.trim()).filter(Boolean);

  // BYOK: --byok generates a keypair on THIS machine (MetaMynd never sees the private key). An
  // explicit --public-key means the caller holds the key elsewhere and will prove it themselves.
  let publicKey = typeof args['public-key'] === 'string' ? args['public-key'] : undefined;
  let generatedKey = null;
  if (args.byok && !publicKey) {
    generatedKey = generateAgentKeypair();
    publicKey = generatedKey.publicKeyHex;
    console.log(`  ${c.green('✓')} generated an Ed25519 keypair locally ${c.dim('(private key stays on this machine)')}`);
  }

  const slug = slugify(name);
  const outDir = resolve(String(args.out || (interactive ? await ask(rl, 'Output directory', `./${slug}`) : `./${slug}`)));

  rl?.close();

  // 3. Provision (one call)
  console.log(c.dim(`\n  → provisioning "${name}" (identity + mandate + SOP + Standards) …`));
  const body = { name, scope, currency, maxAmount, perTxnMax, merchants, ...(publicKey ? { publicKey } : {}) };
  const provisioned = await apiPost(base, '/onboarding/agent', body, token);
  const config = provisioned?.data;
  if (!config?.agentDid) fail('Provisioning did not return a config with an agentDid.');
  console.log(`  ${c.green('✓')} agent DID ${c.b(config.agentDid)}`);
  if (config.standards?.length) console.log(`  ${c.green('✓')} enforced Standards: ${config.standards.join(', ')}`);

  // 3b. BYOK: prove control of the key (verify-key), else the gate blocks with AGENT_KEY_UNVERIFIED.
  if (generatedKey) {
    // We hold the private key — inject it into the config so the scaffolded guard can sign, and
    // prove possession by signing the issued challenge.
    config.agentKey = generatedKey.privateKeyHex;
    if (config.challenge) {
      console.log(c.dim('  → proving key control (verify-key) …'));
      const signature = signChallengeHex(generatedKey.privateKeyHex, config.challenge);
      await apiPost(base, `/agent-identity/${encodeURIComponent(config.identityId)}/verify-key`, { signature }, token);
      config.keyVerified = true;
      delete config.challenge; // one-time; consumed
      console.log(`  ${c.green('✓')} key verified — MetaMynd never saw your private key`);
    }
  } else if (publicKey) {
    // External BYOK key the CLI can't sign — tell the operator how to finish proving control.
    console.log(`  ${c.yellow('⚠ bring-your-own-key:')} no managed key minted. Prove control before the gate accepts the agent:`);
    console.log(c.dim(`      sign this challenge with your private key (Ed25519 over its UTF-8 bytes, hex):`));
    console.log(c.dim(`      challenge: ${config.challenge ?? '(none returned)'}`));
    console.log(c.dim(`      POST ${base}/agent-identity/${config.identityId}/verify-key  { "signature": "<hex>" }  (owner token)`));
  }

  // 4. Scaffold + next steps
  scaffoldProject({ outDir, config, slug, scope, perTxnMax, sandbox: false, force: !!args.force });
}

main().catch((e) => fail(e?.stack || e?.message || String(e)));

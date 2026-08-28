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
  --harness            No login, no KYB, no network at all: a free local governance harness —
                       your own rules, your own identity, decided entirely on this machine. See
                       README#harness. Not for enterprise use (no anchored identity/evidence,
                       no cross-party trust) — that is what the hosted platform adds.
  --sandbox            No login, no KYB: scaffold against the shared sandbox agent (fastest start)
  --config <file>      A JSON policy file (name/scope/limits + simple "rules") — see README#config-file.
                       Flags below still override individual fields from the file. Works with
                       --harness too (its rules become the harness's starter rules file).
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
  --port <n>           --harness only: the local dashboard's port (default 4400)
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

// ---------- policy config file (--config) ----------
// The API/SOP/molecule authoring surface is real, but it is not where a developer wants to
// START — round-five feedback named this precisely: "developers need a simpler policy file
// first." Everything a simple file needs already exists server-side (ProvisionSchema already
// takes mandate limits + an optional sop.documentJson.molecules array in one flat JSON body),
// so this is a thin, ZERO-DEPENDENCY translator — plain JSON, not YAML, so the CLI keeps the
// "no dependencies at all" property the guard itself is built on — not a new policy engine.
//
// Shape:
//   {
//     "name": "Procurement Agent", "scope": "purchase-order", "currency": "USD",
//     "maxAmount": 20000, "perTxnMax": 2000, "merchants": ["acme-supplies"],
//     "rules": [
//       { "when": { "predicate": "amount-over", "config": { "limit": 2000 } }, "then": "escalate" }
//     ]
//   }
// `rules` is sugar for the common one-atom-one-decision case, compiled to a `molecules` array
// below. A caller who needs a real combinator/multi-atom molecule can supply `molecules`
// directly instead — `rules` is ignored when `molecules` is present.
function loadConfigFile(path) {
  let raw;
  try { raw = readFileSync(resolve(path), 'utf8'); }
  catch (e) { fail(`Could not read config file ${path} (${e.message})`); }
  let json;
  try { json = JSON.parse(raw); }
  catch (e) { fail(`${path} is not valid JSON (${e.message})`); }
  if (json === null || typeof json !== 'object' || Array.isArray(json)) {
    fail(`${path} must be a JSON object.`);
  }
  return json;
}

// A rule needs `when.predicate` (the atom) and `then` (the decision the gate should return
// when it fires) — everything else is optional sugar. See backend's atom-catalog.ts for the
// full predicate list (amount-over, risk-at-or-above, jurisdiction-not-allowed, ...).
function ruleToMolecule(rule, i) {
  const when = rule?.when;
  if (!when || typeof when.predicate !== 'string') {
    fail(`rules[${i}] needs a "when.predicate" — see the config file docs for the atom list.`);
  }
  if (typeof rule.then !== 'string') {
    fail(`rules[${i}] needs a "then" decision (e.g. "block", "escalate").`);
  }
  return {
    id: `r${i + 1}`,
    name: rule.name,
    combinator: 'all',
    atoms: [{ id: 'a1', predicate: when.predicate, config: when.config ?? {} }],
    decision: rule.then,
    reasonCode: rule.reasonCode ?? `${when.predicate.toUpperCase().replace(/-/g, '_')}_${String(rule.then).toUpperCase()}`,
  };
}

/** Builds the `sop`/`rulePack` fields to merge into the provisioning body, or {} if the config file specifies neither. */
function configFileSopFields(config) {
  if (!config) return {};
  if (Array.isArray(config.molecules)) return { sop: { documentJson: { molecules: config.molecules } } };
  if (Array.isArray(config.rules) && config.rules.length) {
    return { sop: { documentJson: { molecules: config.rules.map(ruleToMolecule) } } };
  }
  if (typeof config.rulePack === 'string') return { rulePack: config.rulePack };
  return {};
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

// ---------- --harness: a free, local, zero-network governance harness ----------
//
// Not the hosted platform, and not trying to be. `guardToolLocal()` + `evaluateLocally()`
// (agentsafe-guard.mjs) already decide allow/block/escalate with NO network call, given
// {standards, sops, mandate} as plain objects — this mode is just the missing packaging:
// author those objects locally instead of fetching a signed bundle from a backend, add
// somewhere for a human to approve an escalate, and a page to see any of it.
//
// What you get: real gating, on your own machine, your own rules, no account.
// What you don't: anchored/verifiable identity, cross-party trust, evidence anyone but you
// can audit, a dashboard reachable when your machine is off. That gap is the paid platform —
// and it's a config change to cross, not a rewrite: point `bundleUrl` at a real MAGP_API
// (or re-provision with `create-metamynd-agent`, no --harness) and the SAME guardTool() calls
// keep working, sealed by a real gate instead of a rules file you authored yourself.

/** Mirrors defaultSopDocument() in backend/src/features/onboarding/onboarding.provision.ts —
 *  same starter rules the hosted platform issues, so a harness project behaves identically
 *  to a freshly-provisioned one before anyone edits either. */
function harnessDefaultSop(perTxnMax) {
  return {
    molecules: [
      { id: 'cap', name: 'Per-transaction cap', combinator: 'any', atoms: [{ id: 'a1', predicate: 'amount-over', config: { limit: perTxnMax } }], decision: 'block', reasonCode: 'SOP_SPEND_CAP' },
      { id: 'review', name: 'High-risk review', combinator: 'any', atoms: [{ id: 'a2', predicate: 'risk-at-or-above', config: { level: 'high' } }], decision: 'escalate', reasonCode: 'RISK_REVIEW' },
    ],
  };
}

/** Mirrors issueMandate()'s document shape in backend/src/features/policy/mandate/mandate.service.ts
 *  (minus the parts only a real principal/issuer can do: no VC, no Hedera anchor, no signature) —
 *  same shape evaluateMandate() in policy-core.mjs expects either way. */
function harnessMandate({ scope, currency, maxAmount, perTxnMax, merchants }) {
  return {
    uid: `urn:metamynd:mandate:local-${crypto.randomUUID()}`,
    profile: 'https://metamynd.ai/odrl/agent-mandate/v1',
    validFrom: new Date().toISOString(),
    validUntil: null,
    permission: [
      {
        target: scope,
        action: 'execute',
        constraint: [
          { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: perTxnMax, unit: currency },
          { leftOperand: 'mm:cumulativeSpend', operator: 'lteq', rightOperand: maxAmount, unit: currency },
          ...(merchants?.length ? [{ leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: merchants }] : []),
        ],
      },
    ],
  };
}

/** A clearly-local, clearly-not-anchored identifier — `guard.agentDid` is just a signing
 *  subject in the local path (never resolved against Hedera), but the format should not
 *  read as a verified did:hedera when it is not one. */
function harnessAgentDid(publicKeyHex) {
  return `did:key:local-${crypto.createHash('sha256').update(publicKeyHex, 'hex').digest('hex').slice(0, 32)}`;
}

function harnessRulesFile(mandate, sopDocument) {
  return JSON.stringify(
    {
      _comment: 'Your rules — edit here, or at the dashboard below. Reloaded on every decision, no restart needed.',
      mandate,
      sops: [{ standardKey: 'sop', document: sopDocument }],
      standards: [],
    },
    null,
    2,
  ) + '\n';
}

function harnessServerFile() {
  return `// harness-server.mjs — the free local governance dashboard. Zero dependencies.
// Runs in-process with your agent: shows the rules in force, lets you add/edit/remove SOP
// rules without hand-editing JSON, holds an escalated action for YOU to approve (there is no
// hosted owner queue here — you are the owner), and logs every decision. Bound to 127.0.0.1
// by default: this is a local trust boundary, not a service.
import http from 'node:http';
import { readFileSync, writeFileSync, appendFileSync, existsSync, writeFileSync as wf } from 'node:fs';
import { randomUUID } from 'node:crypto';
// The SAME atom catalog + validator the hosted platform's rule builder uses — so the add-rule
// form's predicate list, field types and validation never drift from what the gate accepts.
import { ATOM_SPECS, validateMolecules } from '${GUARD_PKG}/policy-core';

const OPERATORS = { lteq: '<=', gteq: '>=', lt: '<', gt: '>', eq: '==', neq: '!=', isAnyOf: 'is any of', isNoneOf: 'is none of' };
function renderConstraint(c) {
  const op = OPERATORS[c.operator] || c.operator;
  const right = Array.isArray(c.rightOperand) ? \`[\${c.rightOperand.join(', ')}]\` : c.rightOperand;
  return \`\${String(c.leftOperand).replace(/^mm:/, '')} \${op} \${right}\${c.unit ? ' ' + c.unit : ''}\`;
}
function renderAtom(a) {
  const c = a.config || {};
  switch (a.predicate) {
    case 'amount-over': return \`transaction amount must not exceed \${c.limit}\`;
    case 'cumulative-over': return \`cumulative spend must not exceed \${c.limit}\`;
    case 'jurisdiction-not-allowed': return \`jurisdiction must be one of [\${(c.allowed || []).join(', ')}]\`;
    case 'tool-not-allowed': return \`tool must be one of [\${(c.allowed || []).join(', ')}]\`;
    case 'risk-at-or-above': return \`risk level at or above \${c.level}\`;
    default: return \`\${a.predicate}\${Object.keys(c).length ? ' ' + JSON.stringify(c) : ''}\`;
  }
}
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// A field's declared type (from ATOM_SPECS) coerces a raw form string authoritatively —
// no guessing, unlike the generic value-edit coerce() below.
function coerceField(raw, type) {
  if (type === 'number') return Number(raw);
  if (type === 'string[]') return String(raw).split(',').map((s) => s.trim()).filter(Boolean);
  return raw; // string, enum
}

export function startDashboard({ port = 4400, host = '127.0.0.1', agentDid, scope, rulesPath, logPath }) {
  const holds = new Map(); // id -> { id, action, args, decision, ts, status, resolve }
  if (!existsSync(logPath)) wf(logPath, '');

  function log(entry) {
    try { appendFileSync(logPath, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\\n'); } catch { /* best-effort */ }
  }
  function tailLog(n = 25) {
    try {
      const lines = readFileSync(logPath, 'utf8').split('\\n').filter(Boolean);
      return lines.slice(-n).reverse().map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    } catch { return []; }
  }
  function readRules() {
    try { return JSON.parse(readFileSync(rulesPath, 'utf8')); } catch (e) { return { error: String(e?.message ?? e) }; }
  }
  function writeRules(next) {
    writeFileSync(rulesPath, JSON.stringify(next, null, 2) + '\\n');
  }

  /** Called by your agent code when a governed action escalates. Registers the hold (visible
   *  on the dashboard immediately) and returns { id, promise } — promise resolves to
   *  true/false the moment a human clicks Approve/Deny here. Nothing times this out; a caller
   *  that wants a demo-friendly timeout should race the promise itself. */
  function holdForApproval(action, args, decision) {
    const id = randomUUID();
    log({ type: 'escalate', id, action, args, reasonCode: decision.reasonCode });
    let resolveFn;
    const promise = new Promise((resolve) => { resolveFn = resolve; });
    holds.set(id, { id, action, args, decision, ts: Date.now(), status: 'pending', resolve: resolveFn });
    return { id, promise };
  }

  function logDecision(action, args, decision) {
    if (decision.decision === 'escalate') return; // holdForApproval already logs this one
    log({ type: decision.decision, action, args, reasonCode: decision.reasonCode });
  }

  function renderRulesHtml(rules) {
    if (rules.error) return \`<p class="err">Could not read \${esc(rulesPath)}: \${esc(rules.error)}</p>\`;
    const m = (rules.mandate?.permission || [])[0];
    const mandateRows = (m?.constraint || []).map((c, i) =>
      \`<div class="rule"><span class="rname">\${esc(c.leftOperand.replace(/^mm:/, ''))}</span><span class="rcond">\${esc(renderConstraint(c))}</span>
       <input data-kind="mandate" data-idx="\${i}" value="\${esc(Array.isArray(c.rightOperand) ? c.rightOperand.join(',') : c.rightOperand)}" /></div>\`).join('');
    // Grouped by molecule (one "rule" a person authored), not flattened — a molecule can have
    // several atoms/config fields, and the delete button acts on the whole rule, not one field.
    const sopGroups = (rules.sops || []).flatMap((s) => (s.document?.molecules || []).map((mo) => {
      const fieldRows = (mo.atoms || []).flatMap((a) => Object.entries(a.config || {}).map(([k, v]) =>
        \`<div class="rule"><span class="rcond">\${esc(renderAtom(a))}</span>
         <input data-kind="atom" data-mid="\${esc(mo.id)}" data-aid="\${esc(a.id)}" data-key="\${esc(k)}" value="\${esc(Array.isArray(v) ? v.join(',') : v)}" /></div>\`)).join('');
      return \`<div class="mgroup">
        <div class="mhead"><span class="rname">\${esc(mo.name || mo.id)}</span>
          <span class="reff">\${esc(mo.decision)} · \${esc(mo.reasonCode)}</span>
          <button class="delmol" data-id="\${esc(mo.id)}" title="Remove this rule">Delete</button></div>
        \${fieldRows}
      </div>\`;
    })).join('');
    return \`<div class="rules">\${mandateRows}</div>\${sopGroups}<button id="save">Save changes</button><span id="saveMsg"></span>
<div id="addRule">
  <h3>Add a rule</h3>
  <div class="addrow">
    <label>When <select id="addPredicate"></select></label>
    <label>Then <select id="addDecision">
      <option value="block">block</option><option value="escalate">escalate</option>
      <option value="observe">observe</option><option value="suspend">suspend</option>
      <option value="quarantine">quarantine</option>
    </select></label>
  </div>
  <p class="dim" id="addDesc"></p>
  <div id="addFields"></div>
  <div class="addrow">
    <label>Name <input id="addName" placeholder="(optional)" /></label>
    <label>Reason code <input id="addReasonCode" placeholder="(auto)" /></label>
  </div>
  <button id="addRuleBtn">Add rule</button><span id="addMsg"></span>
</div>\`;
  }

  function renderHoldsHtml() {
    const pending = [...holds.values()].filter((h) => h.status === 'pending').sort((a, b) => a.ts - b.ts);
    if (!pending.length) return '<p class="dim">No pending approvals.</p>';
    return pending.map((h) =>
      \`<div class="hold"><b>\${esc(h.action)}</b> <span class="dim">\${esc(h.decision.reasonCode)}</span>
       <pre>\${esc(JSON.stringify(h.args, null, 2))}</pre>
       <button class="approve" data-id="\${h.id}">Approve</button>
       <button class="deny" data-id="\${h.id}">Deny</button></div>\`).join('');
  }

  function renderLogHtml() {
    const rows = tailLog(25);
    if (!rows.length) return '<p class="dim">No decisions yet — run your agent.</p>';
    return rows.map((r) =>
      \`<div class="logrow \${esc(r.type)}"><span class="dot"></span><b>\${esc(r.action)}</b> \${esc(r.type)} <span class="dim">\${esc(r.reasonCode || '')} · \${esc(r.ts)}</span></div>\`).join('');
  }

  function page() {
    const rules = readRules();
    return \`<!doctype html><html><head><meta charset="utf-8"><title>MetaMynd harness — \${esc(scope)}</title>
<style>
  * { box-sizing: border-box; } body { margin:0; background:#f5f4f8; color:#1a1a2e; font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:16px 22px; border-bottom:1px solid #e2e0eb; background:#fff; }
  header h1 { font-size:16px; margin:0 0 4px; } header .did { font:11px ui-monospace,monospace; color:#6b6b80; }
  main { max-width:760px; margin:0 auto; padding:20px; }
  section { background:#fff; border:1px solid #e2e0eb; border-radius:10px; padding:14px 16px; margin-bottom:16px; }
  section h2 { font-size:13px; margin:0 0 10px; color:#6b6b80; text-transform:uppercase; letter-spacing:.04em; }
  .rule { display:flex; align-items:center; gap:10px; padding:6px 0; border-top:1px solid #eeecf3; flex-wrap:wrap; }
  .rule:first-child { border-top:none; } .rname { font-weight:600; } .reff { font-weight:400; color:#6b6b80; font-size:11px; }
  .rcond { font:12px ui-monospace,monospace; color:#6b6b80; flex:1; }
  .rule input { font:12px ui-monospace,monospace; border:1px solid #d8d5e6; border-radius:6px; padding:4px 8px; width:140px; }
  .mgroup { border-top:1px solid #eeecf3; padding:8px 0; }
  .mhead { display:flex; align-items:center; gap:10px; margin-bottom:2px; }
  .mhead .rname { min-width:150px; }
  button { font:inherit; cursor:pointer; border:none; border-radius:8px; padding:8px 14px; background:#6c4ff2; color:#fff; font-weight:600; }
  button.deny, button.delmol { background:#c02532; } button.approve { background:#0f7a43; }
  button.delmol { padding:4px 10px; font-size:11px; margin-left:auto; }
  #saveMsg, #addMsg { margin-left:10px; color:#0f7a43; font-size:12px; }
  #addRule { margin-top:14px; padding-top:14px; border-top:1px solid #eeecf3; }
  #addRule h3 { font-size:12px; margin:0 0 10px; color:#6b6b80; text-transform:uppercase; letter-spacing:.04em; }
  .addrow { display:flex; gap:16px; flex-wrap:wrap; margin-bottom:8px; }
  .addrow label { display:flex; flex-direction:column; gap:3px; font-size:12px; color:#6b6b80; }
  .addrow input, .addrow select, #addFields input, #addFields select { font:13px inherit; border:1px solid #d8d5e6; border-radius:6px; padding:6px 8px; min-width:160px; }
  #addFields { display:flex; gap:16px; flex-wrap:wrap; margin-bottom:8px; }
  #addFields label { display:flex; flex-direction:column; gap:3px; font-size:12px; color:#6b6b80; }
  #addDesc { font-size:12px; margin:2px 0 10px; }
  .hold { border:1px solid #f2c46a; background:#fff8ea; border-radius:8px; padding:10px 12px; margin-bottom:8px; }
  .hold pre { font-size:11px; background:#f5f4f8; padding:8px; border-radius:6px; overflow:auto; }
  .dim { color:#6b6b80; } pre { margin:6px 0; }
  .logrow { padding:5px 0; border-top:1px solid #eeecf3; font-size:12px; } .logrow:first-child { border-top:none; }
  .logrow .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; }
  .logrow.allow .dot, .logrow.observe .dot { background:#0f7a43; } .logrow.block .dot { background:#c02532; } .logrow.escalate .dot { background:#c98a1c; }
  .err { color:#c02532; }
</style></head><body>
<header><h1>MetaMynd governance harness</h1><div class="did">\${esc(agentDid)} · scope \${esc(scope)}</div></header>
<main>
<section><h2>Rules in force</h2>\${renderRulesHtml(rules)}</section>
<section><h2>Pending approvals</h2><div id="holds">\${renderHoldsHtml()}</div></section>
<section><h2>Recent decisions</h2><div id="log">\${renderLogHtml()}</div></section>
</main>
<script>
async function refresh() {
  const r = await fetch('/state').then((x) => x.json());
  document.getElementById('holds').innerHTML = r.holdsHtml;
  document.getElementById('log').innerHTML = r.logHtml;
}

// --- Add-a-rule form: predicates + field types come from the SAME catalog the gate itself
// validates against (served at /catalog), so this form can never offer something invalid. ---
let CATALOG = [];
function fieldInputHtml(f) {
  const id = 'af_' + f.key;
  if (f.type === 'enum') {
    return '<label>' + f.description + '<select id="' + id + '" data-key="' + f.key + '" data-type="' + f.type + '">' +
      (f.options || []).map((o) => '<option value="' + o + '">' + o + '</option>').join('') + '</select></label>';
  }
  return '<label>' + f.description + (f.type === 'string[]' ? ' (comma-separated)' : '') +
    '<input id="' + id + '" data-key="' + f.key + '" data-type="' + f.type + '" ' + (f.type === 'number' ? 'type="number"' : '') + ' /></label>';
}
function renderAddFields() {
  const spec = CATALOG.find((s) => s.predicate === document.getElementById('addPredicate').value);
  document.getElementById('addDesc').textContent = spec ? spec.description : '';
  document.getElementById('addFields').innerHTML = spec ? spec.config.map(fieldInputHtml).join('') : '';
}
fetch('/catalog').then((r) => r.json()).then((specs) => {
  CATALOG = specs;
  document.getElementById('addPredicate').innerHTML = specs.map((s) => '<option value="' + s.predicate + '">' + s.label + '</option>').join('');
  renderAddFields();
});
document.getElementById('addPredicate').addEventListener('change', renderAddFields);

document.addEventListener('click', async (e) => {
  if (e.target.matches('.approve,.deny')) {
    const id = e.target.dataset.id, verb = e.target.classList.contains('approve') ? 'approve' : 'deny';
    await fetch('/holds/' + id + '/' + verb, { method: 'POST' });
    refresh();
  }
  if (e.target.id === 'save') {
    const mandateInputs = [...document.querySelectorAll('input[data-kind="mandate"]')];
    const atomInputs = [...document.querySelectorAll('input[data-kind="atom"]')];
    const edits = {
      mandate: mandateInputs.map((i) => ({ idx: Number(i.dataset.idx), value: i.value })),
      atoms: atomInputs.map((i) => ({ mid: i.dataset.mid, aid: i.dataset.aid, key: i.dataset.key, value: i.value })),
    };
    const res = await fetch('/rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edits) });
    document.getElementById('saveMsg').textContent = res.ok ? 'saved — takes effect on the next decision' : 'save failed';
  }
  if (e.target.matches('.delmol')) {
    if (!confirm('Remove this rule?')) return;
    const res = await fetch('/rules/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: e.target.dataset.id }) });
    if (res.ok) location.reload(); else document.getElementById('saveMsg').textContent = 'delete failed';
  }
  if (e.target.id === 'addRuleBtn') {
    const predicate = document.getElementById('addPredicate').value;
    const config = {};
    for (const el of document.querySelectorAll('#addFields [data-key]')) config[el.dataset.key] = el.value;
    const body = {
      predicate, config,
      decision: document.getElementById('addDecision').value,
      name: document.getElementById('addName').value || undefined,
      reasonCode: document.getElementById('addReasonCode').value || undefined,
    };
    const res = await fetch('/rules/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const r = await res.json();
    if (res.ok) location.reload();
    else document.getElementById('addMsg').textContent = r.error || 'could not add rule';
  }
});
setInterval(refresh, 3000);
</script></body></html>\`;
  }

  // A number-looking string edit becomes a number (spend caps etc.); a comma-list becomes an
  // array (merchants/allow-lists); anything else stays a string.
  function coerce(raw) {
    if (raw.includes(',')) return raw.split(',').map((s) => s.trim()).filter(Boolean);
    if (raw.trim() !== '' && !Number.isNaN(Number(raw))) return Number(raw);
    return raw;
  }

  function applyEdits(rules, edits) {
    const m = (rules.mandate?.permission || [])[0];
    for (const e of edits.mandate || []) {
      if (m?.constraint?.[e.idx]) m.constraint[e.idx].rightOperand = coerce(e.value);
    }
    for (const e of edits.atoms || []) {
      for (const s of rules.sops || []) {
        const mol = (s.document?.molecules || []).find((x) => x.id === e.mid);
        const atom = mol?.atoms?.find((a) => a.id === e.aid);
        if (atom) atom.config[e.key] = coerce(e.value);
      }
    }
    return rules;
  }

  /** Builds one molecule from the add-rule form, validates it with the SAME validator the
   *  hosted platform runs, and appends it to the first SOP document (there is exactly one in
   *  a harness project). Single-atom, combinator "all" — the same "sugar" shape --config's
   *  "rules" array compiles to, so a harness rules file and a --config file stay interchangeable. */
  function addRule({ predicate, config, decision, name, reasonCode }) {
    const spec = ATOM_SPECS.find((s) => s.predicate === predicate);
    if (!spec) return { ok: false, error: \`unknown predicate "\${predicate}"\` };
    const cfg = {};
    for (const f of spec.config) {
      const raw = config?.[f.key];
      if (raw === undefined || raw === '') { if (f.required) return { ok: false, error: \`"\${f.description}" is required\` }; continue; }
      cfg[f.key] = coerceField(raw, f.type);
    }
    const molecule = {
      id: \`\${predicate}-\${Date.now().toString(36)}\`,
      name: name || spec.label,
      combinator: 'all',
      atoms: [{ id: 'a1', predicate, config: cfg }],
      decision,
      reasonCode: reasonCode || \`\${predicate.toUpperCase().replace(/-/g, '_')}_\${String(decision).toUpperCase()}\`,
    };
    const check = validateMolecules([molecule]);
    if (!check.ok) return { ok: false, error: check.issues.map((i) => i.message).join('; ') };
    const rules = readRules();
    if (rules.error) return { ok: false, error: rules.error };
    if (!rules.sops?.[0]) rules.sops = [{ standardKey: 'sop', document: { molecules: [] } }];
    rules.sops[0].document.molecules = [...(rules.sops[0].document.molecules || []), molecule];
    writeRules(rules);
    log({ type: 'rule-added', id: molecule.id, predicate, decision });
    return { ok: true, molecule };
  }

  function deleteRule(id) {
    const rules = readRules();
    if (rules.error) return { ok: false, error: rules.error };
    for (const s of rules.sops || []) {
      if (!s.document?.molecules) continue;
      s.document.molecules = s.document.molecules.filter((mo) => mo.id !== id);
    }
    writeRules(rules);
    log({ type: 'rule-deleted', id });
    return { ok: true };
  }

  const server = http.createServer(async (req, res) => {
    const path = req.url.split('?')[0];
    const send = (status, body, type = 'application/json') => { res.writeHead(status, { 'Content-Type': type }); res.end(type === 'application/json' ? JSON.stringify(body) : body); };
    if (req.method === 'GET' && path === '/') return send(200, page(), 'text/html; charset=utf-8');
    if (req.method === 'GET' && path === '/state') return send(200, { holdsHtml: renderHoldsHtml(), logHtml: renderLogHtml() });
    if (req.method === 'GET' && path === '/catalog') return send(200, ATOM_SPECS);
    if (req.method === 'POST' && path === '/rules') {
      let body = ''; req.on('data', (c) => (body += c));
      req.on('end', () => {
        try { writeRules(applyEdits(readRules(), JSON.parse(body || '{}'))); return send(200, { ok: true }); }
        catch (e) { return send(500, { ok: false, error: String(e?.message ?? e) }); }
      });
      return;
    }
    if (req.method === 'POST' && path === '/rules/add') {
      let body = ''; req.on('data', (c) => (body += c));
      req.on('end', () => {
        try {
          const r = addRule(JSON.parse(body || '{}'));
          return send(r.ok ? 200 : 400, r);
        } catch (e) { return send(500, { ok: false, error: String(e?.message ?? e) }); }
      });
      return;
    }
    if (req.method === 'POST' && path === '/rules/delete') {
      let body = ''; req.on('data', (c) => (body += c));
      req.on('end', () => {
        try {
          const { id } = JSON.parse(body || '{}');
          return send(200, deleteRule(id));
        } catch (e) { return send(500, { ok: false, error: String(e?.message ?? e) }); }
      });
      return;
    }
    const m = /^\\/holds\\/([^/]+)\\/(approve|deny)$/.exec(path);
    if (req.method === 'POST' && m) {
      const h = holds.get(m[1]);
      if (h && h.status === 'pending') {
        h.status = m[2] === 'approve' ? 'approved' : 'denied';
        log({ type: h.status, id: h.id, action: h.action });
        h.resolve(h.status === 'approved');
      }
      return send(200, { ok: true });
    }
    send(404, { error: 'not found' });
  });
  server.listen(port, host);
  return { holdForApproval, logDecision, url: \`http://\${host}:\${port}\`, close: () => server.close() };
}
`;
}

function harnessIndexFile(scope, perTxnMax, port) {
  const under = Math.max(1, Math.round(perTxnMax * 0.5));
  const over = Math.round(perTxnMax + 100);
  return `// index.mjs — your agent, governed entirely on this machine. No account, no network call
// for a decision: guardToolLocal() decides allow/block/escalate against ./metamynd-rules.json
// (edit it directly, or at the dashboard). An escalate is held here for YOU to approve —
// there is no hosted owner queue in this mode, so open the dashboard URL printed below.
import { readFileSync } from 'node:fs';
import { createGuard } from '${GUARD_PKG}';
import { startDashboard } from './harness-server.mjs';

const config = JSON.parse(readFileSync('./agent.metamynd.json', 'utf8'));
// 'local' as the api: guardToolLocal() never calls it. Kept required-but-unused rather than
// silently accepting no api at all, so a later switch to a real gate is one field, not a rewrite.
const guard = createGuard({ api: 'local', agentDid: config.agentDid, agentKey: config.agentKey });

const dashboard = startDashboard({
  port: ${port},
  agentDid: config.agentDid,
  scope: '${scope}',
  rulesPath: './metamynd-rules.json',
  logPath: './metamynd-harness.log.jsonl',
});
console.log('\\x1b[2m  dashboard: ' + dashboard.url + ' (rules, approvals, decision log)\\x1b[0m\\n');

// Reads the CURRENT rules file fresh every call — editing it (by hand, or at the dashboard)
// takes effect on the next decision, no restart, matching the "no redeploy" experience the
// hosted platform gives you.
const getBundle = () => JSON.parse(readFileSync('./metamynd-rules.json', 'utf8'));

// --- Your real tool. Replace the body with your actual implementation. ---
async function bookFlight(args) {
  return { pnr: 'PNR-DEMO', ...args };
}

// --- The GATED version. Register THIS with your agent instead of the raw handler. ---
const gatedBookFlight = guard.guardToolLocal(
  '${scope}',                                   // = your mandate scope
  bookFlight,
  (a) => ({                                     // map tool args → gate inputs
    amount: a.amount,
    merchant: a.merchant,
    context: { tool: 'book-flight', riskLevel: a.riskLevel ?? 'low' },
  }),
  getBundle,
);

// --- A tool the agent was NEVER granted. Wrapping it is the demonstration: there is no
// --- rule anywhere forbidding this. The mandate simply never mentioned the action.
async function raiseOwnLimit(args) {
  return { updated: true, ...args };          // never runs, and that is the point
}

const gatedRaiseOwnLimit = guard.guardToolLocal(
  'permissions.update',                       // an action NOT in the mandate
  raiseOwnLimit,
  (a) => ({ amount: a.amount, merchant: a.merchant, context: { tool: 'permissions-update' } }),
  getBundle,
);

const dim = (t) => '\\x1b[2m' + t + '\\x1b[0m';
const bold = (t) => '\\x1b[1m' + t + '\\x1b[0m';
const rule = (n) => '  ' + '-'.repeat(n);

const WHY = {
  AUTHORIZED: 'inside the mandate and under the SOP spend cap',
  SOP_SPEND_CAP: 'your SOP caps a single transaction at $${perTxnMax}',
  RISK_REVIEW: 'your SOP sends high-risk actions to a human first',
  MERCHANT_NOT_ALLOWED: 'the mandate lists which merchants this agent may pay',
  NO_PERMISSION_FOR_ACTION: 'the mandate never granted this action - at any amount',
  NO_MANDATE: 'there is no mandate for this action at all',
};

async function attempt(n, intent, action, args, tool = gatedBookFlight) {
  console.log('');
  console.log(bold('  Step ' + n + ' of 4') + ' - ' + intent);
  console.log(dim('     evaluating locally, no network call...'));
  try {
    const r = await tool(args);
    console.log('\\x1b[32m     ALLOWED\\x1b[0m  your tool ran and returned ' + (r.pnr ?? 'ok'));
    console.log(dim('     ' + WHY.AUTHORIZED));
  } catch (e) {
    const g = e.governance ?? {};
    const why = WHY[g.reasonCode] ?? e.message;
    if (g.decision === 'escalate') {
      console.log('\\x1b[33m     ESCALATED\\x1b[0m  held for you to approve - ' + g.reasonCode);
      console.log(dim('     ' + why));
      const { id, promise } = dashboard.holdForApproval(action, args, g);
      console.log(dim('     open ' + dashboard.url + ' and click Approve/Deny (hold ' + id.slice(0, 8) + '…)'));
      const timeout = new Promise((r) => setTimeout(() => r('timeout'), 20000));
      const result = await Promise.race([promise, timeout]);
      if (result === 'timeout') console.log(dim('     still pending after 20s — this demo will not wait forever; the dashboard will, run it again to check.'));
      else console.log(dim('     ' + (result ? 'approved.' : 'denied.')));
    } else {
      console.log('\\x1b[31m     BLOCKED\\x1b[0m  ' + (g.reasonCode ?? 'refused'));
      console.log(dim('     ' + why));
      console.log(dim('     your tool never ran - the gate refused before execution.'));
    }
    dashboard.logDecision(action, args, g);
  }
}

console.log('');
console.log(bold('  What this simulation shows'));
console.log('');
console.log('  Same idea as the hosted platform, running entirely on this machine: an agent');
console.log('  should not be the thing that decides what it is allowed to do. Three attempts');
console.log('  take the SAME code path and produce three different outcomes. The fourth asks');
console.log('  for something never granted at all - the one a prompt could not have stopped,');
console.log('  because the decision is not made inside your program, and not on a server either.');
console.log('');
console.log(dim('  scope  ${scope}'));
console.log(dim('  cap    $${perTxnMax} per transaction, from ./metamynd-rules.json'));

console.log('');
console.log(rule(66));
await attempt(1, 'a $${under} booking, low risk. Expected to pass.', '${scope}', { amount: ${under}, merchant: 'skyward-air', riskLevel: 'low' });
await attempt(2, 'a $${over} booking, deliberately over the cap.', '${scope}', { amount: ${over}, merchant: 'skyward-air', riskLevel: 'low' });
await attempt(3, 'a $${under} booking, but flagged high risk.', '${scope}', { amount: ${under}, merchant: 'skyward-air', riskLevel: 'high' });
await attempt(4, 'the agent stops booking flights and asks to raise its OWN limit.', 'permissions.update', { amount: 100000, merchant: 'skyward-air' }, gatedRaiseOwnLimit);
console.log('');
console.log(rule(66));

console.log('');
console.log(bold('  What this proved'));
console.log('');
console.log(dim('   - one code path, three outcomes, decided with zero network calls.'));
console.log(dim('   - step 4 needed no rule to stop it. The agent could not widen its own'));
console.log(dim('     authority, because it cannot name an action nobody delegated to it.'));
console.log(dim('   - the blocked call never reached your tool at all.'));
console.log(dim('   - every decision is in ./metamynd-harness.log.jsonl - yours, locally.'));
console.log('');
console.log('  Edit ./metamynd-rules.json (or the dashboard) and run again - the outcome');
console.log(dim('  changes. This file does not. That is the point.'));
console.log('');
console.log(dim('  Ready for more than one machine, a queue someone else can approve from,'));
console.log(dim('  anchored evidence, or KYC/KYB-backed identity? That is the hosted platform -'));
console.log(dim('  same guardTool() call, same rules shape, drop --harness and provision there.'));
console.log('');
dashboard.close();
`;
}

function harnessPackageJson(slug) {
  return JSON.stringify(
    {
      name: slug,
      version: '0.1.0',
      private: true,
      type: 'module',
      scripts: { start: 'node index.mjs' },
      dependencies: { [GUARD_PKG]: GUARD_VERSION },
    },
    null,
    2,
  ) + '\n';
}

function harnessReadme(slug, scope, port) {
  return `# ${slug}

A free, local MetaMynd/AgentSafe governance harness — your own rules, your own identity,
decided entirely on this machine. No account, no network call for a decision.

## Run

\`\`\`bash
npm install
npm start
\`\`\`

You should see an ALLOW, a BLOCK (over the per-transaction cap), an ESCALATE (high risk —
open the dashboard to approve it), and a BLOCK (an action outside the mandate entirely).

## Files

- \`agent.metamynd.json\` — your local identity (a generated Ed25519 keypair; \`agentDid\` is a
  local label, not an anchored/verifiable one). **Contains a secret key — never commit it.**
- \`metamynd-rules.json\` — your rules: the mandate (scope + spend limits) and SOP (extra checks).
  Edit it directly, or at the dashboard. Reloaded on every decision — no restart.
- \`metamynd-harness.log.jsonl\` — every decision this agent made, append-only.
- \`harness-server.mjs\` — the local dashboard (port ${port}): rules, pending approvals, decision log.
- \`index.mjs\` — wraps a tool with \`guard.guardToolLocal(...)\`; the tool only runs when the
  LOCAL rules permit it.

## What this is not

No anchored/verifiable identity, no cross-party trust, no evidence anyone but you can audit,
no dashboard reachable when this machine is off, no owner queue someone else can approve from.
That's the hosted platform (\`npx create-metamynd-agent\`, without \`--harness\`) — same
\`guardTool()\` call, same rules shape, so upgrading later is a config change, not a rewrite.
`;
}

/** --harness: no login, no KYB, no network — author identity + rules locally and scaffold. */
async function runHarness(args) {
  const interactive = !args.yes && process.stdin.isTTY;
  const rl = interactive ? makeRl() : null;
  const pick = async (flag, prompt, def) => {
    const fromFlag = typeof args[flag] === 'string' ? args[flag] : undefined;
    if (fromFlag !== undefined) return fromFlag;
    if (!interactive) return def;
    return ask(rl, prompt, def);
  };

  const fileConfig = typeof args.config === 'string' ? loadConfigFile(args.config) : null;
  if (fileConfig) console.log(`  ${c.green('✓')} loaded policy config ${c.dim(args.config)}`);

  const name = await pick('name', 'Agent name', fileConfig?.name ?? 'Local Agent');
  const scope = await pick('scope', 'Mandate scope (governed action)', fileConfig?.scope ?? 'flight-purchase');
  const perTxnMax = Number(await pick('per-txn-max', 'Per-transaction cap', String(fileConfig?.perTxnMax ?? '500'))) || 500;
  const maxAmount = Number(await pick('max-amount', 'Total mandate budget', String(fileConfig?.maxAmount ?? '10000'))) || 10000;
  const currency = (await pick('currency', 'Currency', fileConfig?.currency ?? 'USD')) || 'USD';
  const merchantsRaw = await pick('merchants', 'Allowed merchants (comma-sep, blank = any)', Array.isArray(fileConfig?.merchants) ? fileConfig.merchants.join(',') : '');
  const merchants = String(merchantsRaw).split(',').map((s) => s.trim()).filter(Boolean);
  const port = Number(args.port) || 4400;
  const slug = slugify(name);
  const outDir = resolve(String(args.out || (interactive ? await ask(rl, 'Output directory', `./${slug}`) : `./${slug}`)));
  rl?.close();

  assertScaffoldTarget(outDir, !!args.force);
  console.log(c.dim('\n  → generating a local identity (Ed25519, this machine only) …'));
  const { publicKeyHex, privateKeyHex } = generateAgentKeypair();
  const agentDid = harnessAgentDid(publicKeyHex);
  console.log(`  ${c.green('✓')} local agent ${c.b(agentDid)}`);

  const sopFields = configFileSopFields(fileConfig);
  const sopDocument = sopFields.sop ? sopFields.sop.documentJson : harnessDefaultSop(perTxnMax);
  if (sopFields.sop) console.log(`  ${c.green('✓')} compiled ${sopDocument.molecules.length} rule(s) from the config file`);
  const mandate = harnessMandate({ scope, currency, maxAmount, perTxnMax, merchants });

  console.log(`\n  ${c.b('Scaffolding')} ${c.dim(outDir)}`);
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  writeFileSafe(outDir, 'agent.metamynd.json', JSON.stringify({ agentDid, agentKey: privateKeyHex, mode: 'harness' }, null, 2) + '\n', !!args.force);
  writeFileSafe(outDir, 'metamynd-rules.json', harnessRulesFile(mandate, sopDocument), !!args.force);
  writeFileSafe(outDir, 'harness-server.mjs', harnessServerFile(), !!args.force);
  writeFileSafe(outDir, 'index.mjs', harnessIndexFile(scope, perTxnMax, port), !!args.force);
  writeFileSafe(outDir, 'package.json', harnessPackageJson(slug), !!args.force);
  writeFileSafe(outDir, '.gitignore', gitignore(), !!args.force);
  writeFileSafe(outDir, 'README.md', harnessReadme(slug, scope, port), !!args.force);

  const rel = outDir.replace(resolve('.'), '.').replace(/\\/g, '/');
  console.log(`\n${c.green(c.b('  ✓ Done.'))} Your local governance harness is ready.\n`);
  console.log(`  ${c.dim('Free, local, no account. Not the hosted platform — see README#what-this-is-not.')}\n`);
  console.log(`  Next:`);
  console.log(c.cyan(`    cd ${rel}`));
  console.log(c.cyan(`    npm install`));
  console.log(c.cyan(`    npm start`) + c.dim('   → ALLOW · BLOCK (over cap) · ESCALATE (approve at the dashboard) · BLOCK (ungranted action)\n'));
  console.log(c.dim(`  Edit ./metamynd-rules.json any time (by hand, or at http://127.0.0.1:${port}) — no redeploy.\n`));
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

  // --harness: skip login + provisioning + the network entirely.
  if (args.harness) { await runHarness(args); return; }
  // --sandbox: skip login + provisioning entirely.
  if (args.sandbox) { await runSandbox(args); return; }
  // Delegated issuance (#6): request an agent for an owner's org / claim it once approved.
  if (args.request) { await runRequest(args); return; }
  if (args.claim) { await runClaim(args); return; }

  // --config: a JSON policy file. Its fields become the DEFAULT for each prompt/flag below —
  // an explicit CLI flag still wins (e.g. `--config base.json --name "Other Bot"`), and
  // env vars still win over the file for login credentials specifically (never put a
  // password in a policy file that gets checked into source control).
  const fileConfig = typeof args.config === 'string' ? loadConfigFile(args.config) : null;
  if (fileConfig) console.log(`  ${c.green('✓')} loaded policy config ${c.dim(args.config)}`);

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

  // 2. Agent details — a --config file's fields are the default at every prompt/flag below.
  const name = await pick('name', null, 'Agent name', fileConfig?.name ?? 'Support Bot');
  const scope = await pick('scope', null, 'Mandate scope (governed action)', fileConfig?.scope ?? 'flight-purchase');
  const perTxnMax = Number(await pick('per-txn-max', null, 'Per-transaction cap', String(fileConfig?.perTxnMax ?? '500'))) || 500;
  const maxAmount = Number(await pick('max-amount', null, 'Total mandate budget', String(fileConfig?.maxAmount ?? '10000'))) || 10000;
  const currency = (await pick('currency', null, 'Currency', fileConfig?.currency ?? 'USD')) || 'USD';
  const merchantsRaw = await pick(
    'merchants', null, 'Allowed merchants (comma-sep, blank = any)',
    Array.isArray(fileConfig?.merchants) ? fileConfig.merchants.join(',') : '',
  );
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

  // 3. Provision (one call) — a --config file's `rules`/`molecules`/`rulePack` become the
  // starter SOP; with none of those, provisionGuardConfig falls back to its own default
  // (a per-transaction cap + high-risk review), same as before --config existed.
  const sopFields = configFileSopFields(fileConfig);
  if (sopFields.sop) console.log(`  ${c.green('✓')} compiled ${sopFields.sop.documentJson.molecules.length} rule(s) from the config file`);
  console.log(c.dim(`\n  → provisioning "${name}" (identity + mandate + SOP + Standards) …`));
  const body = { name, scope, currency, maxAmount, perTxnMax, merchants, ...(publicKey ? { publicKey } : {}), ...sopFields };
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

#!/usr/bin/env node
// create-metamynd-agent — scaffold a MetaMynd/AgentSafe-governed agent in one command.
//
// Logs a KYB-verified owner in, provisions the agent in ONE call
// (POST /onboarding/agent → identity + mandate + starter SOP + enforced Standards),
// writes the portable `agent.metamynd.json` and a runnable agent example, PLUS (by default)
// a separate `gateway/` process — a second, independent guard that re-verifies every request
// and holds the real tool, so the agent's own guardTool() call is a convenience, not the
// enforcement boundary. `--no-gateway` skips it (see README#separate-tool-gateway-default).
//
// ZERO dependencies: Node ≥ 18 built-ins only (fetch, readline).
//
//   npm create metamynd-agent@latest
//   npx create-metamynd-agent
//   npx create-metamynd-agent --api http://localhost:9926/api/v1 --email you@x.com \
//       --name "Support Bot" --scope flight-purchase --per-txn-max 500 --out ./support-bot --yes
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, chmodSync } from 'node:fs';
import { join, resolve } from 'node:path';
import readline from 'node:readline';
import crypto from 'node:crypto';
import net from 'node:net';

const GUARD_PKG = '@metamynd/agentsafe-guard';
// Must track the guard's MINOR line, not just its major. On a 0.x package `^0.4.0` means
// >=0.4.0 <0.5.0, so leaving this at ^0.4.0 would scaffold an agent whose `npm test` runs
// `agentsafe-guard verify` against a guard that has no such command.
// 0.6.0 adds the amount-unknown atom (deny-by-default when a value-moving action's amount
// can't be determined) — this was already missed once (this constant sat at ^0.5.0 through the
// whole 0.6.0 release), silently scaffolding every new project without that protection.
// 0.7.0 adds the opt-in `signContext` envelope signature (Tier 1 context-claim binding) —
// no scaffolded behavior changes (off by default), but the floor must still cover the real
// current version regardless, per this repo's standing internal-pin invariant.
// 0.8.0 adds an optional `currency` scope to the amount-over/cumulative-over atoms
// (harnessDefaultSop, below, now sets it) — a guard below this version can't evaluate that
// field, so a scaffolded currency-scoped cap would silently never fire on a currency mismatch.
// 0.9.0 makes buildSignedRequest() async (the keyProvider seam, docs/design/
// agent-key-custody-local-signer-daemon-plan.md) — this scaffold's own bookFlightViaGateway/
// callGateway templates now `await` it, so a guard below this version would hand back a
// Promise object where a signed request is expected instead of failing loudly.
// 0.10.0 adds `resource` as a genuinely signed field (mirrors the mandate's own
// ResourceService.scopeConstraint()) — no scaffolded template passes it yet, but the floor
// must still cover the real current version regardless, per this repo's standing
// internal-pin invariant.
// 0.11.0 adds `signLocalDecision` support to `createDaemonKeyProvider` — this scaffold's
// `--byok --daemon-socket` path can now get local-decision audit reporting too, but no
// template code changes yet; the floor must still cover the real current version.
// 0.12.0 adds passphrase-encrypted managed key delivery (createGuardFromConfig's
// `{ passphrase }`) — no scaffolded template passes one yet, but the floor must still cover
// the real current version regardless, per this repo's standing internal-pin invariant.
// 0.12.2 makes a missing/garbled agent.metamynd.json fail with the next step instead of a bare
// ENOENT (BR-004) — every scaffolded project relies on that for the fresh-clone journey.
// 0.12.3 adds `verify --context`, which a non-financial scaffold's `npm test` needs (a policy that
// requires request inputs blocks a bare baseline request).
// 0.12.4 makes `verify` probe in the currency the mandate's caps name (it assumed USD), which a scaffolded
// non-USD agent's `npm test` needs.
const GUARD_VERSION = '^0.15.0';
/** The harness entry point's config load, shared by both harness templates: a fresh clone has no
 *  agent.metamynd.json (it is gitignored), so say what to do instead of a bare ENOENT (BR-004). */
function harnessConfigLoad() {
  return `// agent.metamynd.json holds this agent's LOCAL key and is gitignored, so a fresh clone lacks it.
// Say so, with the way forward, instead of letting readFileSync throw a bare ENOENT.
let config;
try {
  config = JSON.parse(readFileSync('./agent.metamynd.json', 'utf8'));
} catch (e) {
  console.error(e && e.code === 'ENOENT'
    ? ['No ./agent.metamynd.json. It holds the local key for this agent and is gitignored, so a fresh clone never has it.',
       'Create one (no account needed): run  npx create-metamynd-agent --harness  in a NEW folder, then copy its agent.metamynd.json here.'].join(String.fromCharCode(10))
    : 'Could not read ./agent.metamynd.json: ' + (e && e.message));
  process.exit(1);
}`;
}
// Emitted at the top of every generated entry point. A committed package-lock.json can pin a guard
// far older than the one this scaffold was written for (a beta tester's clean clone resolved 0.6.6
// against a current 0.12.x — BR-005), and `npm install` will honour it silently. Warn, don't fail:
// an older guard may still run, but the user should know why behaviour differs from the README.
function guardFreshnessCheck() {
  const floor = GUARD_VERSION.replace(/^\^/, '').split('.').map(Number);
  return `import { readFileSync as __readPkg } from 'node:fs';
{
  // Fresh-clone check — see README.md ("Cloned this project fresh?").
  const floor = [${floor.join(', ')}];
  try {
    const have = JSON.parse(__readPkg(new URL('./node_modules/${GUARD_PKG}/package.json', import.meta.url), 'utf8')).version.split('.').map(Number);
    const older = have[0] !== floor[0] ? have[0] < floor[0] : have[1] !== floor[1] ? have[1] < floor[1] : have[2] < floor[2];
    if (older) console.warn('! installed ${GUARD_PKG} ' + have.join('.') + ' is older than this project expects (>= ${floor.join('.')}); a committed package-lock.json is pinning it. Update: npm install ${GUARD_PKG}@latest');
  } catch { /* not a flat node_modules install — nothing to check */ }
}
`;
}
// The default hosted scaffold's SECOND process — the tool gateway (see scaffoldProject).
const MCP_GUARD_PKG = '@metamynd/agentsafe-mcp-guard';
// 0.2.0 adds requireAuthorization (closes replay + cumulative spend) — this scaffold sets that
// option, so a range that could resolve below 0.2.0 would silently scaffold a no-op.
// 0.3.0 adds the same amount-unknown atom as the guard, above — same reasoning, same miss.
// 0.4.0 adds the same amount-over/cumulative-over `currency` scope as the guard, above —
// same reasoning, same miss.
// 0.5.0 adds the keyProvider seam alongside the guard's own 0.9.0 (same design doc) — this
// scaffold's createMcpGuard() calls never use a handshake here, so no template code changes,
// but the floor must still cover the real current version regardless, per this repo's
// standing internal-pin invariant.
// 0.6.0 brings buildAuthMessage's `resource` field and buildLocalDecisionMessage into this
// package's own bundled policy-core.mjs (alongside the guard's own 0.10.0) — no scaffolded
// template code changes, but the floor must still cover the real current version.
// 0.13.0: a daemon-held service key (keyProvider: 'daemon') now signs claims and settlements as the gateway's
// DID instead of claiming anonymously — refused on every mainnet hold before. No template change.
// 0.14.0: the claim can declare an x402 payment (x402: true) so the issuer observes lowered settlements. No template
// change (the scaffolded gateways don't pay by x402), but the floor must cover the real current version.
const MCP_GUARD_VERSION = '^0.14.0';
const GATEWAY_PKG = '@metamynd/agentsafe-http-gateway';
// 0.2.0 fixes a confused-deputy gap (payload not bound to the signed request) — the CLI must
// never scaffold a range that could resolve below it.
// 0.3.0 was a first, INCOMPLETE attempt at the follow-on gap (checked only "did the body offer
// NONE of the three fields" — a correct decoy in one field let the other hide anywhere). 0.4.0
// is the actual fix: requires amount/merchant specifically, whenever the signature names a real
// value for them. Re-tested live and closed same day; ^0.3.0 here would still resolve to the
// broken version.
// 0.5.0 adds the OPTIONAL Credential Vault `resolveCredential` hook on createHttpGateway (Module
// G) — additive and backward-compatible (every existing consumer sees zero behavior change), but
// the floor must still cover the real current version per this repo's own package-version check.
// 0.12.0: per-route `x402: true` declares an x402 payment on the claim. No template change.
const GATEWAY_VERSION = '^0.12.0';
const DEFAULT_API = 'https://metamynd.ai/api/v1';
const DEFAULT_GATEWAY_PORT = 4401; // distinct from --harness's dashboard (4400)

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
  --non-financial      The agent does not move money: no spend limits, no payment demo, and the
                       demo is derived from your own rules. Works in every mode: --harness, the hosted
                       flow, --sandbox (a shared agent with no spend authority), and --request / --claim
                       (the owner is asked to approve NO spending authority). On --sandbox and --request
                       the platform's default rules apply (a --config file's rules cannot reach an agent
                       you do not provision yourself). Implied
                       when a --config file sets no spend limit and contains no monetary rule;
                       --financial (or "financial": true in the file) opts back in.
  --harness            No login, no KYB, no network at all: a free local governance harness —
                       your own rules, your own identity, decided entirely on this machine. See
                       README#harness. Not for enterprise use (no anchored identity/evidence,
                       no cross-party trust) — that is what the hosted platform adds. Add
                       --gateway for a second local process that closes the cooperative-only
                       gap too, still free and offline (see --gateway below).
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
  --daemon-socket <p>  --byok only: use an already-running agentsafe-signer daemon (started
                       separately, e.g. \`agentsafe-signer start --admin\`) to generate the key and
                       prove control instead — the private key never enters this CLI's process at
                       all, and agent.metamynd.json gets keyProvider:'daemon' instead of a
                       plaintext key. Requires --daemon-admin-socket too. See README#byok.
  --daemon-admin-socket <p>  The same daemon's admin socket (for generate-key) — required with
                       --daemon-socket.
  --out <dir>          Output project directory (default ./<agent-slug>)
  --no-gateway         Hosted flow only: skip the separate tool-gateway process (see
                       README#separate-tool-gateway-default) and scaffold the old
                       single-process example instead. Not a separate enforcement boundary.
  --gateway            --harness only: ALSO scaffold a second local process (still zero
                       network, zero account) that independently re-verifies every request
                       against the same rules file, using the real @metamynd/agentsafe-mcp-guard.
                       Off by default. Refuses a replayed request; does not track cumulative spend — see the
                       generated README#--gateway for exactly what it does and does not.
  --gateway-port <n>   The gateway process's port, hosted flow or --harness --gateway (default 4401)
  --port <n>           --harness only: the local dashboard's port (default 4400)
  --yes, -y            Non-interactive: use flags/env/defaults, never prompt
  -h, --help           Show this help
  -v, --version        Show version

${c.b('Environment')}
  METAMYND_API, METAMYND_EMAIL, METAMYND_PASSWORD  — fallbacks for the flags above

${c.b('Network')}
  Every hosted agent this CLI provisions is a ${c.b('Testnet')} agent, whatever your verification status —
  there is deliberately no mainnet flag. To launch a ${c.b('Mainnet')} agent, use the Launchpad in the
  dashboard (https://metamynd.ai/dashboard/launchpad): its Mainnet option is available once your
  owner verification (KYC/KYB) is complete.

${c.b('What it does')}
  1. Logs in as a KYB-verified owner       → owner access token
  2. POST /onboarding/agent (one call)      → identity + mandate + SOP + Standards
  3. Writes agent.metamynd.json + index.mjs, PLUS (by default) a separate gateway/ process —
     the real enforcement boundary, not index.mjs's own guard.guardTool() call. --no-gateway
     skips it.
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

// ---------- policy-derived demo (BR-006) ----------
//
// The scaffold's demo used to be a flight booking with a spend cap NO MATTER what policy the caller
// supplied, and it injected a per-transaction cap, total budget and currency the policy never
// mentioned (beta regression 2026-09-20: a customer-communications policy produced a flight demo
// with payment limits and no case for its own privacy/content rules). For a NON-financial agent the
// demo is now derived from the supplied rules themselves: one request that should pass, and one
// per rule that should trip it. Each rule is driven through the field its atom actually reads
// (policy-core/atom-registry.ts), and create-metamynd-agent's smoke test proves every generated
// case against the REAL evaluator instead of trusting this table.

const MONETARY_ATOMS = new Set(['amount-over', 'amount-unknown', 'cumulative-over']);

/** The mandate scope is written verbatim into generated JavaScript and shell text; a quote, backslash,
 *  backtick, `$` or line break would break (or inject into) every template. Refuse it up front. */
function assertSafeScope(scope) {
  if (/['"`\\$\r\n]/.test(String(scope))) {
    fail('The mandate scope must not contain quotes, backslashes, backticks, "$" or line breaks: it is written into generated code. Use something like "send-customer-notice".');
  }
}

/** The molecules a caller supplied (never the defaults) — from `molecules`, or `rules` compiled. */
function policyMolecules(config) {
  if (!config) return [];
  if (Array.isArray(config.molecules)) return config.molecules;
  if (Array.isArray(config.rules)) return config.rules.map(ruleToMolecule);
  return [];
}

const KNOWN_CONFIG_KEYS = new Set(['name', 'scope', 'rules', 'molecules', 'rulePack', 'perTxnMax', 'maxAmount', 'currency', 'merchants', 'financial']);
const MONEY_LIKE_KEY = /amount|budget|\bcap\b|limit|currency|spend|price|cost|txn|transaction|payment|payee|invoice|fee/i;

/** Top-level config keys that read like a spend limit but are not ones this scaffolder recognises. */
function unrecognisedMoneyKeys(config) {
  return Object.keys(config ?? {}).filter((k) => !KNOWN_CONFIG_KEYS.has(k) && MONEY_LIKE_KEY.test(k));
}

/** Spend inputs the caller supplied that a non-financial agent will silently ignore. */
function ignoredSpendInputs(args, fileConfig) {
  return [
    ...['per-txn-max', 'max-amount', 'currency'].filter((k) => typeof args[k] === 'string').map((k) => '--' + k),
    ...['perTxnMax', 'maxAmount', 'currency'].filter((k) => fileConfig?.[k] !== undefined).map((k) => '"' + k + '" in the config file'),
  ];
}

/** resolveFinancial + saying so: one decision, announced identically by --harness and the hosted flow. */
function announceFinancial(args, fileConfig) {
  const result = resolveFinancial(args, fileConfig);
  if (result.warn) console.log(`  ${c.yellow('!')} ${result.warn}`);
  if (!result.financial) {
    console.log(`  ${c.green('✓')} non-financial agent ${c.dim('(' + result.why + ') — no spend limits, no payment demo; pass --financial to add them')}`);
    const ignored = ignoredSpendInputs(args, fileConfig);
    if (ignored.length) console.log(`  ${c.yellow('!')} ignoring ${ignored.join(', ')} — a non-financial agent has no spend limits. Pass --financial if this one does.`);
  }
  return result;
}

/**
 * The demo for a non-financial agent whose rules the caller could NOT set: the shared sandbox agent, and a delegated
 * request (the request carries no rules; the platform applies its default at approval). Derived from the platform's
 * own default for a non-financial agent - the same amount-free high-risk review the hosted flow describes - so what
 * the scaffold stages is what the issued agent actually enforces.
 */
function defaultNeutralDemo() {
  const demo = buildPolicyCases(harnessDefaultSopNeutral().molecules);
  console.log(`  ${c.green('✓')} derived ${demo.cases.length} demo case(s) from the platform's default rules for a non-financial agent`);
  for (const n of demo.notDemonstrated) console.log(`  ${c.yellow('!')} not staged in the demo: ${n.rule} ${c.dim('— ' + n.why + '; still enforced')}`);
  return demo;
}

/** A --config file's rules cannot reach an agent the caller does not provision themselves: say so instead of implying they apply. */
function warnRulesNotApplied(fileConfig, where) {
  if (policyMolecules(fileConfig).length === 0) return;
  console.log(`  ${c.yellow('!')} the rules in ${c.b('the config file')} are not applied to ${where} — its rules are the platform's defaults. Set your own in the dashboard (Legal Entity → SOPs), or provision your own agent (drop this flag) to author them here.`);
}

/**
 * Is this a financial agent? Explicit wins (`--non-financial` / `--financial`, or `"financial"` in
 * the config file). Otherwise a policy FILE is treated as the whole policy: with no spend limit
 * and no monetary rule in it, nothing money-shaped is added on the caller's behalf. Flags-only
 * scaffolds keep their historical (visible) defaults.
 */
function resolveFinancial(args, fileConfig) {
  if (args['non-financial']) return { financial: false, why: '--non-financial' };
  if (args.financial) return { financial: true, why: '--financial' };
  if (fileConfig && typeof fileConfig.financial === 'boolean') {
    return { financial: fileConfig.financial, why: 'the config file\'s "financial" field' };
  }
  if (fileConfig) {
    // A rule pack is a policy component this scaffolder cannot inspect (configFileSopFields only uses
    // it when the file has no rules/molecules). Packs are built from spend limits, so "I can't see any
    // money in it" is NOT evidence there is none: keep the historical financial scaffold.
    const inspectable = Array.isArray(fileConfig.molecules) || (Array.isArray(fileConfig.rules) && fileConfig.rules.length > 0);
    if (!inspectable && typeof fileConfig.rulePack === 'string') return { financial: true, why: null };
    // A key that LOOKS like a spend limit but isn't one we read (per_txn_max, budget, spendCap, ...) is
    // exactly how a policy that involves money ends up with none: refuse to infer "non-financial"
    // from a file we may have misread, and say why.
    const moneyLike = unrecognisedMoneyKeys(fileConfig);
    if (moneyLike.length) {
      return {
        financial: true,
        why: null,
        warn: `${moneyLike.map((k) => '"' + k + '"').join(', ')} in the config file look like spend limits but are not recognised (use perTxnMax / maxAmount / currency), so this is NOT treated as a non-financial agent. Pass --non-financial if it really does not move money.`,
      };
    }
    // `merchants` names payees — money-shaped even when no limit is set — so it counts too.
    const moneyField =
      ['perTxnMax', 'maxAmount', 'currency'].some((k) => fileConfig[k] !== undefined) ||
      (Array.isArray(fileConfig.merchants) && fileConfig.merchants.length > 0) ||
      (typeof args.merchants === 'string' && args.merchants.trim() !== '') ||
      ['per-txn-max', 'max-amount', 'currency'].some((k) => typeof args[k] === 'string');
    const monetaryRule = policyMolecules(fileConfig).some((m) => (m.atoms ?? []).some((a) => MONETARY_ATOMS.has(a.predicate)));
    if (!moneyField && !monetaryRule) {
      return { financial: false, why: `${String(args.config).split(/[\\/]/).pop()} sets no spend limit and contains no monetary rule` };
    }
  }
  return { financial: true, why: null };
}

const firstOf = (list, fallback) => (Array.isArray(list) && list.length ? String(list[0]) : fallback);
// The evaluator ignores empty terms, so the first NON-empty one is the only one worth staging.
const termsOf = (cfg) => (Array.isArray(cfg?.terms) ? cfg.terms.map(String).filter((t) => t.trim()) : []);
const CLEAN_PROMPTS = ['A routine request that breaks no rule.', 'ok', '.'];

/**
 * How to make each atom FIRE from the agent's side (`fire`; null = cannot be driven from this
 * config), what it says in the demo (`says`), and the runtime input it reads (`field`). What makes
 * a request PASS every rule at once is computed in buildPolicyCases (unions / intersections / maxima
 * across rules), not per atom. Amount-shaped atoms and the platform-derived trust score are
 * deliberately absent: see reasonNotDemonstrated().
 */
const ATOM_DEMO = {
  'consent-missing': { field: 'consent', fire: () => ({ consent: false }), says: () => 'consent has not been given' },
  'pii-present': { field: 'piiPresent', fire: () => ({ piiPresent: true }), says: () => 'personal data is present' },
  'text-matches': {
    field: 'prompt / output',
    fire: (cfg) => (termsOf(cfg).length ? { prompt: 'Please include "' + termsOf(cfg)[0] + '" in it.' } : null),
    says: (cfg) => 'the text mentions "' + (termsOf(cfg)[0] ?? '…') + '"',
  },
  'risk-at-or-above': {
    field: 'riskLevel',
    fire: (cfg) => ({ riskLevel: cfg?.level ?? 'high' }),
    says: (cfg) => 'the risk level is ' + (cfg?.level ?? 'high') + ' or above',
  },
  'jurisdiction-not-allowed': { field: 'jurisdiction', fire: () => ({ jurisdiction: 'ZZ-NOT-ALLOWED' }), says: () => 'the jurisdiction is not on the allowed list' },
  'data-residency-violation': { field: 'dataResidency', fire: () => ({ dataResidency: 'zz-not-allowed' }), says: () => 'the data would be stored outside the allowed regions' },
  'model-not-allowed': { field: 'model', fire: () => ({ model: 'unlisted-model' }), says: () => 'the model is not on the allowed list' },
  'tool-not-allowed': { field: 'tool', fire: () => ({ tool: 'unlisted-tool' }), says: () => 'the tool is not on the allowed list' },
  'data-source-not-approved': { field: 'dataSourceId', fire: () => ({ dataSourceId: 'unapproved-source' }), says: () => 'the data source is not approved' },
  'rate-limit-exceeded': {
    field: 'callCount',
    fire: (cfg) => ({ callCount: Number(cfg?.max ?? 0) + 1 }),
    says: (cfg) => 'the call count is over ' + Number(cfg?.max ?? 0),
  },
  'evidence-requirement': {
    field: 'evidenceTypes',
    fire: (cfg) => (Array.isArray(cfg?.required) && cfg.required.length ? { evidenceTypes: [] } : null),
    says: (cfg) => 'the required evidence (' + firstOf(cfg?.required, '…') + ') is missing',
  },
  'evidence-confidence-below': {
    field: 'evidenceConfidence',
    fire: (cfg) => (Number(cfg?.min) > 0 ? { evidenceConfidence: 0 } : null),
    says: (cfg) => 'the evidence confidence is below ' + Number(cfg?.min ?? 0),
  },
};

// [predicate, request field, config key holding the allow-list, exact (case-sensitive) match?]
// data-source-not-approved compares exactly; the other allow-list atoms compare case-insensitively.
const ALLOW_LISTS = [
  ['jurisdiction-not-allowed', 'jurisdiction', 'allowed', false],
  ['data-residency-violation', 'dataResidency', 'allowedRegions', false],
  ['model-not-allowed', 'model', 'allowed', false],
  ['tool-not-allowed', 'tool', 'allowed', false],
  ['data-source-not-approved', 'dataSourceId', 'approved', true],
];

/** What `npm start` will show, truthfully — including when no rule could be staged (no passing case exists). */
function demoOutcomes(demo) {
  return demo.cases.length
    ? `ALLOW · then one step per rule of yours (${demo.cases.length - 1}) · BLOCK (ungranted action)`
    : 'BLOCK (ungranted action) only - none of your rules could be staged (see the scaffold output)';
}

function reasonNotDemonstrated(atoms) {
  if (atoms.some((a) => MONETARY_ATOMS.has(a.predicate))) return 'it is a monetary rule and this agent is non-financial';
  if (atoms.some((a) => a.predicate === 'hol-trust-below-review')) return 'the trust score is derived by the platform, not supplied by the agent';
  if (atoms.some((a) => !ATOM_DEMO[a.predicate])) return 'there is no local demonstration for this rule type';
  return 'it cannot be triggered from this configuration';
}

/** The request fields the caller's rules read, and which rules read each. */
function requiredInputs(molecules) {
  const inputs = new Map();
  for (const m of molecules) {
    for (const a of m.atoms ?? []) {
      const field = ATOM_DEMO[a.predicate]?.field ?? (MONETARY_ATOMS.has(a.predicate) ? 'amount' : null);
      if (field) inputs.set(field, [...new Set([...(inputs.get(field) ?? []), m.name || m.id])]);
    }
  }
  return [...inputs].map(([field, rules]) => ({ field, rules }));
}

/**
 * Derive a demo from the caller's own molecules: { cases, notDemonstrated, inputs }.
 *
 * `cases[0]` is a request that satisfies EVERY rule at once; each later case trips exactly one rule.
 * Getting that true takes care, because rules interact (the evaluator lets the most restrictive
 * firing molecule win): so the passing request is merged across all rules (union of required
 * evidence, the highest confidence bar, a value present on every allow-list), and any rules that
 * read the SAME input as another rule are reported rather than staged — two tiers of one atom can't
 * be demonstrated independently, and a demo that mislabels its own policy is worse than none.
 * policy-demo.smoke.mjs runs every generated case through the real evaluator.
 */
function buildPolicyCases(molecules, { maxCases = 8 } = {}) {
  const label = (m) => m.name || m.id;
  const inputs = requiredInputs(molecules);

  // A "none" molecule fires when NO atom fires — exactly the state of a request that satisfies
  // everything — so no truthful passing request exists for the demo to show. Stage nothing.
  if (molecules.some((m) => m.combinator === 'none')) {
    return {
      cases: [],
      inputs,
      notDemonstrated: molecules.map((m) => ({
        rule: label(m),
        why: m.combinator === 'none'
          ? 'a "none" combinator fires when no atom fires, so the demo cannot stage a passing request truthfully'
          : 'not staged because another rule uses a "none" combinator',
      })),
    };
  }

  const notDemonstrated = [];
  const live = []; // molecules that can fire at all (the evaluator: no atoms or a combinator other than all/any never fires)
  for (const m of molecules) {
    if (!Array.isArray(m.atoms) || m.atoms.length === 0) notDemonstrated.push({ rule: label(m), why: 'it has no atoms, so it never fires' });
    else if (m.combinator !== 'all' && m.combinator !== 'any') notDemonstrated.push({ rule: label(m), why: 'its combinator is not "all" or "any", so it never fires' });
    else live.push(m);
  }

  // Rules that read the same input can't be staged independently (a case for one also trips or
  // un-trips the other). text-matches is the exception: its clash is a substring check, done below.
  const users = new Map(); // predicate -> live molecules using it
  for (const m of live) for (const p of new Set(m.atoms.map((a) => a.predicate))) users.set(p, [...(users.get(p) ?? []), m]);
  const sharesInput = new Set();
  for (const [p, ms] of users) if (ms.length > 1 && p !== 'text-matches' && ATOM_DEMO[p]) ms.forEach((m) => sharesInput.add(m));
  for (const m of live) {
    if (m.combinator === 'all' && new Set(m.atoms.map((a) => a.predicate)).size < m.atoms.length) sharesInput.add(m);
  }

  // The passing request: satisfies every live rule, staged or not.
  const configsOf = (pred) => live.flatMap((m) => m.atoms.filter((a) => a.predicate === pred).map((a) => a.config ?? {}));
  const base = {};
  if (configsOf('consent-missing').length) base.consent = true;
  if (configsOf('pii-present').length) base.piiPresent = false;
  if (configsOf('rate-limit-exceeded').length) base.callCount = 0;
  const riskLevels = configsOf('risk-at-or-above').map((cfg) => String(cfg.level ?? 'high'));
  if (riskLevels.length && !riskLevels.includes('low')) base.riskLevel = 'low';
  for (const [pred, field, key, exact] of ALLOW_LISTS) {
    // A value on EVERY list; if there is none (or a list is empty) leave the field absent, which
    // never trips an allow-list atom.
    const lists = configsOf(pred).map((cfg) => (Array.isArray(cfg[key]) ? cfg[key].map(String) : []));
    if (!lists.length || lists.some((l) => l.length === 0)) continue;
    const norm = (v) => (exact ? v : v.toLowerCase().trim());
    const common = lists[0].find((v) => lists.every((l) => l.some((x) => norm(x) === norm(v))));
    if (common !== undefined) base[field] = common;
  }
  const evidenceCfgs = configsOf('evidence-requirement');
  if (evidenceCfgs.length) base.evidenceTypes = [...new Set(evidenceCfgs.flatMap((cfg) => (Array.isArray(cfg.required) ? cfg.required.map(String) : [])))];
  const minConfidence = configsOf('evidence-confidence-below').map((cfg) => Number(cfg.min)).filter((n) => n > 0);
  if (minConfidence.length) base.evidenceConfidence = Math.max(...minConfidence);
  const allTerms = configsOf('text-matches').flatMap(termsOf);
  const containsTerm = (text, terms) => terms.some((t) => text.toLowerCase().includes(t.toLowerCase()));
  if (configsOf('text-matches').length) base.prompt = CLEAN_PROMPTS.find((p) => !containsTerm(p, allTerms)) ?? '';

  const cases = [{ kind: 'allow', intent: 'a request that satisfies every rule. Expected to pass.', expect: 'allow', context: base }];
  for (const m of live) {
    const name = label(m);
    if (m.decision !== 'block' && m.decision !== 'escalate') {
      notDemonstrated.push({ rule: name, why: `its decision is "${m.decision}", which this demo does not stage` });
      continue;
    }
    if (sharesInput.has(m)) {
      notDemonstrated.push({ rule: name, why: 'another rule reads the same input, so the two cannot be staged independently; both are still enforced' });
      continue;
    }
    const driven = m.atoms.map((a) => ({ a, demo: ATOM_DEMO[a.predicate], fire: ATOM_DEMO[a.predicate]?.fire(a.config ?? {}) ?? null }));
    // 'any' fires on one atom; 'all' needs every atom driven.
    const chosen = m.combinator === 'any' ? driven.filter((d) => d.fire).slice(0, 1) : driven.every((d) => d.fire) ? driven : [];
    if (!chosen.length) {
      notDemonstrated.push({ rule: name, why: reasonNotDemonstrated(m.atoms) });
      continue;
    }
    const context = { ...base };
    for (const { fire } of chosen) Object.assign(context, fire);
    // This rule's example text must not also contain a term from a DIFFERENT text rule.
    const otherTerms = live.filter((o) => o !== m).flatMap((o) => o.atoms.filter((a) => a.predicate === 'text-matches').flatMap((a) => termsOf(a.config)));
    if (typeof context.prompt === 'string' && chosen.some(({ a }) => a.predicate === 'text-matches') && containsTerm(context.prompt, otherTerms)) {
      notDemonstrated.push({ rule: name, why: 'its example text also contains a term from another text rule, so it cannot be staged on its own' });
      continue;
    }
    if (cases.length >= maxCases - 1) {
      notDemonstrated.push({ rule: name, why: `the demo stages the first ${maxCases - 2} rules only; it is still enforced` });
      continue;
    }
    cases.push({
      kind: m.decision,
      intent: `${chosen.map(({ a, demo }) => demo.says(a.config ?? {})).join(' and ')}. Expected to be ${m.decision === 'block' ? 'blocked' : 'sent for review'} (${name}).`,
      expect: m.decision,
      reasonCode: m.reasonCode,
      rule: name,
      context,
    });
  }
  return { cases, notDemonstrated, inputs };
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

// did:key (base58btc multibase over an Ed25519-multicodec-prefixed raw public key) — mirrors
// backend/src/features/agent-identity/did.util.ts / magp-did.mjs's buildDidKey exactly, so a
// did:key this CLI mints is resolvable by any real MAGP verifier (agentsafe-guard,
// agentsafe-mcp-guard) with zero network calls: the public key is embedded in the DID string
// itself. Reimplemented inline (not imported) — this CLI stays zero-dependency, and it is
// ~15 lines of pure math, not something worth a package for.
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '';
  for (let k = 0; k < zeros; k++) out += BASE58_ALPHABET[0];
  for (let q = digits.length - 1; q >= 0; q--) out += BASE58_ALPHABET[digits[q]];
  return out;
}
const ED25519_MULTICODEC = Uint8Array.of(0xed, 0x01);
const ED25519_SPKI_PREFIX_LEN = 12; // 302a300506032b6570032100 — fixed for every Ed25519 SPKI DER key
/** The RAW 32-byte Ed25519 public key from this CLI's own DER/SPKI hex export. */
function rawPublicKeyFromSpkiHex(publicKeyHex) {
  return Buffer.from(publicKeyHex, 'hex').subarray(ED25519_SPKI_PREFIX_LEN);
}
function buildDidKey(publicKeyBytes) {
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + publicKeyBytes.length);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(publicKeyBytes, ED25519_MULTICODEC.length);
  return `did:key:z${base58(prefixed)}`;
}

// Sign a BYOK challenge exactly as the gate verifies it: Ed25519 over the UTF-8 bytes of the raw
// challenge nonce, hex-encoded. Mirrors agentsafe-guard's sign().
function signChallengeHex(privateKeyHex, challenge) {
  const key = crypto.createPrivateKey({ key: Buffer.from(privateKeyHex, 'hex'), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(challenge, 'utf8'), key).toString('hex');
}

// ---------- BYOK via an already-running agentsafe-signer daemon (--daemon-socket) ----------
// Opt-in alternative to generateAgentKeypair() above: instead of generating the keypair in THIS
// process and writing it in plaintext into agent.metamynd.json, ask an already-running
// agentsafe-signer daemon (docs/design/agent-key-custody-local-signer-daemon-plan.md — started
// separately, e.g. `agentsafe-signer start --admin`) to generate the key and sign the
// proof-of-possession challenge. The private key never enters this process at all, and the
// scaffolded config gets `keyProvider: 'daemon'` instead of a plaintext `agentKey` — see
// agentsafe-guard/key-providers.mjs's resolveKeyProvider(), which reads that field exactly.
//
// Vendored rather than depending on @metamynd/agentsafe-signer or @metamynd/agentsafe-guard for
// it — this CLI is intentionally zero-dependency, and this is the SAME small, self-contained
// reimplementation of the daemon's local JSON-over-socket protocol that agentsafe-guard/
// key-providers.mjs and agentsafe-mcp-guard/key-providers.mjs already each carry their own copy
// of, rather than a fourth package depending on a signer package built for a persistent service,
// not a one-shot scaffolding command.
function toPlatformSocketPath(logicalPath) {
  if (process.platform !== 'win32') return logicalPath;
  const name = crypto.createHash('sha256').update(resolve(logicalPath)).digest('hex').slice(0, 32);
  return `\\\\.\\pipe\\agentsafe-signer-${name}`;
}

function daemonRequest(socketPath, op, params, { connectTimeoutMs = 5000 } = {}) {
  return new Promise((resolve_, reject) => {
    const deadline = Date.now() + connectTimeoutMs;
    let settled = false;
    const overallTimer = setTimeout(() => {
      settled = true;
      reject(Object.assign(new Error(`agentsafe-signer daemon unreachable at ${socketPath}: timed out after ${connectTimeoutMs}ms`), { code: 'DAEMON_UNREACHABLE' }));
    }, connectTimeoutMs);
    function attempt() {
      if (settled) return;
      const sock = net.connect(toPlatformSocketPath(socketPath));
      const requestId = crypto.randomUUID();
      let buf = '';
      const cleanup = () => sock.destroy();
      sock.once('error', (err) => {
        cleanup();
        if (settled) return;
        if (err.code === 'ENOENT' && Date.now() < deadline) { setTimeout(attempt, 20); return; }
        settled = true;
        clearTimeout(overallTimer);
        reject(Object.assign(new Error(`agentsafe-signer daemon unreachable at ${socketPath}: ${err.message}`), { code: 'DAEMON_UNREACHABLE' }));
      });
      sock.once('connect', () => {
        if (settled) return;
        sock.write(JSON.stringify({ protocolVersion: 1, requestId, op, params }) + '\n');
      });
      sock.on('data', (chunk) => {
        if (settled) return;
        buf += chunk.toString('utf8');
        const idx = buf.indexOf('\n');
        if (idx === -1) return;
        let res;
        try { res = JSON.parse(buf.slice(0, idx)); }
        catch (err) { cleanup(); settled = true; clearTimeout(overallTimer); reject(err); return; }
        cleanup();
        settled = true;
        clearTimeout(overallTimer);
        if (res.ok) resolve_(res.result);
        else reject(Object.assign(new Error(res.error?.message || res.error?.code || 'daemon rejected request'), { code: res.error?.code }));
      });
    }
    attempt();
  });
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

/**
 * POST /policy/counterparties for the gateway's own DID — best-effort, unlike apiPost above: a
 * hosted financial gateway works fine on testnet with no registration at all (open by default), so
 * a failure here (network blip, an older backend without the endpoint) should not abort scaffolding
 * the way a failed agent provisioning does. Always sends confirmEnforcementChange: true — this CLI
 * IS the confirmation (the caller is reading this exact terminal output live, the same way a
 * dashboard registration shows its own dialog before setting the flag); see the printed message
 * either way.
 */
async function registerGatewayCounterparty(base, token, did, label) {
  try {
    const res = await fetch(`${base}/policy/counterparties`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ did, label, confirmEnforcementChange: true }),
    });
    const json = await res.json().catch(() => null);
    if (!res.ok || json?.success === false) return { ok: false, message: json?.message ?? `HTTP ${res.status}` };
    return { ok: true, message: json?.message ?? 'registered' };
  } catch (e) {
    return { ok: false, message: String(e?.message ?? e) };
  }
}

// ---------- scaffolding ----------
/**
 * The --no-gateway / --sandbox variant: the tool is a local function in the SAME process as
 * guard.guardTool(). Fine for a demo with nothing real behind it (--sandbox always uses this —
 * it's a shared identity, never meant to hold real credentials). For anything that touches a
 * real credential, guard.guardTool() alone is a client-side convenience, not a boundary: it
 * still calls this handler in-process regardless of where the decision came from, so an agent
 * that skips it and calls bookFlight() directly gets the same result the gate would have given
 * it — the same shape of gap --harness's README documents. See exampleIndex() below, which is
 * what the real (non-sandbox) flow scaffolds by default instead.
 */
function exampleIndexNoGateway(scope, perTxnMax, currency, merchant) {
  const under = Math.max(1, Math.round(perTxnMax * 0.5));
  const over = Math.round(perTxnMax + 100);
  return `// index.mjs — your agent, governed by MetaMynd/AgentSafe.
// Every governed tool call is checked (allow / block / escalate) before it runs.
import { createGuardFromConfig } from '${GUARD_PKG}';
${guardFreshnessCheck()}

// Loads agent.metamynd.json: the agent's DID, its signing key, and the gate to call.
const guard = await createGuardFromConfig('./agent.metamynd.json'); // no env vars

// --- Your real tool. Replace the body with your actual implementation. ---
// --- If that implementation touches a real credential, this in-process call is NOT an
// --- enforcement boundary: guard.guardTool() below still calls this function directly in
// --- THIS process regardless of the decision's source, so anything that can call it directly
// --- gets the same result the gate would have given it. A real (non --sandbox) scaffold
// --- without --no-gateway moves this behind a separate process instead. See README.
async function bookFlight(args) {
  return { pnr: 'PNR-DEMO', ...args };
}

// --- The GATED version. Register THIS with your agent instead of the raw handler. ---
const gatedBookFlight = guard.guardTool(
  '${scope}',                                   // = your mandate scope
  bookFlight,
  (a) => ({                                     // map tool args → gate inputs
    amount: a.amount,
    currency: '${currency}',
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
    currency: '${currency}',
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
  SOP_SPEND_CAP: 'your SOP caps a single transaction at ${currency} ${perTxnMax}',
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
console.log(dim('  cap    ${currency} ${perTxnMax} per transaction, set by your SOP'));

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
await attempt(1, 'a ${currency} ${under} booking, low risk. Expected to pass.', { amount: ${under}, currency: '${currency}', merchant: '${merchant}', riskLevel: 'low' });
await attempt(2, 'a ${currency} ${over} booking, deliberately over the cap.', { amount: ${over}, currency: '${currency}', merchant: '${merchant}', riskLevel: 'low' });
await attempt(3, 'a ${currency} ${under} booking, but flagged high risk.', { amount: ${under}, currency: '${currency}', merchant: '${merchant}', riskLevel: 'high' });
await attempt(
  4,
  'the agent stops booking flights and asks to raise its OWN limit.',
  { amount: 100000, currency: '${currency}', merchant: '${merchant}' },
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
console.log(bold('  Without MetaMynd, you can be bypassed.') + ' bookFlight() runs in THIS process -');
console.log(dim('  call it directly instead of gatedBookFlight and nothing above stops you.'));
console.log(dim('  Re-scaffold without --sandbox/--no-gateway for the default shape, which does.'));
console.log('');
console.log('  Change the cap in the dashboard (Legal Entity -> SOPs) and run again.');
console.log(dim('  The outcome changes. This file does not. That is the point.'));
console.log('');
`;
}

/**
 * The DEFAULT hosted scaffold: the tool lives in a separate process (./gateway), not here.
 * guard.guardTool() below is still called — it is a fast, local, client-side pre-check that
 * gives good UX (fail fast, no round trip for an obviously-blocked call) — but it is not what
 * stops a bypass. What stops a bypass is that there is no bookFlight() in THIS process to call
 * directly: it only exists in ./gateway, which independently re-verifies every request against
 * this agent's own policy bundle before it runs, and holds any real credentials the tool needs.
 */
function exampleIndex(scope, perTxnMax, gatewayPort, currency, merchant) {
  const under = Math.max(1, Math.round(perTxnMax * 0.5));
  const over = Math.round(perTxnMax + 100);
  return `// index.mjs — your agent, governed by MetaMynd/AgentSafe.
// Every governed tool call is checked TWICE before it runs: once here (fast, local, client-side),
// and independently again by ./gateway — a SEPARATE process that holds the real tool and its
// credentials. That second check is the actual enforcement boundary; see ./gateway/README.md.
import { createGuardFromConfig } from '${GUARD_PKG}';
${guardFreshnessCheck()}

// Loads agent.metamynd.json: the agent's DID, its signing key, and the gate to call.
const guard = await createGuardFromConfig('./agent.metamynd.json'); // no env vars

const GATEWAY = process.env.GATEWAY_URL || 'http://localhost:${gatewayPort}';

// --- Calls the gateway process instead of a local function. There is no raw bookFlight() in
// --- this file to call directly — the tool, and any real credentials it needs, live only in
// --- ./gateway, which independently re-verifies this signed request itself.
// --- \`decision\` is guardTool()'s own verdict, already produced by the REAL remote gate for any
// --- value-bearing action (sealValueActions, on by default) — its authorizationId is what lets
// --- the gateway atomically claim single-use execution, closing replay + cumulative spend, not
// --- just re-checking policy. See ./gateway/README.md.
async function bookFlightViaGateway(args, decision) {
  // The COMPLETE body the tool receives. It is signed as a payload (MAGP 8.3.9): the eight signed fields cover amount and
  // merchant, not anything else a real tool takes (a payee, a passenger list). The digest covers ALL of it, and the gateway
  // refuses to run the tool on a body that is not exactly this one.
  const payload = { amount: args.amount, merchant: args.merchant, currency: args.currency ?? '${currency}' };
  const signed = await guard.buildSignedRequest({
    action: '${scope}',
    amount: args.amount,
    currency: args.currency ?? '${currency}',
    merchant: args.merchant,
    context: { tool: 'book-flight', riskLevel: args.riskLevel ?? 'low' },
    payload,
  });
  signed.authorizationId = decision?.authorizationId;
  const res = await fetch(GATEWAY + '/book-flight', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-magp-request': JSON.stringify(signed) },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error('gateway ' + res.status + ': ' + (body?.reasonCode ?? 'refused'));
    err.name = 'GovernanceBlocked';
    err.governance = { decision: body?.decision ?? 'block', reasonCode: body?.reasonCode ?? 'GATEWAY_ERROR' };
    throw err;
  }
  return body;
}

// --- The GATED version. Register THIS with your agent instead of calling the gateway directly.
// --- This local check and the gateway's own re-check are independent; neither trusts the other.
const gatedBookFlight = guard.guardTool(
  '${scope}',                                   // = your mandate scope
  bookFlightViaGateway,
  (a) => ({                                     // map tool args → gate inputs
    amount: a.amount,
    currency: a.currency ?? '${currency}',
    merchant: a.merchant,
    context: { tool: 'book-flight', riskLevel: a.riskLevel ?? 'low' },
    // The authorization is bound to the SAME body bookFlightViaGateway() sends, so the gate records what this agent
    // signed and the gateway can prove it is running exactly that. Keep the two in step if you add a field.
    payload: { amount: a.amount, merchant: a.merchant, currency: a.currency ?? '${currency}' },
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
    currency: a.currency ?? '${currency}',
    merchant: a.merchant,
    context: { tool: 'permissions-update' },
  }),
);

const dim = (t) => '\\x1b[2m' + t + '\\x1b[0m';
const bold = (t) => '\\x1b[1m' + t + '\\x1b[0m';
const rule = (n) => '  ' + '-'.repeat(n);

// Plain-English meaning for the reason codes this demo can produce. The gateway re-evaluates
// the SAME policy bundle with the SAME evaluator the gate uses, so it produces these same codes.
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
console.log('  An agent should not be the thing that decides what it is allowed to do — and');
console.log('  it should not be the thing that RUNS what it decided, either. This run makes');
console.log('  both concrete. Three attempts take the SAME code path and produce three');
console.log('  different outcomes. The fourth asks for something the agent was never granted');
console.log('  at all - and that is the one a prompt could not have stopped, because the');
console.log('  decision is not made inside your program, and the tool is not either.');

// ---------------------------------------------------------------- 2. MECHANISM
console.log('');
console.log(bold('  How it does that'));
console.log('');
console.log(dim('   1. this project holds an agent identity (a DID) and its signing key'));
console.log(dim('   2. that agent has a mandate - a scope it may act in, and a spend cap'));
console.log(dim('   3. guardTool() wraps your tool call, giving a fast local pre-check'));
console.log(dim('   4. each attempt is ALSO signed and sent to ./gateway - a separate process'));
console.log(dim('   5. the gateway independently re-verifies before your tool runs there'));
console.log(dim('   6. there is no local bookFlight() to call directly - only the gateway has it'));
console.log('');
console.log(dim('  scope    ${scope}'));
console.log(dim('  cap      ${currency} ${perTxnMax} per transaction, set by your SOP'));
console.log(dim('  gateway  ' + GATEWAY + '  (run it in a separate terminal - see ./gateway)'));

// ---------------------------------------------------------------- 3. THE STEPS
async function attempt(n, intent, args, tool = gatedBookFlight) {
  console.log('');
  console.log(bold('  Step ' + n + ' of 4') + ' - ' + intent);
  console.log(dim('     signing the request locally, then asking the gate to decide...'));
  try {
    const r = await tool(args);
    console.log('\\x1b[32m     ALLOWED\\x1b[0m  your tool ran (in ./gateway) and returned ' + (r.pnr ?? 'ok'));
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
      console.log(dim('     your tool never ran - refused before execution.'));
    }
  }
}

console.log('');
console.log(rule(66));
await attempt(1, 'a ${currency} ${under} booking, low risk. Expected to pass.', { amount: ${under}, currency: '${currency}', merchant: '${merchant}', riskLevel: 'low' });
await attempt(2, 'a ${currency} ${over} booking, deliberately over the cap.', { amount: ${over}, currency: '${currency}', merchant: '${merchant}', riskLevel: 'low' });
await attempt(3, 'a ${currency} ${under} booking, but flagged high risk.', { amount: ${under}, currency: '${currency}', merchant: '${merchant}', riskLevel: 'high' });
await attempt(
  4,
  'the agent stops booking flights and asks to raise its OWN limit.',
  { amount: 100000, currency: '${currency}', merchant: '${merchant}' },
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
console.log(dim('   - step 1 ran in ./gateway, a process this file cannot reach into. There'));
console.log(dim('     is no rawBookFlight() here to call instead - that is what actually'));
console.log(dim('     stops a bypass, not the guardTool() call above it.'));
console.log(dim('   - step 4 needed no rule to stop it. The agent could not widen its own'));
console.log(dim('     authority, because it cannot name an action nobody delegated to it.'));
console.log(dim('   - every blocked/escalated call never reached a real tool at all.'));
console.log(dim('   - if the gate were unreachable the guard fails CLOSED: it blocks.'));
console.log('');
console.log(bold('  With MetaMynd, you can\\'t be bypassed.') + ' ./gateway is why - it independently');
console.log(dim('  re-verified step 1 before running it, and holds the tool this file never can.'));
console.log('');
console.log('  Change the cap in the dashboard (Legal Entity -> SOPs) and run again.');
console.log(dim('  The outcome changes. This file does not. That is the point.'));
console.log('');
`;
}

/** The generated README's fresh-clone section (BR-004/BR-005), shared by every hosted README. */
function clonedFreshSection(daemonKey) {
  return `## Cloned this project fresh?

\`agent.metamynd.json\` holds the agent's identity${daemonKey ? '' : ' and secret key'}, so it is gitignored — a clone never contains it, and \`npm start\` will stop and tell you so. To continue:

1. Get the config: download it from the MetaMynd dashboard (Agents → your agent), or run \`npx create-metamynd-agent\` for a new agent.
2. Save it in this directory as \`agent.metamynd.json\`.
3. \`npm install && npm start\`.

If a committed \`package-lock.json\` pins an older \`${GUARD_PKG}\` than this project was written for, the first run prints a warning; fix it with \`npm install ${GUARD_PKG}@latest\`.`;
}

// ---------- hosted NON-FINANCIAL scaffold (BR-006) ----------
//
// The hosted flow used to provision spend limits and generate a flight-booking demo whatever the
// policy. For an agent that does not move money (`financial === false`, see resolveFinancial) the
// provisioning call omits every spend field (the backend treats their absence as a non-financial
// mandate — onboarding.provision.ts) and the project below is generated instead: the action is the
// caller's own scope, the demo steps are derived from their rules (buildPolicyCases), and nothing in
// it is about payments. The financial templates above are unchanged.

/**
 * The example agent for a non-financial hosted scaffold — one template for both shapes:
 * with `gatewayPort` the tool lives in a separate process (./gateway, the real enforcement
 * boundary); without it (--no-gateway) the tool is a local function in this process.
 */
function exampleIndexNeutral({ scope, gatewayPort, demo, merchant }) {
  const withGateway = gatewayPort != null;
  const steps = [
    ...demo.cases,
    { kind: 'block', intent: 'the agent asks to change its OWN permissions - an action nobody delegated. Expected to be blocked.', expect: 'block', reasonCode: 'NO_PERMISSION_FOR_ACTION', action: 'permissions.update', context: {} },
  ];
  return `// index.mjs — your agent, governed by MetaMynd/AgentSafe.
// Every governed tool call is checked before it runs: allow, block, or escalate to a human.${withGateway ? `
// It is checked TWICE: once here (fast, local, client-side), and independently again by ./gateway —
// a SEPARATE process that holds the real tool. That second check is the actual enforcement
// boundary; see ./gateway/README.md.` : ''}
// The steps below were DERIVED FROM YOUR OWN RULES when this project was scaffolded: one request
// that should pass, and one per rule that should trip it. Nothing here is about payments.
import { createGuardFromConfig } from '${GUARD_PKG}';
${guardFreshnessCheck()}

// Loads agent.metamynd.json: the agent's DID, its signing key, and the gate to call.
const guard = await createGuardFromConfig('./agent.metamynd.json'); // no env vars

const dim = (t) => '\\x1b[2m' + t + '\\x1b[0m';
const bold = (t) => '\\x1b[1m' + t + '\\x1b[0m';
const rule = (n) => '  ' + '-'.repeat(n);

const MERCHANT = ${merchant ? JSON.stringify(merchant) : 'undefined'};
${withGateway ? `const GATEWAY = process.env.GATEWAY_URL || 'http://localhost:${gatewayPort}';

// --- Calls the gateway process instead of a local function. There is no raw performAction() in
// --- this file to call directly — the tool, and any real credentials it needs, live only in
// --- ./gateway, which independently re-verifies this signed request itself.
async function performViaGateway(args, decision) {
  const signed = await guard.buildSignedRequest({ action: '${scope}', merchant: MERCHANT, context: args });
  signed.authorizationId = decision?.authorizationId; // none for a value-less action — see ./gateway/README.md
  const res = await fetch(GATEWAY + '/perform', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-magp-request': JSON.stringify(signed) },
    body: '{}', // this tool reads nothing from the body; the request's fields travel in the SIGNED context
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error('gateway ' + res.status + ': ' + (body?.reasonCode ?? 'refused'));
    err.name = 'GovernanceBlocked';
    err.governance = { decision: body?.decision ?? 'block', reasonCode: body?.reasonCode ?? 'GATEWAY_ERROR' };
    throw err;
  }
  return body;
}
` : `// --- Your real tool. Replace the body with your actual implementation. ---
// --- If that implementation touches a real credential, this in-process call is NOT an
// --- enforcement boundary: guard.guardTool() below still calls this function directly in
// --- THIS process regardless of the decision's source. A scaffold without --no-gateway moves
// --- the tool behind a separate process instead. See README.
async function performAction(args) {
  return { done: true, action: '${scope}' };
}
`}
// --- The GATED version. Register THIS with your agent instead of the raw handler. ---
// The request's own fields (consent, piiPresent, jurisdiction, ...) travel as the gate's \`context\`.
const gatedAction = guard.guardTool(
  '${scope}',                                   // = your mandate scope
  ${withGateway ? 'performViaGateway' : 'performAction'},
  (a) => ({ merchant: MERCHANT, context: a }),   // map tool args → gate inputs
);

// --- An action the agent was NEVER granted. Wrapping it is the demonstration: no rule anywhere
// --- forbids it. The mandate simply never mentioned the action.
async function changeOwnPermissions(args) {
  return { updated: true, ...args };          // never runs, and that is the point
}
const gatedChangeOwnPermissions = guard.guardTool(
  'permissions.update',                       // an action NOT in the mandate
  changeOwnPermissions,
  (a) => ({ context: a }),
);

const STEPS = ${JSON.stringify(steps, null, 2)};
const INPUTS = ${JSON.stringify(demo.inputs)};
const NOT_STAGED = ${JSON.stringify(demo.notDemonstrated)};

async function attempt(n, total, step) {
  const tool = step.action === 'permissions.update' ? gatedChangeOwnPermissions : gatedAction;
  console.log('');
  console.log(bold('  Step ' + n + ' of ' + total) + ' - ' + step.intent);
  console.log(dim('     signing the request locally, then asking the gate to decide...'));
  let got;
  let g = {};
  try {
    await tool(step.context);
    got = 'allow';
    console.log('\\x1b[32m     ALLOWED\\x1b[0m  your tool ran${withGateway ? ' (in ./gateway)' : ''}');
  } catch (e) {
    g = e.governance ?? {};
    got = g.decision ?? 'error';
    if (g.decision === 'escalate') {
      console.log('\\x1b[33m     ESCALATED\\x1b[0m  held for a human - ' + g.reasonCode);
      console.log(dim('     not a failure: approve it in the dashboard and the action resumes.'));
    } else {
      console.log('\\x1b[31m     BLOCKED\\x1b[0m  ' + (g.reasonCode ?? e.message));
      console.log(dim('     your tool never ran - refused before execution.'));
    }
  }
  const asExpected = got === step.expect && (!step.reasonCode || g.reasonCode === step.reasonCode);
  if (asExpected) console.log(dim('     as expected.'));
  else console.log('\\x1b[33m     NOT AS EXPECTED\\x1b[0m  expected ' + step.expect + (step.reasonCode ? ' (' + step.reasonCode + ')' : '') + ' — your rules (in the dashboard) or this step have changed since scaffolding.');
}

console.log('');
console.log(bold('  What this simulation shows'));
console.log('');
console.log('  An agent should not be the thing that decides what it is allowed to do${withGateway ? ' — and' : '.'}');${withGateway ? `
console.log('  it should not be the thing that RUNS what it decided, either. Each step below');
console.log('  takes the SAME code path and your rules decide.');` : `
console.log('  Each step below takes the SAME code path and your rules decide.');`}
console.log(dim('  The steps come from YOUR rules, as they were when this project was scaffolded.'));
console.log('');
console.log(dim('  scope   ${scope}  (no spending authority - this agent does not move money)'));
${withGateway ? "console.log(dim('  gateway  ' + GATEWAY + '  (run it in a separate terminal - see ./gateway)'));\n" : ''}console.log(dim('  inputs  the fields your application must supply for these rules to judge anything:'));
for (const i of INPUTS) console.log(dim('            ' + i.field + '  <-  ' + i.rules.join(', ')));
if (INPUTS.length) console.log(dim('          A missing field never trips an allow-list, consent or PII rule - supply it.'));
for (const n of NOT_STAGED) console.log(dim('  not staged  ' + n.rule + ' - ' + n.why));

console.log('');
console.log(rule(66));
for (let i = 0; i < STEPS.length; i++) await attempt(i + 1, STEPS.length, STEPS[i]);
console.log('');
console.log(rule(66));

console.log('');
console.log(bold('  What this proved'));
console.log('');
console.log(dim('   - one code path, several outcomes. The rules decided, not this file'));
console.log(dim('     and not the model driving it.'));
console.log(dim('   - the last step needed no rule to stop it. The agent could not widen its own'));
console.log(dim('     authority, because it cannot name an action nobody delegated to it.'));
console.log(dim('   - a blocked or held call never reached your tool at all.'));
console.log(dim('   - if the gate were unreachable the guard fails CLOSED: it blocks.'));
console.log('');${withGateway ? `
console.log(bold('  Checked twice, by two processes.') + ' ./gateway independently re-verified the allowed step');
console.log(dim('  before running your tool there - a process this file cannot reach into.'));
console.log(dim('  It enforces scope and identity firmly. What it does NOT close: the rule inputs'));
console.log(dim('  above are not signed (an agent that can sign could omit or forge one), and a'));
console.log(dim('  signed request can be reused for 5 minutes - see ./gateway/README.md.'));` : `
console.log(bold('  Without MetaMynd, you can be bypassed.') + ' performAction() runs in THIS process -');
console.log(dim('  call it directly instead of gatedAction and nothing above stops you.'));
console.log(dim('  Re-scaffold without --no-gateway for the default shape, which closes that.'));`}
console.log('');
console.log('  Change your rules in the dashboard (Legal Entity -> SOPs) and run again.');
console.log(dim('  The outcome changes. This file does not. That is the point.'));
console.log('');
`;
}

/**
 * The tool gateway for a non-financial hosted scaffold. Same shape as gatewayServerFile, with two
 * deliberate differences: the route has NO value fields, and requireAuthorization is OFF — the guard
 * only seals a single-use authorization for a value-bearing action (amount > 0), so with it ON every
 * allowed value-less request would be refused AUTHORIZATION_REQUIRED. The README states what that
 * leaves open (replay) rather than implying the financial scaffold's guarantees.
 */
function gatewayServerFileNeutral(scope, port, apiBase, policyKey) {
  return `#!/usr/bin/env node
// gateway/server.mjs — the enforcement boundary for this agent's tool(s).
//
// This is a SEPARATE process from the agent. It holds the tool's real credentials (the agent
// process never does), and it independently re-verifies every request against this agent's OWN
// published policy bundle — it does not trust the agent's own guard.guardTool() check. A
// compromised or dishonest agent calling its own local function gets nothing here, because
// there is no local function: the tool only runs in this process.
import http from 'node:http';
import { createMcpGuard } from '${MCP_GUARD_PKG}';
import { createHttpGateway } from '${GATEWAY_PKG}';

const PORT = Number(process.env.PORT || ${port});
const MAGP_API = process.env.MAGP_API || '${apiBase}';

// --- Your real tool. Real credentials belong ONLY here, read from process.env (see .env.example)
// --- — never in the agent process.
async function performAction(args) {
  return { done: true, action: '${scope}' };
}

// One protected route: only a request signed by this agent, for exactly this action, and
// re-verified against this agent's own mandate/SOP, reaches performAction() below.
//
// valueFields: [] because this action carries no amount or merchant to bind the body to — say so
// explicitly rather than lean on the library default, which would demand both.
//
// allowedFields: [] because performAction() reads nothing from the body, so any key the agent adds is
// refused (PAYLOAD_UNBINDABLE): nothing signed covers it. When your real tool reads body fields, list
// exactly those keys here — the gateway refuses every top-level key you do not name.
const routes = [{ method: 'POST', path: '/perform', action: '${scope}', valueFields: [], allowedFields: [] }];

// requireAuthorization is OFF on purpose. It makes the gateway claim a single-use, stateful
// authorization before running the tool — but the agent's guard only seals one for a value-bearing
// action (amount > 0), and this agent has no spending authority. With it ON, every ALLOWED request
// would be refused AUTHORIZATION_REQUIRED. What that leaves open (a signed request is reusable for
// the guard's 5-minute freshness window; the issuer's stateful rate/circuit-breaker floors; and the
// rule inputs, which are not covered by the signature) is spelled out in README.md.
// policyPublicKey pins the bundle to MetaMynd's OWN signing key (from your provisioning response,
// baked in here — never fetched at runtime, so a compromised network can't swap it out alongside a
// forged bundle). Without it, verifyBundle() never runs at all: an attacker who can intercept the
// fetch to \`\${MAGP_API}/policy/bundle/...\` — a MITM, a compromised DNS/proxy — can hand this gateway
// a bundle with a higher cap or no rules, and it would be trusted the same as the real one.
const guard = createMcpGuard({ serviceDid: 'did:local:${scope}-gateway', issuerApi: MAGP_API, requireAuthorization: false${policyKey ? `, policyPublicKey: '${policyKey}'` : ''} });

const gateway = createHttpGateway({
  guard,
  routes,
  forward: async (req) => {
    let args = {};
    try { args = JSON.parse(req.rawBody?.toString('utf8') || '{}'); } catch { /* empty body */ }
    const result = await performAction(args);
    return { status: 200, body: result };
  },
  // This gateway IS the tool, not a proxy in front of one — an unmatched path has nothing to
  // pass through TO. Without this, any path a route doesn't match falls through ungoverned
  // straight to forward() above, which would run performAction() with no check at all.
  denyByDefault: true,
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const rawBody = await readBody(req);
    const result = await gateway({ method: req.method, path: req.url, headers: req.headers, rawBody });
    const headers = { 'content-type': 'application/json' };
    if (result.governance) headers['x-agentsafe-decision'] = result.governance.decision;
    res.writeHead(result.status, headers);
    res.end(JSON.stringify(result.body ?? {}));
  } catch (err) {
    // Fail CLOSED on any gateway error.
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: 'block', reasonCode: 'GATEWAY_ERROR', error: String(err?.message ?? err) }));
  }
});

server.listen(PORT, () => {
  console.log('[gateway] listening on :' + PORT + ' -> the only place performAction() runs.');
  console.log('[gateway] every request is independently re-verified against this agent\\'s own policy.');
});
`;
}

function gatewayEnvExampleNeutral() {
  return `# Real tool credentials belong HERE, read from process.env in server.mjs — never in the
# agent process one directory up.
# TOOL_API_KEY=
`;
}

function gatewayReadmeNeutral(slug, scope, port) {
  return `# ${slug}-gateway

This process is the **enforcement boundary** for \`${slug}\`'s tool — not \`../index.mjs\`.

## Why this exists

\`guard.guardTool()\` in the agent's \`index.mjs\` is a client-side convenience: it gives fast, local
allow/block/escalate feedback, but it still runs its handler in the SAME process regardless of where
the decision came from. Anything able to call the agent's tool function directly — a bug, a
compromised dependency, a dishonest fork of the agent's own code — gets the same result the gate
would have given it. A cooperative in-process check has no counterparty to disagree with a caller
that skips it.

This process closes that gap by being a **separate** one. \`performAction()\` does not exist in the
agent's process; it exists only here, and every request that reaches it has been re-verified against
this agent's OWN published policy bundle, fetched by THIS process, with the agent's Ed25519
signature checked against its DID.

## What this closes, and what it does not

This is narrower than it sounds, so read it before relying on it.

**Closed:** no tool call without a validly signed request from THIS agent for an action in its
mandate. The agent's Ed25519 signature is checked against its DID, the action must be granted, and a
suspended or quarantined agent is refused. Code that skips the agent's own guard and cannot sign as
the agent gets nothing, and there is no local function to call directly. The policy bundle itself is
pinned to MetaMynd's own signing key (\`policyPublicKey\`, baked in from your provisioning response) —
a party that can intercept the bundle fetch (a MITM, a compromised DNS/proxy) cannot hand this gateway
a forged bundle with a higher cap or no rules; \`server.mjs\` refuses an unsigned or tampered one outright.

**NOT closed — be precise about this:**

- **Rule inputs are not signed.** The request fields your rules read (\`consent\`, \`piiPresent\`,
  \`jurisdiction\`, …) travel in the request's \`itinerary\`, which the signature does not cover, and
  the body the tool executes is not bound to it (\`valueFields: []\`). An agent that CAN sign — a
  dishonest one, or a compromised one — can omit a field or send a different one, and the rule that
  reads it will not fire: an allow-list, consent or PII rule treats an absent field as "nothing to
  object to". So this gateway enforces scope and identity firmly, but an **input-dependent rule is
  only as strong as whatever supplies the input**. Source those fields from a system you control,
  not from model output.
- **Replay.** \`server.mjs\` runs with \`requireAuthorization: false\`. That option makes a gateway claim
  a single-use, stateful authorization before running the tool. The agent's guard only seals such an
  authorization for a **value-bearing** action (\`amount > 0\`), and this agent has no spending
  authority — so its allowed requests carry none, and requiring one would refuse every allowed
  request. Consequence: a validly signed request can be reused, with different content, until the
  guard's freshness window (5 minutes from its \`issuedAt\`) lapses.
- **The issuer's stateful floors** (rate limit, circuit breaker) are not re-checked at this gateway.
  If your policy relies on them, enforce them where the call originates.

## Run

\`\`\`bash
npm install
npm start           # listens on :${port} (PORT to change)
\`\`\`

Start this **before** the agent. \`MAGP_API\` overrides the issuer URL it fetches the policy bundle from.

## Your real tool

Replace \`performAction()\` in \`server.mjs\` with your implementation and put any credentials in
\`.env\` (see \`.env.example\`). Add a route per governed action; a path with no route is refused.
`;
}

/** The README for a non-financial hosted scaffold. `withGateway` selects the two-process shape. */
function exampleReadmeNeutral(slug, scope, withGateway, gatewayPort, daemonKey, demo) {
  const configLine = daemonKey
    ? `- \`agent.metamynd.json\` — your portable guard config (identity, mandate scope \`${scope}\`, issuer keys).
  **Holds no secret key.** Signing goes through your already-running agentsafe-signer daemon instead.`
    : `- \`agent.metamynd.json\` — your portable guard config (identity, mandate scope \`${scope}\`, issuer keys).
  **Contains the agent's secret key — never commit it.** It is already in \`.gitignore\`.`;
  return `# ${slug}

A MetaMynd/AgentSafe-governed agent, scaffolded with \`create-metamynd-agent\`. It has **no spending
authority** — it does not move money — so there is no spend cap and no payment demo. What it does is
governed by the rules you supplied.

## Run

${withGateway ? `Two processes — start the gateway first, in its own terminal:

\`\`\`bash
cd gateway && npm install && npm start   # the enforcement boundary — see gateway/README.md
\`\`\`

Then, in this directory:

\`\`\`bash
npm install
npm start
\`\`\`
` : `\`\`\`bash
npm install
npm start
\`\`\`
`}
${demo.cases.length
  ? `You should see an ALLOW, then one BLOCK or ESCALATE for each rule of yours the demo can stage, and
finally a BLOCK for an action outside the mandate entirely. Every step says what it expects and flags
any surprise.`
  : `None of your rules could be staged in the demo (see below), so it shows only a BLOCK for an action
outside the mandate. Your rules are still enforced.`}

## Files

${configLine}
- \`index.mjs\` — the example. ${withGateway ? 'Signs each request and calls `./gateway` for it; `guard.guardTool()` here is a fast local pre-check, not the enforcement boundary.' : 'Wraps a tool with `guard.guardTool(...)`; the tool only runs when the gate allows.'}
- \`verify-context.json\` — the request fields of a request that satisfies every rule. \`npm test\` sends
  it, because a policy that REQUIRES an input blocks a request without it.${withGateway ? `
- \`gateway/\` — a **separate process** that holds the real tool and independently re-verifies every
  request. See \`gateway/README.md\` — including what it does NOT close.` : ''}

## What your rules read

A rule can only judge a field your application actually supplies with the request. Supply each of
these (the demo in \`index.mjs\` does):

${demo.inputs.map((i) => `- \`${i.field}\` — ${i.rules.join(', ')}`).join('\n') || '- (none — your rules read no request fields)'}

**A missing field is not a violation** for an allow-list, consent or PII rule: if your application
forgets to send \`jurisdiction\` or \`consent\`, that rule simply does not fire. Make sure the field is
always present. These fields are asserted by the calling agent and are not covered by its signature —
an agent that can sign could omit or forge one, and the rule would not fire. Source them from a system you
control, not from model output.${demo.notDemonstrated.length ? `

Rules the demo does not stage (they are still enforced):

${demo.notDemonstrated.map((n) => `- ${n.rule} — ${n.why}`).join('\n')}` : ''}

## \`npm test\`

\`agentsafe-guard verify --context ./verify-context.json\` asserts this agent cannot act outside its
mandate. Controls this mandate does not set (a spend cap, say — it has none) are reported as **not
configured**, never as passed. Put it in CI.${demo.cases.length ? '' : `

\`verify-context.json\` is empty because no request that satisfies every rule could be derived from
yours (a rule using a \`none\` combinator fires on exactly such a request). \`npm test\` may therefore
report that ordinary work is blocked. Edit \`verify-context.json\` to a request your rules permit.`}

${clonedFreshSection(daemonKey)}

## Change the rules

Edit the agent's SOPs in the dashboard (Legal Entity → SOPs). The agent's behaviour changes live —
no redeploy. An \`escalate\` verdict is held for an owner to approve; poll \`guard.escalationStatus(id)\`.

## What this is not

${withGateway
  ? `**The gateway closes one real gap, not every gap.** It stops code that cannot sign as this agent from
running the tool, and refuses anything outside the mandate. It does **not** make input-dependent rules
tamper-proof: the request fields your rules read are not signed, so an agent that can sign could omit
or forge one, and a signed request can be reused for 5 minutes (a value-less action has no sealed
authorization to claim) — see \`gateway/README.md\`.`
  : `**Without MetaMynd, you can be bypassed.** \`guard.guardTool()\` wraps the tool in the SAME process as
the check itself: a client-side convenience, not a boundary. Anything able to call \`performAction()\`
directly gets the same result the gate would have given it. If this tool ever holds a real credential,
re-scaffold without \`--no-gateway\` so it lives behind a separate process instead.`}

Full integration guide: \`docs/integration/INTEGRATE-WITH-METAMYND.md\`.
`;
}

function examplePackageJson(slug, neutral = false) {
  return JSON.stringify(
    {
      name: slug,
      version: '0.1.0',
      private: true,
      type: 'module',
      // `verify` is scaffolded in because governance that lives only in a dashboard is a
      // thing someone has to remember to look at. As a build step it is a control: a change
      // that widens this agent's authority fails `npm test`.
      scripts: { start: 'node index.mjs', test: neutral ? 'agentsafe-guard verify --context ./verify-context.json' : 'agentsafe-guard verify' },
      dependencies: { [GUARD_PKG]: GUARD_VERSION },
    },
    null,
    2,
  ) + '\n';
}

function exampleReadme(slug, scope, withGateway, gatewayPort, daemonKey = false) {
  const configFileLine = daemonKey
    ? `- \`agent.metamynd.json\` — your portable guard config (identity, mandate scope \`${scope}\`, issuer keys).
  **Holds no secret key.** Signing goes through your already-running agentsafe-signer daemon
  (\`daemonSocketPath\`) instead — see \`docs/integration/INSTALL-AGENTSAFE-SIGNER.md\`.${withGateway ? ' Payload binding is on by default and signs through the daemon too, which needs agentsafe-signer 0.15.0 or later.' : ''}`
    : `- \`agent.metamynd.json\` — your portable guard config (identity, mandate scope \`${scope}\`, issuer keys).
  **Contains the agent's secret key — never commit it.** It is already in \`.gitignore\`.`;
  const gatewaySection = withGateway
    ? `## Run

Two processes — start the gateway first, in its own terminal:

\`\`\`bash
cd gateway && npm install && npm start   # the REAL enforcement boundary — see gateway/README.md
\`\`\`

Then, in this directory:

\`\`\`bash
npm install
npm start
\`\`\`

You should see an ALLOW (fulfilled by \`./gateway\`), a BLOCK (over the per-transaction cap), and
an ESCALATE (high risk). The BLOCK and ESCALATE never reach the gateway at all — this file's own
\`guard.guardTool()\` refuses them first. Only the ALLOW crosses into the other process.

## Files

${configFileLine}
- \`index.mjs\` — signs each request and calls \`./gateway\` for it; \`guard.guardTool()\` here is a
  fast local pre-check, not the enforcement boundary.
- \`gateway/\` — a **separate process**. It holds the real tool and independently re-verifies every
  request against this agent's own policy before running it. See \`gateway/README.md\` — read that
  one first if you're only going to read one.

## What this is not

`
    : `## Run

\`\`\`bash
npm install
npm start
\`\`\`

You should see an ALLOW, a BLOCK (over the per-transaction cap), and an ESCALATE (high risk).

## Files

${configFileLine}
- \`index.mjs\` — wraps a tool with \`guard.guardTool(...)\`; the tool only runs when the gate allows.

## What this is not

`;
  return `# ${slug}

A MetaMynd/AgentSafe-governed agent, scaffolded with \`create-metamynd-agent\`.

${gatewaySection}${
    withGateway
      ? `**With MetaMynd's gateway, you can't be bypassed** — that's what this section is about.
This scaffold's default shape (agent + separate gateway process, port ${gatewayPort} by default)
is the actual enforcement boundary: \`guard.guardTool()\` in \`index.mjs\` is a client-side
convenience, not a boundary — it still runs its handler in-process regardless of where the
decision came from. What actually stops direct-call and confused-deputy bypasses is that
\`bookFlight()\` itself only exists in \`./gateway\`, a process this one cannot reach into, which
independently re-verifies every request against this agent's own policy bundle AND binds it to
the actual body being executed. Replay and cumulative spend are closed too, via
\`requireAuthorization\` — see \`./gateway/README.md\`'s "What this closes, precisely" section for
exactly what that covers, including the one narrower gap disclosed there. Re-scaffold with
\`--no-gateway\` for the old single-process shape — it is NOT a separate enforcement boundary at
all; see its own generated README for why.`
      : `**Without MetaMynd, you can be bypassed** — this is that case. This scaffold has no
separate gateway process (either \`--sandbox\`, which never provisions real credentials, or
\`--no-gateway\` was passed): \`guard.guardTool()\` wraps a tool in the SAME process as the check
itself. That is a client-side convenience, not a boundary — it still runs your tool's handler
in-process regardless of where the decision came from, so anything able to call \`bookFlight()\`
directly gets the same result the gate would have given it. If this tool ever holds a real
credential, provision for real (drop \`--sandbox\`) without \`--no-gateway\` for the default
shape, which puts the tool behind a separate process instead. This is the same structural gap
\`--harness\`'s README documents, for the same reason: a cooperative in-process check has no
counterparty to disagree with a caller that skips it.`
  }

${clonedFreshSection(daemonKey)}

## Change the rules

Edit the agent's SOPs in the dashboard (Legal Entity → SOPs). The agent's behaviour changes live —
no redeploy. An \`escalate\` verdict is held for an owner to approve; poll \`guard.escalationStatus(id)\`.

Full integration guide: \`docs/integration/INTEGRATE-WITH-METAMYND.md\`.
`;
}

function gitignore() {
  return `node_modules/\nagent.metamynd.json\n.env\n`;
}

// ---------- the default hosted scaffold's second process: a separate tool gateway ----------
//
// Not a new protocol — @metamynd/agentsafe-mcp-guard (trustless verifyRequest, already public)
// and @metamynd/agentsafe-http-gateway (the generic reverse-proxy built on it, already public)
// do the real work. This just wires up the smallest useful shape: one protected route, one
// tool, re-verified independently of the agent that's calling it. See demo/duffel-mcp-gateway
// in the AgentSafe repo for the full pattern (mutual handshake, x402 payment, capability
// binding) this is a minimal slice of.

function gatewayServerFile(scope, port, apiBase, policyKey) {
  return `#!/usr/bin/env node
// gateway/server.mjs — the REAL enforcement boundary for this agent's tool(s).
//
// This is a SEPARATE process from the agent. It holds the tool's real credentials (the agent
// process never does), and it independently re-verifies every request against this agent's OWN
// published policy bundle — it does not trust the agent's own guard.guardTool() check. A
// compromised or dishonest agent calling its own local function gets nothing here, because
// there is no local function: the tool only runs in this process.
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { createMcpGuard } from '${MCP_GUARD_PKG}';
import { createHttpGateway } from '${GATEWAY_PKG}';

const PORT = Number(process.env.PORT || ${port});
const MAGP_API = process.env.MAGP_API || '${apiBase}';

// --- Your real tool. Real credentials (an airline API key, a payment key, ...) belong ONLY
// --- here, read from process.env (see .env.example) — never in the agent process.
async function bookFlight(args) {
  return { pnr: 'PNR-DEMO', ...args };
}

// One protected route: only a request signed by this agent, for exactly this action, and
// re-verified against this agent's own mandate/SOP, reaches bookFlight() below.
//
// valueFields is explicit on purpose, not left to the gateway's own default (which would be
// this exact list anyway): a route with a real amount/merchant should always say so itself,
// rather than relying on a library default to guess right. A route with NO value concept at
// all (a read, a status check) should set valueFields: [] instead — see the gateway's README.
//
// allowedFields is the COMPLETE list of top-level body keys bookFlight() reads. The gateway refuses
// every other key (PAYLOAD_UNBINDABLE) because nothing the agent signed covers it — that is what
// stops a request signed for $250 from carrying \`surcharge: 4750\` through to your tool. Add a key
// here only when your real tool reads it; things policy needs to see (a risk level) travel in the
// signed context, not the tool body.
const routes = [{ method: 'POST', path: '/book-flight', action: '${scope}', valueFields: ['amount', 'merchant'], allowedFields: ['amount', 'currency', 'merchant'] }];

// This gateway's OWN identity — separate from the agent's on purpose (an agent must not be able to
// release or lower-settle a hold it authorized itself; only the SERVICE that claimed it may). Real
// and registered as a trusted counterparty when \`npx create-metamynd-agent\` provisioned it (see
// README.md); a real serviceKey is what lets serviceAuthHeaders() sign an AUTHENTICATED claim
// (MAGP-SERVICE-v1) instead of relying on the bearer claimToken alone — required for a MAINNET
// hold (MAGP §8.7.10), and strictly better than an anonymous claim on testnet too.
const identity = JSON.parse(readFileSync(new URL('./service.metamynd.json', import.meta.url)));
//
// requireAuthorization: true is what closes replay and cumulative spend, not just per-request
// policy — it requires the agent's authorizationId (from a REAL guard.authorize() call) to
// atomically claim single-use execution against the issuer before this gateway runs the tool.
//
// policyPublicKey pins the bundle to MetaMynd's OWN signing key (from your provisioning response,
// baked in here — never fetched at runtime, so a compromised network can't swap it out alongside a
// forged bundle). Without it, verifyBundle() never runs at all: an attacker who can intercept the
// fetch to \`\${MAGP_API}/policy/bundle/...\` — a MITM, a compromised DNS/proxy — can hand this gateway
// a bundle with a higher cap or no rules, and it would be trusted the same as the real one.
const guard = createMcpGuard({ serviceDid: identity.serviceDid, serviceKey: identity.serviceKey ?? undefined, issuerApi: MAGP_API, requireAuthorization: true${policyKey ? `, policyPublicKey: '${policyKey}'` : ''} });

const gateway = createHttpGateway({
  guard,
  routes,
  // Payload binding (MAGP 8.3.9): the agent signs a digest of the WHOLE body, this gateway digests the body it is about to
  // run, and the issuer refuses the claim unless the two are the digest the agent signed at authorize time. allowedFields
  // above lists which keys may appear; this makes the VALUES of every one of them (a payee, a passenger list) the agent's too.
  // A request whose authorization bound no payload is refused (PAYLOAD_BINDING_REQUIRED) rather than run unbound.
  requirePayloadBinding: true,
  forward: async (req) => {
    let args = {};
    try { args = JSON.parse(req.rawBody?.toString('utf8') || '{}'); } catch { /* empty body */ }
    const result = await bookFlight(args);
    return { status: 200, body: result };
  },
  // This gateway IS the tool, not a proxy in front of one — an unmatched path has nothing to
  // pass through TO. Without this, any path a route doesn't match falls through ungoverned
  // straight to forward() above, which would run bookFlight() with no check at all.
  denyByDefault: true,
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const rawBody = await readBody(req);
    const result = await gateway({ method: req.method, path: req.url, headers: req.headers, rawBody });
    const headers = { 'content-type': 'application/json' };
    if (result.governance) headers['x-agentsafe-decision'] = result.governance.decision;
    res.writeHead(result.status, headers);
    res.end(JSON.stringify(result.body ?? {}));
  } catch (err) {
    // Fail CLOSED on any gateway error.
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: 'block', reasonCode: 'GATEWAY_ERROR', error: String(err?.message ?? err) }));
  }
});

server.listen(PORT, () => {
  console.log('[gateway] listening on :' + PORT + ' -> the only place bookFlight() runs.');
  console.log('[gateway] every request is independently re-verified against this agent\\'s own policy.');
});
`;
}

function gatewayPackageJson(slug) {
  return JSON.stringify(
    {
      name: slug + '-gateway',
      version: '0.1.0',
      private: true,
      type: 'module',
      scripts: { start: 'node server.mjs' },
      dependencies: { [MCP_GUARD_PKG]: MCP_GUARD_VERSION, [GATEWAY_PKG]: GATEWAY_VERSION },
    },
    null,
    2,
  ) + '\n';
}

function gatewayEnvExample() {
  return `# Real tool credentials belong HERE, read from process.env in server.mjs — never in the
# agent process one directory up.
# AIRLINE_API_KEY=
`;
}

function gatewayGitignore() {
  return `node_modules/\n.env\nservice.metamynd.json\n`;
}

function gatewayReadme(slug, scope, port) {
  return `# ${slug}-gateway

**With MetaMynd, you can't be bypassed.** This process is why. It is the **real enforcement
boundary** for \`${slug}\`'s tool(s) — not \`../index.mjs\`. See
[What this closes, precisely](#what-this-closes-precisely) below for exactly what that covers.

## Why this exists

\`guard.guardTool()\` in the agent's \`index.mjs\` is a client-side convenience: it gives fast,
local ALLOW/BLOCK/ESCALATE feedback, but it still runs its handler in the SAME process
regardless of where that decision came from. Anything able to call the agent's tool function
directly — a bug, a compromised dependency, a dishonest fork of the agent's own code — gets the
same result the gate would have given it. That is not a defect in \`guardTool()\`; a cooperative
in-process check has no counterparty to disagree with a caller that skips it. See \`--harness\`'s
own README for the same structural point in the free local-demo mode.

This process closes that gap by being a **separate** one. The agent has no way to reach into it
and call \`bookFlight()\` directly, because \`bookFlight()\` doesn't exist in the agent's process —
it exists only here, and every request that reaches it has already been independently
re-verified against this agent's OWN published policy bundle, fetched over the network by THIS
process, not trusted from the agent's say-so — AND bound to the actual body being executed
(payload binding) AND to a real, single-use, stateful authorization (\`requireAuthorization\`) —
see below for what each of those means precisely.

## Run

\`\`\`bash
npm install
npm start
\`\`\`

Listens on \`:${port}\` by default (\`PORT\` env var to change it — keep \`../index.mjs\`'s
\`GATEWAY_URL\` in sync if you do).

## Add real credentials

Edit \`server.mjs\`'s \`bookFlight()\` with your real implementation, reading any credentials it
needs from \`process.env\` (see \`.env.example\`). Load \`.env\` however you prefer (e.g.
\`node --env-file=.env server.mjs\`, Node ≥ 20.6) — it is already in \`.gitignore\`. The agent
directory one level up must never hold these credentials; if it needs to call a DIFFERENT tool,
add another protected route here rather than adding a local function back in \`index.mjs\`.

## Files

- \`server.mjs\` — the gateway: one protected route (\`POST /book-flight\`, action \`${scope}\`),
  \`@metamynd/agentsafe-mcp-guard\`'s \`verifyRequest()\` re-checking every request, and the real
  \`bookFlight()\`.
- \`service.metamynd.json\` — this gateway's OWN identity (\`serviceDid\`/\`serviceKey\`), gitignored
  like \`agent.metamynd.json\` one directory up. \`npx create-metamynd-agent\` generated it and
  registered its DID as a trusted counterparty (see "Who may claim this agent's holds" below); a
  clone needs its own, the same way it needs its own \`agent.metamynd.json\`.
- \`.env.example\` — where real tool credentials go (copy to \`.env\`, fill in, never commit).

## What this closes, precisely

Four independent checks, each closing a different bypass an agent (or anything able to call its
own code, or a network attacker) might attempt:

- **Direct call.** \`bookFlight()\` doesn't exist in the agent's process. There's nothing to call.
- **Forged policy bundle.** \`server.mjs\` bakes in \`policyPublicKey\` (from your provisioning
  response) and refuses an unsigned or tampered bundle outright — a party that can intercept the
  fetch (a MITM, a compromised DNS/proxy) cannot hand this gateway a bundle with a higher cap or
  no rules and have it trusted the same as the real one.
- **Confused deputy (payload).** The gateway re-verifies the signed request against this agent's
  own policy AND binds it to the actual request body (payload binding,
  \`@metamynd/agentsafe-http-gateway\` ≥ 0.4.5) — signing a cheap request while executing an
  expensive one is refused before the tool ever runs. This route's \`valueFields: ['amount',
  'merchant']\` (see \`server.mjs\`) is an explicit, server-controlled requirement, not a guess
  inferred from anything the signed request itself declares — that distinction is what closes
  the full history below, not just the most recent case in it. Earlier attempts checked
  progressively weaker versions of "is this real": 0.3.0 only refused a body offering NONE of
  the governed fields (a correct decoy in one field let the other hide nested, renamed, an
  array, or an entirely empty/non-JSON body); 0.4.0–0.4.2 required a field only when the
  SIGNED request's own value for it looked "real," which a signer could defeat by signing
  \`amount: 0\` — or, identically, by never signing an amount at all, since both verify against
  the exact same canonical message. \`valueFields\` moves the requirement to something the
  signer never controls at all.
- **Replay.** \`requireAuthorization: true\` (set in \`server.mjs\`) requires the agent's
  \`authorizationId\` — from a REAL \`guard.authorize()\` call, which \`index.mjs\` already makes for
  any value-bearing action by default — to atomically claim single-use execution against the
  issuer. A captured, replayed request fails the claim the second time.
- **Cumulative spend.** The same \`authorizationId\` only exists because the real stateful gate
  already checked it against the mandate's TOTAL budget when it was minted — not just this one
  request's amount. Many small legal-looking calls can't add up past the mandate cap this way,
  because each needed its own real authorization first.
- **Settlement (\`@metamynd/agentsafe-http-gateway\` ≥ 0.6.0).** A claimed hold stays against the
  mandate's cap until it is settled — it does NOT lapse after 15 minutes. So this gateway closes the
  hold it claimed once the upstream answers: a 2xx is captured at the authorized amount, and anything
  else (a rejection, a 5xx, a dropped connection) is parked as UNKNOWN so the spend stays committed.
  A rejected call therefore keeps its budget until it is reconciled; if a given upstream status
  guarantees nothing was executed, list it in \`releaseOnStatus\` on the route (e.g. \`[400, 422]\`) and
  the gateway will release that hold. Only the gateway that claimed the hold can do either — the agent
  cannot capture it lower or void it, which is what stopped it recovering the budget of a purchase it
  had just had executed.

### Who may claim this agent's holds

This gateway claims with its own real identity (\`service.metamynd.json\`, above) — not the agent's,
on purpose: an agent must never be able to release or lower-settle a hold it authorized itself. On
provisioning, \`npx create-metamynd-agent\` registered that DID as a trusted counterparty for you
(\`POST /policy/counterparties\`). A **MAINNET** hold is *always* registered-only, regardless of your
registry (MAGP §8.7.10) — a testnet hold stays open unless you have registered anything at all.
Manage the registry at \`/dashboard/counterparties\`, or:

\`\`\`bash
curl -X POST $MAGP_API/policy/counterparties \\
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{ "did": "'"$(node -e "console.log(JSON.parse(require('fs').readFileSync('./service.metamynd.json')).serviceDid)")"'", "confirmEnforcementChange": true }'
\`\`\`

\`confirmEnforcementChange: true\` is required only for your account's FIRST-EVER registration —
it switches EVERY one of your holds (not just this agent's) from open to registered-only, so the
API refuses a first registration without it.
- **Amount unknown.** \`amount-unknown\` (\`@metamynd/agentsafe-mcp-guard\` ≥ 0.3.0) blocks a
  platform tool by default when its raw bytes or a nested payload hide the amount from a naive
  spend cap — AND this agent's OWN starter SOP (see \`agent.metamynd.json\` /
  \`harness-rules.json\`) puts the same check ahead of its per-transaction cap. That second part
  didn't used to be true: the SOP only ever authored \`amount-over\`, which silently does not fire
  on a missing or string amount, so either one slipped the cap untested — the atom existing
  wasn't the gap, this template never authoring it was.

The claim above also checks the claimed authorization's own \`agentDid\`/\`amount\`/\`currency\`/
\`merchant\` against the request actually being executed (\`@metamynd/agentsafe-mcp-guard\` ≥ 0.2.1)
— a same-amount, same-currency authorization legitimately obtained for one merchant cannot unlock
a booking with a different one; that gap was found while building this and closed, not left open.
See \`@metamynd/agentsafe-mcp-guard\`'s own README (\`requireAuthorization\`) for the full mechanism,
and \`demo/duffel-mcp-gateway\` in the AgentSafe repo for the fuller pattern this is a slice of
(mutual DID handshake, x402 payment binding, commitment-bound capability tokens).
`;
}

function writeFileSafe(dir, name, content, force = false, mode) {
  const p = join(dir, name);
  const exists = existsSync(p);
  if (exists && !force) { console.log(`  ${c.yellow('skip')}  ${name} ${c.dim('(exists)')}`); return; }
  // `mode` (e.g. 0o600 for a private-key-bearing file) only narrows perms at CREATE time —
  // writeFileSync ignores its own `mode` option on an existing file, so an --force overwrite
  // needs an explicit chmod or a stale world-readable mode from the file's first creation
  // would otherwise survive untouched.
  writeFileSync(p, content, mode !== undefined ? { mode } : undefined);
  if (mode !== undefined) chmodSync(p, mode);
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

/**
 * Write the scaffolded project + print next steps. Shared by the provision and sandbox paths.
 * `withGateway`: scaffold the default two-process shape (agent + ./gateway) — the real
 * enforcement boundary. Off for --sandbox (shared demo identity, never real credentials
 * anyway) and --no-gateway (opt out, e.g. you're already running your own separate gateway).
 */
// `demo` (from buildPolicyCases) selects the NON-financial project; without it this is the historical
// payment scaffold. `merchant` defaults to a payment demo's merchant only in that financial branch.
function scaffoldProject({ outDir, config, slug, scope, perTxnMax, currency = 'USD', merchant, sandbox, withGateway, gatewayPort = DEFAULT_GATEWAY_PORT, force = false, demo = null, gatewayIdentity = null }) {
  const neutral = !!demo;
  assertScaffoldTarget(outDir, force);
  console.log(`\n  ${c.b('Scaffolding')} ${c.dim(outDir)}`);
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  writeFileSafe(outDir, 'agent.metamynd.json', JSON.stringify(config, null, 2) + '\n', force, 0o600);
  const paymentMerchant = merchant ?? 'skyward-air';
  writeFileSafe(
    outDir,
    'index.mjs',
    neutral
      ? exampleIndexNeutral({ scope, gatewayPort: withGateway ? gatewayPort : null, demo, merchant })
      : withGateway
        ? exampleIndex(scope, perTxnMax, gatewayPort, currency, paymentMerchant)
        : exampleIndexNoGateway(scope, perTxnMax, currency, paymentMerchant),
    force,
  );
  writeFileSafe(outDir, 'package.json', examplePackageJson(slug, neutral), force);
  writeFileSafe(outDir, '.gitignore', gitignore(), force);
  writeFileSafe(
    outDir,
    'README.md',
    neutral
      ? exampleReadmeNeutral(slug, scope, withGateway, gatewayPort, config.keyProvider === 'daemon', demo)
      : exampleReadme(slug, scope, withGateway, gatewayPort, config.keyProvider === 'daemon'),
    force,
  );
  // `npm test` (agentsafe-guard verify --context) needs the request inputs of a compliant request:
  // a policy that requires evidence/consent blocks a bare baseline request and reads as broken.
  if (neutral) {
    const context = { ...(demo.cases[0]?.context ?? {}) };
    // verify's baseline sends riskLevel "low" unless told otherwise. A rule whose threshold IS "low"
    // would block that, so when the rules read riskLevel and the passing request has none, say
    // "no risk level" explicitly (null never fires a risk rule).
    if (demo.inputs.some((i) => i.field === 'riskLevel') && !('riskLevel' in context)) context.riskLevel = null;
    writeFileSafe(outDir, 'verify-context.json', JSON.stringify(context, null, 2) + '\n', force);
  }

  if (withGateway) {
    const apiBase = config.apiBase ?? config.api ?? DEFAULT_API;
    // The key that signs every policy bundle (magp.policy-signer.ts) — present on every provisioning
    // response that talks to a real backend (full account, sandbox, delegated-claim). Baked into the
    // generated gateway so it pins the bundle rather than trusting whatever the fetch returns; absent
    // only for a config predating this field (an older scaffold's saved agent.metamynd.json), where
    // the generated gateway is unchanged from before rather than baking in nothing and crashing.
    const policyKey = config.issuer?.policyKey ?? null;
    const gwDir = join(outDir, 'gateway');
    if (!existsSync(gwDir)) mkdirSync(gwDir, { recursive: true });
    if (!neutral) {
      // The gateway's OWN identity — the one that claims and settles this agent's holds (MAGP §8.7.6/
      // §8.7.10), separate from the agent's own DID on purpose (an agent must not be able to release or
      // lower-settle a hold it authorized itself). `gatewayIdentity` is real and registered when the
      // caller generated + registered one (main()'s hosted-financial path); a caller that didn't
      // (an older code path, or a direct scaffoldProject() call in a test) falls back to the historical
      // non-cryptographic placeholder — same shape as before this field existed, still parses and runs,
      // just unable to claim a MAINNET hold or sign an authenticated claim on any network.
      const identity = gatewayIdentity ?? { did: `did:local:${scope}-gateway`, keyHex: null };
      writeFileSafe(gwDir, 'service.metamynd.json', JSON.stringify({ serviceDid: identity.did, serviceKey: identity.keyHex }, null, 2) + '\n', force, 0o600);
    }
    writeFileSafe(gwDir, 'server.mjs', neutral ? gatewayServerFileNeutral(scope, gatewayPort, apiBase, policyKey) : gatewayServerFile(scope, gatewayPort, apiBase, policyKey), force);
    writeFileSafe(gwDir, 'package.json', gatewayPackageJson(slug), force);
    writeFileSafe(gwDir, '.env.example', neutral ? gatewayEnvExampleNeutral() : gatewayEnvExample(), force);
    writeFileSafe(gwDir, '.gitignore', gatewayGitignore(), force);
    writeFileSafe(gwDir, 'README.md', neutral ? gatewayReadmeNeutral(slug, scope, gatewayPort) : gatewayReadme(slug, scope, gatewayPort), force);
  }

  const rel = outDir.replace(resolve('.'), '.').replace(/\\/g, '/');
  console.log(`\n${c.green(c.b('  ✓ Done.'))} Your governed agent is ready.\n`);
  if (sandbox) {
    console.log(`  ${c.dim('Shared sandbox agent — for trying MetaMynd only. Provision your own (drop --sandbox) for anything real.')}\n`);
  } else if (config.keyProvider === 'daemon') {
    console.log(`  ${c.dim('agent.metamynd.json holds no secret key — signing goes through your agentsafe-signer daemon at')} ${c.b(config.daemonSocketPath)}${c.dim('.')}\n`);
  } else if (config.agentKey) {
    console.log(`  ${c.yellow('⚠ agent.metamynd.json holds the agent secret key')} — it is gitignored; never commit it.\n`);
  }
  if (withGateway) {
    console.log(`  ${c.yellow('⚠ two processes now')} — \`gateway/\` is the real enforcement boundary, not \`index.mjs\`. Read \`gateway/README.md\`.\n`);
  }
  console.log(`  Next:`);
  if (withGateway) {
    console.log(c.cyan(`    cd ${rel}/gateway && npm install && npm start`) + c.dim('   (separate terminal — start this first)'));
  }
  console.log(c.cyan(`    cd ${rel}`));
  console.log(c.cyan(`    npm install`));
  // The example runs FOUR attempts. This summary promised three, so the one carrying the
  // whole argument — the agent asking to raise its own limit — arrived unannounced.
  if (neutral) {
    console.log(c.cyan(`    npm start`) + c.dim(`   → ${demoOutcomes(demo)}\n`));
  } else {
    console.log(c.cyan(`    npm start`) + c.dim('   → ALLOW · BLOCK (over cap) · ESCALATE (high risk)'));
    console.log(c.dim('                 · BLOCK (the agent asking to raise its OWN limit)\n'));
  }
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
  // The same decision --harness and the hosted flow make, so one policy file scaffolds the same shape everywhere.
  const fileConfig = typeof args.config === 'string' ? loadConfigFile(args.config) : null;
  if (fileConfig) console.log(`  ${c.green('✓')} loaded policy config ${c.dim(args.config)}`);
  const { financial } = announceFinancial(args, fileConfig);
  warnRulesNotApplied(fileConfig, 'the shared sandbox agent');
  if (!financial && typeof fileConfig?.scope === 'string' && fileConfig.scope !== 'perform-action') {
    console.log(`  ${c.yellow('!')} the scope "${fileConfig.scope}" in the config file is not used: the shared sandbox agent's scope is "perform-action".`);
  }
  console.log(c.dim(`  → requesting a ${financial ? '' : 'non-financial '}sandbox agent from ${base} …`));
  const provisioned = await apiPost(base, '/onboarding/sandbox', financial ? {} : { financial: false }, null);
  const config = provisioned?.data;
  if (!config?.agentDid) fail('Sandbox did not return a config with an agentDid.');
  // A server that predates the non-financial sandbox agent ignores the field and returns the shared PAYMENT agent.
  // Scaffolding a payment-free project on top of it would hand out spend authority nobody asked for: stop.
  if (!financial && config.financial !== false) {
    fail('This server does not offer a non-financial sandbox agent yet: it returned an agent that has spend limits. Use --harness for a free local demo, or provision your own agent (drop --sandbox).');
  }
  console.log(`  ${c.green('✓')} sandbox agent ${c.b(config.agentDid)} ${c.dim('(shared test identity)')}`);
  if (!financial) {
    scaffoldProject({ demo: defaultNeutralDemo(), outDir, config, slug: 'metamynd-sandbox', scope: config.mandate?.scope || 'perform-action', sandbox: true, withGateway: false, force: !!args.force });
    return;
  }
  const scope = config.mandate?.scope || 'flight-purchase';
  const perTxnMax = Number(config.perTxnMax) || 500;
  scaffoldProject({ outDir, config, slug: 'metamynd-sandbox', scope, perTxnMax, sandbox: true, withGateway: false, force: !!args.force });
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
 *  to a freshly-provisioned one before anyone edits either.
 *
 *  `amount-unknown` first matters MORE here than on the hosted path: evaluateLocally() runs
 *  entirely client-side with no schema boundary in front of it, so nothing stops a caller from
 *  passing amount: "5000" (a string) or omitting amount entirely — `amount-over` silently does
 *  not fire on either (`typeof c.amount === 'number'` is false), so the cap passes untested,
 *  not safe. Ordering amount-unknown first blocks that instead of letting it through.
 *
 *  The per-transaction cap is scoped to `currency` (atom-catalog.ts's `amount-over` currency
 *  config), mirroring the hosted default exactly — see mandate-eval.ts for why an
 *  unscoped numeric cap can be cleared just by naming a different currency. The atom's
 *  `currency` config is declared `type: 'string[]'` (always an array, e.g. `['USD']`, never
 *  a bare string — see atom-catalog.ts's own field doc); `harnessMandate` below correctly
 *  passes the bare string straight through to the ODRL `unit` field, which is a DIFFERENT,
 *  genuinely string-or-array field — the two must not be confused (see the backend's own
 *  currencyScopeFor/currencyUnitFor split in currency-unit.ts for the same distinction). */
function harnessDefaultSop(perTxnMax, currency) {
  return {
    molecules: [
      { id: 'amount-known', name: 'Amount must be determinable', combinator: 'any', atoms: [{ id: 'a0', predicate: 'amount-unknown' }], decision: 'block', reasonCode: 'AMOUNT_NOT_DETERMINABLE' },
      { id: 'cap', name: 'Per-transaction cap', combinator: 'any', atoms: [{ id: 'a1', predicate: 'amount-over', config: { limit: perTxnMax, currency: [currency] } }], decision: 'block', reasonCode: 'SOP_SPEND_CAP' },
      { id: 'review', name: 'High-risk review', combinator: 'any', atoms: [{ id: 'a2', predicate: 'risk-at-or-above', config: { level: 'high' } }], decision: 'escalate', reasonCode: 'RISK_REVIEW' },
    ],
  };
}

/** The default SOP for a NON-financial agent: nothing about amounts (an `amount-unknown` block
 *  would refuse every action that carries no amount — i.e. all of them), just the amount-free
 *  high-risk review. The caller's own rules replace this whenever a config file supplies any. */
function harnessDefaultSopNeutral() {
  return {
    molecules: [
      { id: 'review', name: 'High-risk review', combinator: 'any', atoms: [{ id: 'a2', predicate: 'risk-at-or-above', config: { level: 'high' } }], decision: 'escalate', reasonCode: 'RISK_REVIEW' },
    ],
  };
}

/** Mirrors issueMandate()'s document shape in backend/src/features/policy/mandate/mandate.service.ts
 *  (minus the parts only a real principal/issuer can do: no VC, no Hedera anchor, no signature) —
 *  same shape evaluateMandate() in policy-core.mjs expects either way.
 *  `financial: false` adds NO spend constraint at all (mirrors onboarding.provision.ts, where
 *  omitting currency/maxAmount/perTxnMax together is a non-financial mandate). */
function harnessMandate({ scope, currency, maxAmount, perTxnMax, merchants, financial = true }) {
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
          ...(financial
            ? [
                { leftOperand: 'mm:payAmount', operator: 'lteq', rightOperand: perTxnMax, unit: currency },
                { leftOperand: 'mm:cumulativeSpend', operator: 'lteq', rightOperand: maxAmount, unit: currency },
              ]
            : []),
          ...(merchants?.length ? [{ leftOperand: 'mm:merchant', operator: 'isAnyOf', rightOperand: merchants }] : []),
        ],
      },
    ],
  };
}

/** A genuine did:key — self-certifying (the verification key is embedded in the DID itself,
 *  §4.1.2), clearly NOT a did:hedera (never resolved against Hedera, never anchored) but still
 *  a REAL, resolvable DID: any MAGP verifier can check a signature against it completely
 *  offline. This matters once --gateway is on (below): the harness's second local process
 *  verifies the agent's requests via key-in-DID, exactly like a real did:hedera counterparty
 *  would, just with no chain underneath it. */
function harnessAgentDid(publicKeyHex) {
  return buildDidKey(rawPublicKeyFromSpkiHex(publicKeyHex));
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

// ---------- --harness --gateway: a second local process, still zero network -----------------
//
// Everything above is ONE process: guardToolLocal() decides, and the SAME process holds the
// tool. "Without MetaMynd, you can be bypassed" (the harness README says so directly) — call
// bookFlight() instead of gatedBookFlight() and nothing stops you, because there is no
// counterparty in the loop to disagree with you.
//
// --gateway adds one: a SEPARATE local process, using the real @metamynd/agentsafe-mcp-guard
// (the same package a production Service uses), that independently re-verifies every signed
// request against the SAME metamynd-rules.json — not by trusting the agent process, by
// checking the Ed25519 signature itself via the agent's did:key (key-in-DID, §4.1.2, fully
// offline). Still no account, still no network call, still free.
//
// What this DOES close: the agent process lying to itself. A compromised or dishonest agent
// that skips its own guardToolLocal() call, or calls bookFlight() directly, gets nothing —
// the tool only runs in the gateway process now.
//
// Replay of the SAME signed request is refused too (REPLAY_DETECTED): the gateway remembers each nonce for as long as
// the guard would accept it, in memory (a restart forgets them). An independent tester's rerun (2026-09-24) found the
// same bytes accepted twice before this.
//
// What this does NOT close (be precise, this is a local demo, not the hosted platform):
// cumulative spend across many DIFFERENT calls. That needs a STATEFUL authority — the hosted gate's
// `requireAuthorization` claims a real, single-use authorizationId against a database and holds the budget there. A
// local harness has no such database (that is the whole point of --harness). The README says so.

function harnessGatewayServerFile(scope, gatewayPort, agentDid, neutral = false) {
  return `#!/usr/bin/env node
// harness-gateway.mjs — a SEPARATE process from your agent. It holds the tool (${neutral ? 'the action below' : 'bookFlight below'}
// never runs anywhere else) and independently re-verifies every request against
// ../metamynd-rules.json using the REAL @metamynd/agentsafe-mcp-guard — the same package a
// production Service uses, just pointed at a local file instead of a hosted issuer.
//
// There is NO enforcement logic of your own in this file. Routing, payload binding and the
// deny-by-default posture come from @metamynd/agentsafe-http-gateway — the same component the
// hosted scaffold uses — so what it refuses is what production refuses: a body that does not match
// what the agent signed (PAYLOAD_NOT_BOUND), a value it cannot find (PAYLOAD_UNBINDABLE), and any
// top-level key you did not list in allowedFields. See ../README.md#--gateway for what this closes.
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { createMcpGuard } from '${MCP_GUARD_PKG}';
import { createHttpGateway } from '${GATEWAY_PKG}';
import { matchRoute } from '${GATEWAY_PKG}/route-match';

const PORT = Number(process.env.PORT || ${gatewayPort});
// The agent's did:key, fixed at scaffold time — a request claiming to be any OTHER agentDid
// fails BUNDLE_SUBJECT_MISMATCH, not just an unmatched-signature error, because the bundle
// this gateway serves is only ever this one agent's.
const AGENT_DID = '${agentDid}';

// Reshapes the harness's own rules-file shape ({mandate, sops:[{standardKey,document}],
// standards:[{standardKey,document}]}) into what agentsafe-mcp-guard's verifyRequest expects
// ({mandates:[{action,document}], sops:[{id,document}], standards:[{key,document}]}) — a pure
// format adapter, not a second source of truth: both this and index.mjs's dashboard read the
// SAME ../metamynd-rules.json.
function bundleFromRules(rules) {
  return {
    mandates: [{ action: '${scope}', document: rules.mandate }],
    sops: (rules.sops ?? []).map((s) => ({ id: s.standardKey, document: s.document })),
    standards: (rules.standards ?? []).map((s) => ({ key: s.standardKey, document: s.document })),
  };
}

// No serviceKey: this gateway only calls verifyRequest() (re-check a signed request), not the
// mutual-handshake methods, which are the only thing that needs one. No issuerApi either — the
// whole point of --harness is no network; fetchBundle reads the SAME rules file the dashboard
// and your agent process both read, so editing it takes effect on the next request everywhere.
const guard = createMcpGuard({
  serviceDid: 'did:local:${scope}-gateway',
  fetchBundle: async (agentDid) => {
    if (agentDid !== AGENT_DID) return { subject: AGENT_DID, mandates: [], sops: [], standards: [] };
    const rules = JSON.parse(readFileSync('../metamynd-rules.json', 'utf8'));
    return { subject: AGENT_DID, ...bundleFromRules(rules) };
  },
});

// One protected route per gated action in index.mjs. This gateway IS the tool, not a proxy in
// front of one, so a path with no route below is refused (denyByDefault) — nothing to fall through TO.
//
//   valueFields   the fields the SIGNATURE covers that this route's body must carry and match
//   allowedFields the COMPLETE list of top-level body keys the tool reads. Anything else is refused,
//                 because nothing signed covers it. Add a key here only when your tool reads it.
const ROUTES = [
  ${neutral
    ? `{ method: 'POST', path: '/perform', action: '${scope}', valueFields: [], allowedFields: [], run: async () => ({ done: true, action: '${scope}' }) },`
    : `{ method: 'POST', path: '/book-flight', action: '${scope}', valueFields: ['amount', 'merchant'], allowedFields: ['amount', 'currency', 'merchant'], run: async (args) => ({ pnr: 'PNR-DEMO', ...args }) },`}
  { method: 'POST', path: '/raise-limit', action: 'permissions.update', valueFields: [], allowedFields: ['amount', 'currency', 'merchant'], run: async (args) => ({ updated: true, ...args }) },
];

const gateway = createHttpGateway({
  guard,
  routes: ROUTES,
  denyByDefault: true,
  // Payload binding (MAGP 8.3.9): the agent signs a digest of the WHOLE body and this gateway refuses to run a tool on a
  // body that is not exactly that one — the values of every allowed field, not only amount and merchant. A request that
  // bound no payload is refused (PAYLOAD_BINDING_REQUIRED) instead of run unbound.
  requirePayloadBinding: true,
  // Reached ONLY after the guard allowed the request AND the body was bound to what was signed.
  forward: async (req) => {
    const route = matchRoute(ROUTES, req.method, req.path);
    let args = {};
    try { args = JSON.parse(req.rawBody?.toString('utf8') || '{}'); } catch { /* empty body */ }
    return { status: 200, body: await route.run(args) };
  },
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Replay: every signed request carries a fresh nonce, and the guard refuses one more than 5 minutes old. So a nonce
// only has to be remembered for that long to refuse the SAME signed request twice. Checked and recorded in one
// synchronous step, before anything awaits, so two simultaneous copies cannot both get through. In memory: restarting
// this process forgets it (a replay inside the 5-minute window after a restart is not caught). Cumulative spend across
// many DIFFERENT requests is still not tracked here — that needs the hosted gate.
const NONCE_TTL_MS = 6 * 60 * 1000;
const seenNonces = new Map(); // agentDid|nonce -> expiry
function firstUseOfNonce(headers) {
  let signed;
  try { signed = JSON.parse(headers['x-magp-request'] ?? 'null'); } catch { return true; } // malformed: the guard refuses it
  if (!signed || typeof signed.nonce !== 'string') return true; // no nonce: the guard refuses it
  const now = Date.now();
  if (seenNonces.size > 10000) for (const [k, exp] of seenNonces) if (exp <= now) seenNonces.delete(k);
  const key = String(signed.agentDid) + '|' + signed.nonce;
  const exp = seenNonces.get(key);
  if (exp !== undefined && exp > now) return false;
  seenNonces.set(key, now + NONCE_TTL_MS);
  return true;
}

const server = http.createServer(async (req, res) => {
  try {
    const rawBody = await readBody(req);
    if (!firstUseOfNonce(req.headers)) {
      console.log('[harness-gateway] BLOCK ' + req.url + ' — REPLAY_DETECTED (this exact signed request already came through)');
      res.writeHead(403, { 'content-type': 'application/json', 'x-agentsafe-decision': 'block' });
      res.end(JSON.stringify({ decision: 'block', reasonCode: 'REPLAY_DETECTED' }));
      return;
    }
    const result = await gateway({ method: req.method, path: req.url, headers: req.headers, rawBody });
    const headers = { 'content-type': 'application/json' };
    const decision = result.governance?.decision;
    if (decision) headers['x-agentsafe-decision'] = decision;
    if (result.status === 200) console.log('[harness-gateway] ALLOW ' + req.url + ' — running the real tool here, not in the agent process');
    else console.log('[harness-gateway] ' + String(result.body?.decision ?? 'block').toUpperCase() + ' ' + req.url + ' — ' + (result.body?.reasonCode ?? 'refused') + ' (re-evaluated independently, did not trust the agent)');
    res.writeHead(result.status, headers);
    res.end(JSON.stringify(result.body ?? {}));
  } catch (err) {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: 'block', reasonCode: 'GATEWAY_ERROR', error: String(err?.message ?? err) }));
  }
});

server.listen(PORT, () => {
  console.log('[harness-gateway] listening on :' + PORT + ' — the only place your tools run.');
  console.log('[harness-gateway] re-verifying against ../metamynd-rules.json, independently of index.mjs.');
});
`;
}

function harnessGatewayPackageJson(slug) {
  return JSON.stringify(
    { name: slug + '-harness-gateway', version: '0.1.0', private: true, type: 'module', scripts: { start: 'node harness-gateway.mjs' }, dependencies: { [MCP_GUARD_PKG]: MCP_GUARD_VERSION, [GATEWAY_PKG]: GATEWAY_VERSION } },
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
    case 'amount-unknown': return \`transaction amount must be a real, determinable number\`;
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

function harnessIndexFile(scope, perTxnMax, port, withGateway, gatewayPort, currency, merchant) {
  const under = Math.max(1, Math.round(perTxnMax * 0.5));
  const over = Math.round(perTxnMax + 100);
  return `// index.mjs — your agent, governed entirely on this machine. No account, no network call
// for a decision: guardToolLocal() decides allow/block/escalate against ./metamynd-rules.json
// (edit it directly, or at the dashboard). An escalate is held here for YOU to approve —
// there is no hosted owner queue in this mode, so open the dashboard URL printed below.${withGateway ? `
// Your tools run in ./harness-gateway.mjs, a SEPARATE process — it independently re-verifies
// every signed request for itself. See README.md#--gateway for what that closes.` : ''}
import { readFileSync } from 'node:fs';
import { createGuard } from '${GUARD_PKG}';
import { startDashboard } from './harness-server.mjs';
${guardFreshnessCheck()}
${harnessConfigLoad()}
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
console.log('\\x1b[2m  dashboard: ' + dashboard.url + ' (rules, approvals, decision log)\\x1b[0m');
${withGateway ? `console.log('\\x1b[2m  gateway  : http://localhost:${gatewayPort} (a SEPARATE process — run \\'npm start\\' in ./harness-gateway first)\\x1b[0m\\n');` : `console.log('');`}

// Reads the CURRENT rules file fresh every call — editing it (by hand, or at the dashboard)
// takes effect on the next decision, no restart, matching the "no redeploy" experience the
// hosted platform gives you. The gateway process (below, when scaffolded) reads the SAME file.
const getBundle = () => JSON.parse(readFileSync('./metamynd-rules.json', 'utf8'));
${withGateway ? `
const GATEWAY = process.env.HARNESS_GATEWAY_URL || 'http://localhost:${gatewayPort}';
// Calls the gateway process instead of a local function — there is no raw bookFlight() or
// raiseOwnLimit() in THIS file to call directly. buildSignedRequest() is pure (no network, no
// issuer): it builds and signs the same canonical message a real gate would verify, entirely
// offline, using this agent's own did:key — the gateway verifies that signature for itself.
async function callGateway(path, action, args) {
  // The COMPLETE body the tool receives, signed as a payload (MAGP 8.3.9): the eight signed fields cover amount and merchant
  // only, and this gateway refuses to run the tool on a body that is not exactly the one signed here.
  const payload = { amount: args.amount, merchant: args.merchant, currency: args.currency ?? '${currency}' };
  const signed = await guard.buildSignedRequest({ action, amount: args.amount, currency: args.currency ?? '${currency}', merchant: args.merchant, context: { tool: '${scope}', riskLevel: args.riskLevel ?? 'low' }, payload });
  const res = await fetch(GATEWAY + path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-magp-request': JSON.stringify(signed) }, body: JSON.stringify(payload) });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error('gateway ' + res.status + ': ' + (body?.reasonCode ?? 'refused'));
    err.name = 'GovernanceBlocked';
    err.governance = { decision: body?.decision ?? 'block', reasonCode: body?.reasonCode ?? 'GATEWAY_ERROR' };
    throw err;
  }
  return body;
}
` : `
// --- Your real tool. Replace the body with your actual implementation. ---
async function bookFlight(args) {
  return { pnr: 'PNR-DEMO', ...args };
}
`}
// --- The GATED version. Register THIS with your agent instead of the raw handler. ---
const gatedBookFlight = guard.guardToolLocal(
  '${scope}',                                   // = your mandate scope
  ${withGateway ? `(args) => callGateway('/book-flight', '${scope}', args)` : 'bookFlight'},
  (a) => ({                                     // map tool args → gate inputs
    amount: a.amount,
    currency: a.currency ?? '${currency}',
    merchant: a.merchant,
    context: { tool: 'book-flight', riskLevel: a.riskLevel ?? 'low' },
  }),
  getBundle,
);

// --- A tool the agent was NEVER granted. Wrapping it is the demonstration: there is no
// --- rule anywhere forbidding this. The mandate simply never mentioned the action.${withGateway ? '' : `
async function raiseOwnLimit(args) {
  return { updated: true, ...args };          // never runs, and that is the point
}`}

const gatedRaiseOwnLimit = guard.guardToolLocal(
  'permissions.update',                       // an action NOT in the mandate
  ${withGateway ? `(args) => callGateway('/raise-limit', 'permissions.update', args)` : 'raiseOwnLimit'},
  (a) => ({ amount: a.amount, currency: a.currency ?? '${currency}', merchant: a.merchant, context: { tool: 'permissions-update' } }),
  getBundle,
);

const dim = (t) => '\\x1b[2m' + t + '\\x1b[0m';
const bold = (t) => '\\x1b[1m' + t + '\\x1b[0m';
const rule = (n) => '  ' + '-'.repeat(n);

const WHY = {
  AUTHORIZED: 'inside the mandate and under the SOP spend cap',
  SOP_SPEND_CAP: 'your SOP caps a single transaction at ${currency} ${perTxnMax}',
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
console.log(dim('  cap    ${currency} ${perTxnMax} per transaction, from ./metamynd-rules.json'));

console.log('');
console.log(rule(66));
await attempt(1, 'a ${currency} ${under} booking, low risk. Expected to pass.', '${scope}', { amount: ${under}, currency: '${currency}', merchant: '${merchant}', riskLevel: 'low' });
await attempt(2, 'a ${currency} ${over} booking, deliberately over the cap.', '${scope}', { amount: ${over}, currency: '${currency}', merchant: '${merchant}', riskLevel: 'low' });
await attempt(3, 'a ${currency} ${under} booking, but flagged high risk.', '${scope}', { amount: ${under}, currency: '${currency}', merchant: '${merchant}', riskLevel: 'high' });
await attempt(4, 'the agent stops booking flights and asks to raise its OWN limit.', 'permissions.update', { amount: 100000, currency: '${currency}', merchant: '${merchant}' }, gatedRaiseOwnLimit);
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
console.log('');${withGateway ? `
console.log(bold('  Checked twice, by two processes.') + ' bookFlight() lives in ./harness-gateway.mjs -');
console.log(dim('  not here. It independently re-verified every attempt above against the SAME'));
console.log(dim('  ./metamynd-rules.json, over a signed request, before running your tool.'));
console.log('');
console.log(dim('  It also refuses a replay of the same signed request. What --gateway does NOT close:'));
console.log(dim('  cumulative spend across many different calls. That needs a STATEFUL authority (the'));
console.log(dim('  hosted gate holds the budget in a database) - a local harness has none.'));
console.log(dim('  See README.md#--gateway for exactly what this does and does not prove.'));
console.log('');
console.log('  Edit ./metamynd-rules.json (or the dashboard) and run again - the outcome');
console.log(dim('  changes, in BOTH processes, from the one file. That is the point.'));
console.log('');
console.log(dim('  Ready for more than one machine, a queue someone else can approve from,'));
console.log(dim('  anchored evidence, KYC/KYB-backed identity, or nonce/cumulative-spend closure?'));
console.log(dim('  That is the hosted platform - drop --harness and provision there; the same'));
console.log(dim('  guardTool() call keeps working, sealed by a real gate instead of this file.'));` : `
console.log(bold('  Without MetaMynd, you can be bypassed.') + ' bookFlight() above runs in THIS');
console.log(dim('  process - call it directly instead of gatedBookFlight and nothing stops you.'));
console.log(dim('  --harness proves your policy logic; it does not enforce it against that.'));
console.log('');
console.log('  Edit ./metamynd-rules.json (or the dashboard) and run again - the outcome');
console.log(dim('  changes. This file does not. That is the point.'));
console.log('');
console.log(dim('  Ready for a SEPARATE process that closes the bypass above, still free and'));
console.log(dim('  local? Re-scaffold with --gateway. Ready for more than one machine, a queue'));
console.log(dim('  someone else can approve from, anchored evidence, or KYC/KYB-backed identity?'));
console.log(dim('  That is the hosted platform - drop --harness and provision there; the same'));
console.log(dim('  guardTool() call keeps working.'));`}
console.log('');
dashboard.close();
`;
}

/**
 * The harness entry point for a NON-financial agent (BR-006). Same machinery as harnessIndexFile —
 * guardToolLocal, the local dashboard, the optional gateway process — but nothing in it is about
 * flights or money: the action is the caller's own scope, and the steps are `demo.cases`, derived
 * from the caller's own rules (buildPolicyCases). Each step states what it expects and says so
 * when the evaluator disagrees, so editing the rules file visibly changes the outcome.
 */
function harnessIndexFileNeutral({ scope, port, withGateway, gatewayPort, demo, merchant }) {
  const steps = [
    ...demo.cases,
    { kind: 'block', intent: 'the agent asks to change its OWN permissions - an action nobody delegated. Expected to be blocked.', expect: 'block', reasonCode: 'NO_PERMISSION_FOR_ACTION', action: 'permissions.update', context: {} },
  ];
  return `// index.mjs — your agent, governed entirely on this machine. No account, no network call
// for a decision: guardToolLocal() decides allow/block/escalate against ./metamynd-rules.json
// (edit it directly, or at the dashboard). An escalate is held here for YOU to approve —
// there is no hosted owner queue in this mode, so open the dashboard URL printed below.
// The steps below were DERIVED FROM YOUR OWN RULES when this project was scaffolded: one request
// that should pass, and one per rule that should trip it. Nothing here is about payments.${withGateway ? `
// Your tool runs in ./harness-gateway/harness-gateway.mjs, a SEPARATE process — it independently
// re-verifies every signed request for itself. See README.md#--gateway for what that closes.` : ''}
import { readFileSync } from 'node:fs';
import { createGuard } from '${GUARD_PKG}';
import { startDashboard } from './harness-server.mjs';
${guardFreshnessCheck()}
${harnessConfigLoad()}
// 'local' as the api: guardToolLocal() never calls it. Kept required-but-unused rather than
// silently accepting no api at all, so a later switch to a real gate is one field, not a rewrite.
const guard = createGuard({ api: 'local', agentDid: config.agentDid, agentKey: config.agentKey });

const dim = (t) => '\\x1b[2m' + t + '\\x1b[0m';
const bold = (t) => '\\x1b[1m' + t + '\\x1b[0m';
const rule = (n) => '  ' + '-'.repeat(n);

const dashboard = startDashboard({
  port: ${port},
  agentDid: config.agentDid,
  scope: '${scope}',
  rulesPath: './metamynd-rules.json',
  logPath: './metamynd-harness.log.jsonl',
});
console.log(dim('  dashboard: ' + dashboard.url + ' (rules, approvals, decision log)'));
${withGateway ? `console.log(dim('  gateway  : http://localhost:${gatewayPort} (a SEPARATE process — run \\'npm start\\' in ./harness-gateway first)'));\nconsole.log('');` : `console.log('');`}

// Reads the CURRENT rules file fresh every call — editing it (by hand, or at the dashboard)
// takes effect on the next decision, no restart. The gateway process (when scaffolded) reads the SAME file.
const getBundle = () => JSON.parse(readFileSync('./metamynd-rules.json', 'utf8'));

// The request's own fields (consent, piiPresent, jurisdiction, ...) travel as the gate's \`context\`.
const MERCHANT = ${merchant ? JSON.stringify(merchant) : 'undefined'};
${withGateway ? `const GATEWAY = process.env.HARNESS_GATEWAY_URL || 'http://localhost:${gatewayPort}';
// Calls the gateway process instead of a local function — there is no raw performAction() in THIS
// file to call directly. buildSignedRequest() is pure (no network, no issuer): it signs the request
// offline with this agent's own did:key, and the gateway verifies that signature for itself.
async function callGateway(path, action, args) {
  // The body is empty on purpose (this tool reads nothing from it), and it is signed as the payload so the gateway can
  // require binding on every route: a body with anything in it is not the one signed (MAGP 8.3.9).
  const signed = await guard.buildSignedRequest({ action, merchant: MERCHANT, context: args, payload: {} });
  const res = await fetch(GATEWAY + path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-magp-request': JSON.stringify(signed) }, body: '{}' });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error('gateway ' + res.status + ': ' + (body?.reasonCode ?? 'refused'));
    err.name = 'GovernanceBlocked';
    err.governance = { decision: body?.decision ?? 'block', reasonCode: body?.reasonCode ?? 'GATEWAY_ERROR' };
    throw err;
  }
  return body;
}
` : `// --- Your real tool. Replace the body with your actual implementation. ---
async function performAction(args) {
  return { done: true, action: '${scope}' };
}
`}
// --- The GATED version. Register THIS with your agent instead of the raw handler. ---
const gatedAction = guard.guardToolLocal(
  '${scope}',                                   // = your mandate scope
  ${withGateway ? `(args) => callGateway('/perform', '${scope}', args)` : 'performAction'},
  (a) => ({ merchant: MERCHANT, context: a }),   // map tool args → gate inputs
  getBundle,
);

// --- An action the agent was NEVER granted. Wrapping it is the demonstration: no rule anywhere
// --- forbids it. The mandate simply never mentioned the action.${withGateway ? '' : `
async function changeOwnPermissions(args) {
  return { updated: true, ...args };          // never runs, and that is the point
}`}
const gatedChangeOwnPermissions = guard.guardToolLocal(
  'permissions.update',                       // an action NOT in the mandate
  ${withGateway ? `(args) => callGateway('/raise-limit', 'permissions.update', args)` : 'changeOwnPermissions'},
  (a) => ({ context: a }),
  getBundle,
);

const STEPS = ${JSON.stringify(steps, null, 2)};
const INPUTS = ${JSON.stringify(demo.inputs)};
const NOT_STAGED = ${JSON.stringify(demo.notDemonstrated)};

let waitedForApproval = false;
async function attempt(n, total, step) {
  const tool = step.action === 'permissions.update' ? gatedChangeOwnPermissions : gatedAction;
  const action = step.action ?? '${scope}';
  console.log('');
  console.log(bold('  Step ' + n + ' of ' + total) + ' - ' + step.intent);
  console.log(dim('     evaluating locally, no network call...'));
  let got;
  let g = {};
  try {
    await tool(step.context);
    got = 'allow';
    console.log('\\x1b[32m     ALLOWED\\x1b[0m  your tool ran');
  } catch (e) {
    g = e.governance ?? {};
    got = g.decision ?? 'error';
    if (g.decision === 'escalate') {
      console.log('\\x1b[33m     ESCALATED\\x1b[0m  held for you to approve - ' + g.reasonCode);
      const { id, promise } = dashboard.holdForApproval(action, step.context, g);
      console.log(dim('     open ' + dashboard.url + ' and click Approve/Deny (hold ' + id.slice(0, 8) + '…)'));
      // Wait for a human once, not once per escalation: a policy with several review rules would
      // otherwise sit for 20 seconds at each. The rest stay pending on the dashboard.
      if (!waitedForApproval) {
        waitedForApproval = true;
        const result = await Promise.race([promise, new Promise((r) => setTimeout(() => r('timeout'), 20000))]);
        if (result === 'timeout') console.log(dim('     still pending after 20s — this demo will not wait forever; the dashboard will.'));
        else console.log(dim('     ' + (result ? 'approved.' : 'denied.')));
      }
    } else {
      console.log('\\x1b[31m     BLOCKED\\x1b[0m  ' + (g.reasonCode ?? e.message));
      console.log(dim('     your tool never ran - the gate refused before execution.'));
    }
    dashboard.logDecision(action, step.context, g);
  }
  const asExpected = got === step.expect && (!step.reasonCode || g.reasonCode === step.reasonCode);
  if (asExpected) console.log(dim('     as expected.'));
  else console.log('\\x1b[33m     NOT AS EXPECTED\\x1b[0m  expected ' + step.expect + (step.reasonCode ? ' (' + step.reasonCode + ')' : '') + ' — ./metamynd-rules.json or this step has changed since scaffolding.');
}

console.log(bold('  What this simulation shows'));
console.log('');
console.log('  An agent should not be the thing that decides what it is allowed to do. Each step');
console.log('  below takes the SAME code path and the rules decide - on this machine, with no');
console.log('  network call. The steps come from YOUR rules in ./metamynd-rules.json.');
console.log('');
console.log(dim('  scope   ${scope}  (no spending authority - this agent does not move money)'));
console.log(dim('  inputs  the fields your application must supply for these rules to judge anything:'));
for (const i of INPUTS) console.log(dim('            ' + i.field + '  <-  ' + i.rules.join(', ')));
if (INPUTS.length) console.log(dim('          A missing field never trips an allow-list, consent or PII rule - supply it.'));
for (const n of NOT_STAGED) console.log(dim('  not staged  ' + n.rule + ' - ' + n.why));

console.log('');
console.log(rule(66));
for (let i = 0; i < STEPS.length; i++) await attempt(i + 1, STEPS.length, STEPS[i]);
console.log('');
console.log(rule(66));

console.log('');
console.log(bold('  What this proved'));
console.log('');
console.log(dim('   - one code path, several outcomes, decided with zero network calls.'));
console.log(dim('   - the last step needed no rule to stop it. The agent could not widen its own'));
console.log(dim('     authority, because it cannot name an action nobody delegated to it.'));
console.log(dim('   - a blocked or held call never reached your tool at all.'));
console.log(dim('   - every decision is in ./metamynd-harness.log.jsonl - yours, locally.'));
console.log('');${withGateway ? `
console.log(bold('  Checked twice, by two processes.') + ' Your tool lives in ./harness-gateway/harness-gateway.mjs -');
console.log(dim('  not here. It independently re-verified every step above against the SAME'));
console.log(dim('  ./metamynd-rules.json, over a signed request, before running your tool.'));
console.log(dim('  It enforces scope and identity firmly; the rule inputs above are NOT signed, so an'));
console.log(dim('  agent that can sign could omit or forge one and its rule would not fire.'));
console.log('');
console.log(dim('  It also refuses a replay of the same signed request (remembered in memory, so a restart'));
console.log(dim('  forgets). See README.md#--gateway for exactly what this does and does not prove.'));
console.log('');
console.log('  Edit ./metamynd-rules.json (or the dashboard) and run again - the outcome');
console.log(dim('  changes, in BOTH processes, from the one file. That is the point.'));` : `
console.log(bold('  Without MetaMynd, you can be bypassed.') + ' performAction() above runs in THIS');
console.log(dim('  process - call it directly instead of gatedAction and nothing stops you.'));
console.log(dim('  --harness proves your policy logic; it does not enforce it against that.'));
console.log('');
console.log('  Edit ./metamynd-rules.json (or the dashboard) and run again - the outcome');
console.log(dim('  changes. This file does not. That is the point.'));
console.log('');
console.log(dim('  Want a SEPARATE process that closes the bypass above, still free and local?'));
console.log(dim('  Re-scaffold with --gateway. Want more than one machine, a queue someone else can'));
console.log(dim('  approve from, or anchored evidence? That is the hosted platform - drop --harness.'));`}
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

function harnessReadme(slug, scope, port, withGateway, gatewayPort, demo = null) {
  // `demo` is set for a NON-financial scaffold (BR-006): the steps, inputs and any rule the demo
  // could not stage are the caller's own, so this README must not talk about spend limits/flights.
  const neutral = !!demo;
  const tool = neutral ? 'performAction' : 'bookFlight';
  const gatedTool = neutral ? 'gatedAction' : 'gatedBookFlight';
  return `# ${slug}

A free, local MetaMynd/AgentSafe governance harness — your own rules, your own identity,
decided entirely on this machine. No account, no network call for a decision.

## Run

\`\`\`bash
npm install${withGateway ? ' && (cd harness-gateway && npm install)' : ''}
${withGateway ? `(cd harness-gateway && npm start &)   # the second process, in the background\n` : ''}npm start
\`\`\`

${neutral
  ? (demo.cases.length
    ? `You should see an ALLOW, then one BLOCK or ESCALATE for each rule of yours the demo can stage
(an ESCALATE is held for you — open the dashboard to approve it), and finally a BLOCK for an
action outside the mandate entirely. Every step says what it expects and flags any surprise.`
    : `None of your rules could be staged in the demo (see below), so it shows only a BLOCK for an
action outside the mandate. Your rules are still enforced; see \`metamynd-rules.json\`.`)
  : `You should see an ALLOW, a BLOCK (over the per-transaction cap), an ESCALATE (high risk —
open the dashboard to approve it), and a BLOCK (an action outside the mandate entirely).`}

## Files

- \`agent.metamynd.json\` — your local identity: a generated Ed25519 keypair, and a REAL
  \`did:key\` (self-certifying — the verification key is embedded in the DID itself, so a
  signature against it is checkable completely offline). Not anchored to Hedera; that's the
  hosted platform. **Contains a secret key — never commit it.**
- \`metamynd-rules.json\` — your rules: the mandate (${neutral ? 'scope only — this agent has no spending authority' : 'scope + spend limits'}) and SOP (${neutral ? 'your rules' : 'extra checks'}).
  Edit it directly, or at the dashboard. Reloaded on every decision — no restart${withGateway ? ', in BOTH processes' : ''}.
- \`metamynd-harness.log.jsonl\` — every decision this agent made, append-only.
- \`harness-server.mjs\` — the local dashboard (port ${port}): rules, pending approvals, decision log.
- \`index.mjs\` — wraps a tool with \`guard.guardToolLocal(...)\`; the tool only runs when the
  LOCAL rules permit it${withGateway ? ', AND the SEPARATE gateway process (below) independently agrees' : ''}.${withGateway ? `
- \`harness-gateway/harness-gateway.mjs\` — a SECOND process. Your tools live HERE now, not in
  \`index.mjs\`. It re-verifies every signed request for itself against the SAME
  \`../metamynd-rules.json\`, using the real \`@metamynd/agentsafe-mcp-guard\` — the identical
  package a production Service uses, just pointed at a local file instead of a hosted issuer.` : ''}

${neutral ? `## What your rules read

A rule can only judge a field your application actually supplies with the request. Supply each
of these (the demo in \`index.mjs\` does):

${demo.inputs.map((i) => `- \`${i.field}\` — ${i.rules.join(', ')}`).join('\n') || '- (none — your rules read no request fields)'}

**A missing field is not a violation** for an allow-list, consent or PII rule: if your application
forgets to send \`jurisdiction\` or \`consent\`, that rule simply does not fire. Make sure the
field is always present.${demo.notDemonstrated.length ? `

Rules the demo does not stage (they are still enforced):

${demo.notDemonstrated.map((n) => `- ${n.rule} — ${n.why}`).join('\n')}` : ''}

` : ''}## What this is not

${withGateway ? `**\`--gateway\` closes one real gap, not every gap.** Precisely:

**Closed:** the agent process lying to itself. Call \`${gatedTool}\`'s underlying handler
directly (or skip \`index.mjs\` and hand a forged/altered request straight to
\`harness-gateway.mjs\`) — either way, the gateway independently re-verifies the Ed25519
signature and re-evaluates the SAME rules file for itself. There is no raw \`${tool}()\` left
in \`index.mjs\` to call for a shortcut, and a signature over an altered request fails
verification regardless of which process sent it.

**Also closed — the executed arguments are bound to what was signed.** \`harness-gateway.mjs\` contains
no enforcement logic of its own: routing, payload binding and deny-by-default come from
\`@metamynd/agentsafe-http-gateway\`, the same component the hosted scaffold uses. A request signed for
one amount and merchant but carrying another in the body is refused (\`PAYLOAD_NOT_BOUND\`) before your tool
runs, and so is any top-level body key you did not list in that route's \`allowedFields\`
(\`PAYLOAD_UNBINDABLE\`) — nothing signed covers it. When your real tool reads more body fields, list exactly
those keys; the gateway refuses the rest.${neutral ? `

**Also NOT closed — rule inputs are not signed.** The request fields your rules read (\`consent\`,
\`piiPresent\`, \`jurisdiction\`, …) travel in the signed request's context, which the signature does
not cover. An agent that can sign could omit a field or send a different one, and the rule that reads
it would not fire. The gateway enforces scope and identity firmly; an input-dependent rule is only as
strong as whatever supplies its input.` : ''}

**Also closed — replaying the same signed request.** \`harness-gateway.mjs\` remembers every nonce for as long as
the guard would accept the request (about 5 minutes) and refuses the second copy (\`REPLAY_DETECTED\`). The memory is
in-process: restarting the gateway forgets it.

${demo ? `**NOT closed:** anything that depends on history across many DIFFERENT calls (rate limits, circuit breakers,
patterns). That needs a STATEFUL authority — the hosted gate's \`requireAuthorization\` atomically claims a real,
single-use \`authorizationId\` against a database (see \`@metamynd/agentsafe-mcp-guard\`'s own README). A local
harness has no database; that is the whole point of \`--harness\`. \`harness-gateway.mjs\` re-checks POLICY per
request, which is real and worth having, but it does not remember what earlier calls did.` : `**NOT closed:** cumulative spend across many DIFFERENT calls. That needs a STATEFUL authority — the hosted gate's
\`requireAuthorization\` atomically claims a real, single-use \`authorizationId\` against a database and holds the
budget there (see \`@metamynd/agentsafe-mcp-guard\`'s own README). A local harness has no database; that is the
whole point of \`--harness\`. \`harness-gateway.mjs\` re-checks POLICY per request, so each call is held to the
per-transaction cap, but many calls under the cap are not added up here the way the hosted gate adds them up.`}

Also not closed by \`--gateway\` alone: cross-party trust (nobody but you can verify this agent's
identity or its decisions), evidence anyone but you can audit, a dashboard reachable when this
machine is off, an owner queue someone else can approve from. That's the hosted platform
(\`npx create-metamynd-agent\`, without \`--harness\`) — same \`guardTool()\` call, same rules
shape, so upgrading later is a config change, not a rewrite.` : `**Without MetaMynd, you can be bypassed.** Everything below is why, precisely.

No anchored/verifiable identity, no cross-party trust, no evidence anyone but you can audit,
no dashboard reachable when this machine is off, no owner queue someone else can approve from.
That's the hosted platform (\`npx create-metamynd-agent\`, without \`--harness\`) — same
\`guardTool()\` call, same rules shape, so upgrading later is a config change, not a rewrite.

It is also **not a separate enforcement boundary**. \`guardToolLocal()\` (in \`index.mjs\`) is a
cooperative library this process embeds — call the tool handler directly instead of the guarded
one and nothing stops you, because there is no second party in the loop to disagree with you.
That's structural, not a bug: use this harness to govern your own agent's own honest behavior,
not as a defense against an agent (or a person) actively trying to get around it. Re-scaffold
with \`--gateway\` for a SECOND local process that closes exactly this, still free and offline
(see README#--gateway once scaffolded) — or drop \`--harness\` entirely for the hosted platform's
default scaffold, which has this gap closed AND closes nonce replay/cumulative spend, because a
SEPARATE gateway process re-verifies the agent's signed authority against a real, stateful gate.`}
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

  // Is this a financial agent? A policy file with no spend limit and no monetary rule is taken at its
  // word: nothing money-shaped is added on the caller's behalf (BR-006). Say what was decided.
  const { financial } = announceFinancial(args, fileConfig);

  const name = await pick('name', 'Agent name', fileConfig?.name ?? 'Local Agent');
  const scope = await pick('scope', 'Mandate scope (governed action)', fileConfig?.scope ?? (financial ? 'flight-purchase' : 'perform-action'));
  assertSafeScope(scope);
  const perTxnMax = financial ? Number(await pick('per-txn-max', 'Per-transaction cap', String(fileConfig?.perTxnMax ?? '500'))) || 500 : undefined;
  const maxAmount = financial ? Number(await pick('max-amount', 'Total mandate budget', String(fileConfig?.maxAmount ?? '10000'))) || 10000 : undefined;
  const currency = financial ? (await pick('currency', 'Currency', fileConfig?.currency ?? 'USD')) || 'USD' : undefined;
  if (financial && !interactive && !['per-txn-max', 'max-amount', 'currency'].some((k) => typeof args[k] === 'string') && !['perTxnMax', 'maxAmount', 'currency'].some((k) => fileConfig?.[k] !== undefined)) {
    // A default the caller never asked for must at least be visible (conformance spec, section B).
    console.log(`  ${c.yellow('!')} no spend limits supplied — using the defaults ${currency} ${perTxnMax} per transaction, ${maxAmount} in total. If this agent does not move money, pass ${c.b('--non-financial')}.`);
  }
  const merchantsRaw = await pick('merchants', financial ? 'Allowed merchants (comma-sep, blank = any)' : 'Allowed recipients (comma-sep, blank = any)', Array.isArray(fileConfig?.merchants) ? fileConfig.merchants.join(',') : '');
  const merchants = String(merchantsRaw).split(',').map((s) => s.trim()).filter(Boolean);
  const port = Number(args.port) || 4400;
  const withGateway = !!args.gateway;
  const gatewayPort = Number(args['gateway-port']) || DEFAULT_GATEWAY_PORT;
  const slug = slugify(name);
  const outDir = resolve(String(args.out || (interactive ? await ask(rl, 'Output directory', `./${slug}`) : `./${slug}`)));
  rl?.close();

  assertScaffoldTarget(outDir, !!args.force);
  console.log(c.dim('\n  → generating a local identity (Ed25519, this machine only) …'));
  const { publicKeyHex, privateKeyHex } = generateAgentKeypair();
  const agentDid = harnessAgentDid(publicKeyHex);
  console.log(`  ${c.green('✓')} local agent ${c.b(agentDid)}`);

  const sopFields = configFileSopFields(fileConfig);
  const sopDocument = sopFields.sop ? sopFields.sop.documentJson : financial ? harnessDefaultSop(perTxnMax, currency) : harnessDefaultSopNeutral();
  if (sopFields.sop) console.log(`  ${c.green('✓')} compiled ${sopDocument.molecules.length} rule(s) from the config file`);
  const mandate = harnessMandate({ scope, currency, maxAmount, perTxnMax, merchants, financial });
  // Non-financial: the demo is derived from the rules actually in force, and what it cannot stage is said out loud.
  const demo = financial ? null : buildPolicyCases(sopDocument.molecules ?? []);
  if (demo) {
    console.log(`  ${c.green('✓')} derived ${demo.cases.length} demo case(s) from your rules`);
    for (const n of demo.notDemonstrated) console.log(`  ${c.yellow('!')} not staged in the demo: ${n.rule} ${c.dim('— ' + n.why + '; still enforced')}`);
  }

  console.log(`\n  ${c.b('Scaffolding')} ${c.dim(outDir)}`);
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  writeFileSafe(outDir, 'agent.metamynd.json', JSON.stringify({ agentDid, agentKey: privateKeyHex, mode: 'harness' }, null, 2) + '\n', !!args.force, 0o600);
  writeFileSafe(outDir, 'metamynd-rules.json', harnessRulesFile(mandate, sopDocument), !!args.force);
  writeFileSafe(outDir, 'harness-server.mjs', harnessServerFile(), !!args.force);
  writeFileSafe(
    outDir,
    'index.mjs',
    financial
      ? harnessIndexFile(scope, perTxnMax, port, withGateway, gatewayPort, currency, merchants[0] || 'demo-merchant')
      : harnessIndexFileNeutral({ scope, port, withGateway, gatewayPort, demo, merchant: merchants[0] }),
    !!args.force,
  );
  writeFileSafe(outDir, 'package.json', harnessPackageJson(slug), !!args.force);
  writeFileSafe(outDir, '.gitignore', gitignore(), !!args.force);
  writeFileSafe(outDir, 'README.md', harnessReadme(slug, scope, port, withGateway, gatewayPort, demo), !!args.force);

  if (withGateway) {
    const gwDir = join(outDir, 'harness-gateway');
    if (!existsSync(gwDir)) mkdirSync(gwDir, { recursive: true });
    writeFileSafe(gwDir, 'harness-gateway.mjs', harnessGatewayServerFile(scope, gatewayPort, agentDid, !financial), !!args.force);
    writeFileSafe(gwDir, 'package.json', harnessGatewayPackageJson(slug), !!args.force);
    writeFileSafe(gwDir, '.gitignore', gatewayGitignore(), !!args.force);
  }

  const rel = outDir.replace(resolve('.'), '.').replace(/\\/g, '/');
  console.log(`\n${c.green(c.b('  ✓ Done.'))} Your local governance harness is ready.\n`);
  console.log(`  ${c.dim('Free, local, no account. Not the hosted platform — see README#what-this-is-not.')}\n`);
  console.log(`  Next:`);
  console.log(c.cyan(`    cd ${rel}`));
  const outcomes = financial
    ? '   → ALLOW · BLOCK (over cap) · ESCALATE (approve at the dashboard) · BLOCK (ungranted action)\n'
    : `   → ${demoOutcomes(demo)}\n`;
  if (withGateway) {
    console.log(c.cyan(`    npm install && (cd harness-gateway && npm install)`));
    console.log(c.cyan(`    (cd harness-gateway && npm start &)`) + c.dim('   → the second process, in the background'));
    console.log(c.cyan(`    npm start`) + c.dim(outcomes));
  } else {
    console.log(c.cyan(`    npm install`));
    console.log(c.cyan(`    npm start`) + c.dim(outcomes));
  }
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

  // The same decision --harness and the hosted flow make (see announceFinancial): a non-financial request asks the
  // OWNER to approve no spending authority at all, and says so explicitly - an omitted amount means "use the
  // defaults" to every existing server, so absence alone must never be read as non-financial.
  const fileConfig = typeof args.config === 'string' ? loadConfigFile(args.config) : null;
  if (fileConfig) console.log(`  ${c.green('✓')} loaded policy config ${c.dim(args.config)}`);
  const { financial } = announceFinancial(args, fileConfig);
  warnRulesNotApplied(fileConfig, 'a delegated request');
  const name = (typeof args.name === 'string' ? args.name : undefined) ?? fileConfig?.name ?? 'Delegated Agent';
  const scope = (typeof args.scope === 'string' ? args.scope : undefined) ?? fileConfig?.scope ?? (financial ? 'flight-purchase' : 'perform-action');
  assertSafeScope(scope);
  const perTxnMax = financial ? Number(args['per-txn-max'] ?? fileConfig?.perTxnMax) || 500 : undefined;
  // Only what was SUPPLIED is sent, so an ordinary `--request` is byte-for-byte what it always was. Before this the
  // other financial fields in a --config file were read and silently dropped, and the owner saw the server defaults.
  const maxAmountReq = financial && (args['max-amount'] ?? fileConfig?.maxAmount) !== undefined ? Number(args['max-amount'] ?? fileConfig?.maxAmount) : undefined;
  const currencyReq = financial ? (typeof args.currency === 'string' ? args.currency : typeof fileConfig?.currency === 'string' ? fileConfig.currency : undefined) : undefined;
  const merchantsReq = typeof args.merchants === 'string'
    ? args.merchants.split(',').map((s) => s.trim()).filter(Boolean)
    : Array.isArray(fileConfig?.merchants) ? fileConfig.merchants.map(String) : [];
  let publicKey, generated;
  if (args.byok) {
    generated = generateAgentKeypair();
    publicKey = generated.publicKeyHex;
    console.log(`  ${c.green('✓')} generated an Ed25519 keypair locally ${c.dim('(private key stays on this machine)')}`);
  }

  console.log(c.dim(`  → requesting "${name}" for ${owner} …`));
  const res = await apiPost(base, '/onboarding/requests', { ownerEmail: owner, name, scope, ...(financial ? { perTxnMax, ...(maxAmountReq !== undefined && Number.isFinite(maxAmountReq) ? { maxAmount: maxAmountReq } : {}), ...(currencyReq ? { currency: currencyReq } : {}) } : { financial: false }), ...(merchantsReq.length ? { merchants: merchantsReq } : {}), ...(publicKey ? { publicKey } : {}) }, token);
  const d = res.data;
  // A server that predates non-financial requests ignores the field and files the request WITH default spend
  // limits. The developer cannot withdraw it, so say exactly what now exists and who can deny it; do not save a
  // claim file for a request this scaffolder must not build on.
  if (!financial && d?.financial !== false) {
    fail(`This server does not support non-financial requests yet. Request ${d?.requestId ?? '(unknown id)'} WAS submitted, with default spend limits, so it is not the agent you asked for: ask ${owner} to DENY it in the dashboard (AgentSafe → Agent Requests), and do not claim it.`);
  }
  const state = { api: base, requestId: d.requestId, claimToken: d.claimToken, byok: !!generated, privateKey: generated?.privateKeyHex ?? null, name, scope, financial, ...(financial ? { perTxnMax, ...(currencyReq ? { currency: currencyReq } : {}) } : {}) };
  const file = resolve(String(args.out || '.'), REQUEST_STATE_FILE);
  // May carry a BYOK private key (state.privateKey) — same 0600 treatment as agent.metamynd.json.
  writeFileSync(file, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
  if (existsSync(file)) chmodSync(file, 0o600);

  console.log(`  ${c.green('✓')} request ${c.b(d.requestId)} submitted — awaiting ${owner}'s approval${financial ? '' : c.dim(' (no spending authority requested)')}`);
  console.log(`  ${c.yellow('⚠ saved the one-time claim token to')} ${file.replace(resolve('.'), '.').replace(/\\/g, '/')} ${c.dim('(secret — do not commit)')}\n`);
  console.log(`  The owner approves in the dashboard (AgentSafe → Agent Requests). Then run:`);
  console.log(c.cyan(`    npx create-metamynd-agent --claim --watch\n`));
}

// --claim: poll for the owner's approval, then scaffold. Reads metamynd-request.json (or flags).
async function runClaim(args) {
  const file = resolve(String(args['request-file'] || `./${REQUEST_STATE_FILE}`));
  const state = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
  const base = String((typeof args.api === 'string' ? args.api : undefined) ?? state.api ?? process.env.METAMYND_API ?? DEFAULT_API).replace(/\/+$/, '');
  const requestId = (typeof args['request-id'] === 'string' ? args['request-id'] : undefined) ?? state.requestId;
  const claimToken = (typeof args.token === 'string' ? args.token : undefined) ?? state.claimToken;
  if (!requestId || !claimToken) fail(`Need a requestId + claim token (--request-id/--token, or a ${REQUEST_STATE_FILE}).`);

  // Claiming returns a managed key ONCE and wipes it from the server, so nothing that can be caught before the
  // request may be caught after it.
  if (args.financial && (args['non-financial'] || state.financial === false)) {
    fail('--financial contradicts a non-financial request (--non-financial, or the request file says so). Drop one.');
  }
  if (args['non-financial'] && state.financial === true) {
    fail('--non-financial contradicts the request file, which records a request WITH spend limits. Drop the flag, or submit a new non-financial request.');
  }

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

  // What was ISSUED decides the shape, not what was hoped for: the config the server returned says whether the
  // agent carries spend authority. Refuse a mismatch either way rather than scaffold something that contradicts it.
  const issuedNonFinancial = config.financial === false;
  const wantsNonFinancial = !!args['non-financial'] || state.financial === false;
  // The claim has ALREADY happened here: a managed key was returned once and is gone from the server. So before
  // refusing to scaffold, keep what was returned (never over an existing file) and say the request cannot be denied
  // any more - it is approved. The remedy is to contain or rotate the agent.
  const keepConfigAndStop = (why) => {
    const keptDir = resolve(String(args.out || `./${slugify(state.name || 'metamynd-agent')}`));
    let kept = null;
    try {
      mkdirSync(keptDir, { recursive: true });
      const name = existsSync(join(keptDir, 'agent.metamynd.json')) ? `agent.metamynd.${String(requestId).slice(0, 8)}.json` : 'agent.metamynd.json';
      kept = join(keptDir, name);
      writeFileSync(kept, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
      if (existsSync(kept)) chmodSync(kept, 0o600);
    } catch { kept = null; }
    fail(`${why}\n  The request is already APPROVED, so it cannot be denied. ${kept ? `Its config was saved to ${kept.replace(/\\/g, '/')} (a managed key is returned once and cannot be fetched again). ` : ''}NOTHING was scaffolded. Contain or rotate the agent in the dashboard (Agent Identities), or keep it and set the project up by hand.`);
  };
  if (wantsNonFinancial && !issuedNonFinancial) {
    keepConfigAndStop(`You asked for a non-financial agent, but the approved config does not say it is one (financial: ${String(config.financial)}), so it may carry spend limits.`);
  }
  if (args.financial && issuedNonFinancial) {
    keepConfigAndStop('--financial was passed, but the approved agent has NO spending authority (the request was non-financial).');
  }
  const slug = slugify(state.name || 'metamynd-agent');
  const outDir = resolve(String(args.out || `./${slug}`));
  if (issuedNonFinancial) {
    console.log(`  ${c.green('✓')} non-financial agent ${c.dim('(the approved config has no spending authority) — no spend limits, no payment demo')}`);
    scaffoldProject({ demo: defaultNeutralDemo(), outDir, config, slug, scope: state.scope || config.mandate?.scope || 'perform-action', sandbox: false, withGateway: !args['no-gateway'], gatewayPort: Number(args['gateway-port']) || DEFAULT_GATEWAY_PORT, force: !!args.force });
    return;
  }
  // The demo must be in the currency the request was filed in: the gate refuses a request in any other currency
  // against a currency-scoped cap, so a USD demo against a GBP agent is blocked at step 1 and reads as a broken agent.
  // A request file from before the currency was recorded was filed without one, i.e. in USD.
  scaffoldProject({ outDir, config, slug, scope: state.scope || config.mandate?.scope || 'flight-purchase', perTxnMax: Number(state.perTxnMax) || 500, currency: typeof state.currency === 'string' && state.currency ? state.currency : 'USD', sandbox: false, withGateway: !args['no-gateway'], gatewayPort: Number(args['gateway-port']) || DEFAULT_GATEWAY_PORT, force: !!args.force });
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

  // BR-006: is this a financial agent? Same rule as --harness, so one policy file scaffolds the same
  // shape either way. A non-financial agent is provisioned with NO spend fields (the backend treats
  // their absence as a non-financial mandate) and gets the neutral project; say what was decided.
  const { financial } = announceFinancial(args, fileConfig);

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
  const scope = await pick('scope', null, 'Mandate scope (governed action)', fileConfig?.scope ?? (financial ? 'flight-purchase' : 'perform-action'));
  assertSafeScope(scope);
  const perTxnMax = financial ? Number(await pick('per-txn-max', null, 'Per-transaction cap', String(fileConfig?.perTxnMax ?? '500'))) || 500 : undefined;
  const maxAmount = financial ? Number(await pick('max-amount', null, 'Total mandate budget', String(fileConfig?.maxAmount ?? '10000'))) || 10000 : undefined;
  const currency = financial ? (await pick('currency', null, 'Currency', fileConfig?.currency ?? 'USD')) || 'USD' : undefined;
  if (financial && !interactive && !['per-txn-max', 'max-amount', 'currency'].some((k) => typeof args[k] === 'string') && !['perTxnMax', 'maxAmount', 'currency'].some((k) => fileConfig?.[k] !== undefined)) {
    // A default the caller never asked for must at least be visible (conformance spec, section B).
    console.log(`  ${c.yellow('!')} no spend limits supplied — using the defaults ${currency} ${perTxnMax} per transaction, ${maxAmount} in total. Set --per-txn-max / --max-amount / --currency (or the config file) to choose your own.`);
  }
  const merchantsRaw = await pick(
    'merchants', null, financial ? 'Allowed merchants (comma-sep, blank = any)' : 'Allowed recipients (comma-sep, blank = any)',
    Array.isArray(fileConfig?.merchants) ? fileConfig.merchants.join(',') : '',
  );
  const merchants = String(merchantsRaw).split(',').map((s) => s.trim()).filter(Boolean);

  // BYOK: --byok generates a keypair on THIS machine (MetaMynd never sees the private key) —
  // either locally in this process (default) or, opt-in, via an already-running agentsafe-signer
  // daemon (--daemon-socket + --daemon-admin-socket, see their own help text) so the private key
  // never enters this process at all. An explicit --public-key means the caller holds the key
  // elsewhere and will prove it themselves — daemon flags are meaningless with it.
  let publicKey = typeof args['public-key'] === 'string' ? args['public-key'] : undefined;
  const daemonSocket = typeof args['daemon-socket'] === 'string' ? args['daemon-socket'] : undefined;
  const daemonAdminSocket = typeof args['daemon-admin-socket'] === 'string' ? args['daemon-admin-socket'] : undefined;
  if (Boolean(daemonSocket) !== Boolean(daemonAdminSocket)) {
    rl?.close();
    fail('--daemon-socket and --daemon-admin-socket must be used together.');
  }
  if (daemonSocket && !args.byok) {
    rl?.close();
    fail('--daemon-socket requires --byok.');
  }
  if (daemonSocket && publicKey) {
    rl?.close();
    fail('--daemon-socket generates its own key — pass --byok alone, not --public-key.');
  }
  let generatedKey = null;
  let daemonPublicKeyHex = null;
  if (args.byok && !publicKey && daemonSocket) {
    console.log(c.dim('  → asking the agentsafe-signer daemon to generate a key …'));
    const { publicKeyHex } = await daemonRequest(daemonAdminSocket, 'generate-key', { allowRekey: false });
    daemonPublicKeyHex = publicKeyHex;
    publicKey = publicKeyHex;
    console.log(`  ${c.green('✓')} generated an Ed25519 keypair via the signer daemon ${c.dim('(the private key never left it)')}`);
  } else if (args.byok && !publicKey) {
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
  // A non-financial agent sends NO spend fields at all (currency/maxAmount/perTxnMax omitted together
  // is how the backend recognises one). A rule pack is built from spend limits, so it cannot apply.
  if (!financial && sopFields.rulePack) {
    console.log(`  ${c.yellow('!')} the rule pack "${sopFields.rulePack}" cannot be applied to a non-financial hosted agent (the platform applies a pack only when spend limits are supplied) — the default (an amount-free high-risk review) applies. List your rules under "rules" to set your own.`);
    delete sopFields.rulePack;
  }
  const body = {
    name, scope,
    // Explicit, not left to the backend's own eligibility-based default (mainnet for a KYB-verified
    // owner, testnet otherwise) — an owner who happens to be verified would otherwise silently get a
    // REAL mainnet agent from a plain `npx create-metamynd-agent` with no signal that anything
    // changed. The generated financial gateway CAN now satisfy mainnet's registry enforcement (a
    // real, registered did:key — see the gateway identity step below), but this CLI has no flag to
    // opt into mainnet yet; that is a separate decision (exposing it safely — KYB status, spend
    // caps — is more than a network toggle) from giving the gateway a real identity, which is what
    // this fixes. docs/design/release-blockers-open-items.md, "Registry default".
    network: 'testnet',
    ...(financial ? { currency, maxAmount, perTxnMax } : {}),
    merchants,
    ...(publicKey ? { publicKey } : {}),
    ...sopFields,
  };
  const provisioned = await apiPost(base, '/onboarding/agent', body, token);
  const config = provisioned?.data;
  if (!config?.agentDid) fail('Provisioning did not return a config with an agentDid.');
  console.log(`  ${c.green('✓')} agent DID ${c.b(config.agentDid)}`);
  if (config.standards?.length) console.log(`  ${c.green('✓')} enforced Standards: ${config.standards.join(', ')}`);

  // 3b. BYOK: prove control of the key (verify-key), else the gate blocks with AGENT_KEY_UNVERIFIED.
  if (daemonPublicKeyHex) {
    // The daemon holds the private key — it never entered this process. Point the scaffolded
    // guard at the daemon instead of embedding a plaintext key (agentsafe-guard/key-providers.mjs's
    // resolveKeyProvider() reads these two fields and never looks for `agentKey` when present).
    config.keyProvider = 'daemon';
    config.daemonSocketPath = daemonSocket;
    if (config.challenge) {
      console.log(c.dim('  → proving key control via the daemon (verify-key) …'));
      const { signature } = await daemonRequest(daemonSocket, 'sign-key-control-challenge', { challenge: config.challenge });
      await apiPost(base, `/agent-identity/${encodeURIComponent(config.identityId)}/verify-key`, { signature }, token);
      config.keyVerified = true;
      delete config.challenge; // one-time; consumed
      console.log(`  ${c.green('✓')} key verified — MetaMynd never saw your private key, and neither did this CLI`);
    }
  } else if (generatedKey) {
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

  // 3c. The gateway's OWN identity — a real did:key, separate from the agent's own (an agent must
  // never be able to release or lower-settle a hold it authorized itself; only the SERVICE that
  // claimed it may). Only the financial, with-gateway shape ever claims a hold at all; the
  // non-financial gateway never calls claimAuthorization() (requireAuthorization is off there), so
  // it has no counterparty identity to register.
  let gatewayIdentity = null;
  if (financial && !args['no-gateway']) {
    const gwKeypair = generateAgentKeypair();
    const gatewayDid = buildDidKey(rawPublicKeyFromSpkiHex(gwKeypair.publicKeyHex));
    gatewayIdentity = { did: gatewayDid, keyHex: gwKeypair.privateKeyHex };
    console.log(c.dim(`\n  → registering the gateway's identity as a trusted counterparty (so it can claim this agent's holds) …`));
    const reg = await registerGatewayCounterparty(base, token, gatewayDid, `${scope}-gateway`);
    if (reg.ok) {
      console.log(`  ${c.green('✓')} gateway DID ${c.b(gatewayDid)} — ${reg.message}`);
    } else {
      console.log(`  ${c.yellow('!')} could not register the gateway as a trusted counterparty: ${reg.message}`);
      console.log(c.dim(`     it still works on testnet (open by default with no registry entries); a MAINNET hold cannot be`));
      console.log(c.dim(`     claimed until it is registered — POST ${base}/policy/counterparties { "did": "${gatewayDid}", "confirmEnforcementChange": true }`));
    }
  }

  // 4. Scaffold + next steps
  // The demo comes from the rules actually provisioned: the caller's own, else the backend's default
  // for a non-financial agent (the same amount-free review harnessDefaultSopNeutral describes).
  const demo = financial ? null : buildPolicyCases(sopFields.sop?.documentJson?.molecules ?? harnessDefaultSopNeutral().molecules);
  if (demo) {
    console.log(`  ${c.green('✓')} derived ${demo.cases.length} demo case(s) from your rules`);
    for (const n of demo.notDemonstrated) console.log(`  ${c.yellow('!')} not staged in the demo: ${n.rule} ${c.dim('— ' + n.why + '; still enforced')}`);
  }
  scaffoldProject({ demo, outDir, config, slug, scope, perTxnMax, currency, merchant: financial ? merchants[0] || 'demo-merchant' : merchants[0], sandbox: false, withGateway: !args['no-gateway'], gatewayPort: Number(args['gateway-port']) || DEFAULT_GATEWAY_PORT, force: !!args.force, gatewayIdentity });
}

// Exported so the smoke tests can exercise the generators directly. Importing this file must not
// start the CLI, hence the opt-out; a normal `npx create-metamynd-agent` never sets it.
export {
  buildPolicyCases, resolveFinancial, policyMolecules, ruleToMolecule,
  generateAgentKeypair, harnessAgentDid, harnessMandate, harnessRulesFile, harnessDefaultSopNeutral,
  scaffoldProject, defaultNeutralDemo, exampleIndexNeutral, exampleReadmeNeutral, gatewayServerFileNeutral, gatewayReadmeNeutral,
};
if (!process.env.CREATE_METAMYND_AGENT_NO_MAIN) main().catch((e) => fail(e?.stack || e?.message || String(e)));

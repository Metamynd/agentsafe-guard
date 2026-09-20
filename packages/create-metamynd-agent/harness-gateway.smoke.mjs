// harness-gateway.smoke.mjs — scaffolds --harness both with and without --gateway into a
// throwaway temp dir and syntax-checks every generated file. No network, no npm install: this
// catches template-string bugs (an unbalanced backtick, a stray `${}`) in the generator
// functions themselves, which `node --check` on THIS file can never see — the bug only exists
// once the template is rendered.
//
//   node harness-gateway.smoke.mjs   → PASS when every generated file parses.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let failed = 0;
function check(ok, name) {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`);
}

function allFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...allFiles(p));
    else if (p.endsWith('.mjs')) out.push(p);
  }
  return out;
}

function scaffoldAndCheck(label, extraArgs) {
  const outDir = mkdtempSync(join(tmpdir(), 'metamynd-harness-smoke-'));
  try {
    execFileSync(process.execPath, [
      join(process.cwd(), 'index.mjs'),
      '--harness', '--yes', '--name', 'Smoke Test', '--scope', 'flight-purchase',
      '--per-txn-max', '500', '--out', outDir, ...extraArgs,
    ], { stdio: 'pipe' });
  } catch (err) {
    check(false, `${label}: scaffold command itself failed — ${err.stderr?.toString().slice(0, 300) ?? err.message}`);
    return;
  }
  const files = allFiles(outDir);
  check(files.length > 0, `${label}: scaffolded at least one .mjs file`);
  for (const f of files) {
    try {
      execFileSync(process.execPath, ['--check', f], { stdio: 'pipe' });
      check(true, `${label}: ${f.slice(outDir.length + 1)} parses`);
    } catch (err) {
      check(false, `${label}: ${f.slice(outDir.length + 1)} — ${err.stderr?.toString().slice(0, 300) ?? err.message}`);
    }
  }
  // Fresh-clone journey (BR-004/BR-005): agent.metamynd.json is gitignored, so a clone never has
  // it. The generated entry point must say what to do rather than throw a bare ENOENT, and must
  // warn when a committed lockfile pins a guard older than this scaffold expects.
  const index = readFileSync(join(outDir, 'index.mjs'), 'utf8');
  check(/No \.\/agent\.metamynd\.json/.test(index) && /code === 'ENOENT'/.test(index), `${label}: index.mjs explains a missing agent.metamynd.json`);
  check(/Fresh-clone check/.test(index) && /npm install @metamynd\/agentsafe-guard@latest/.test(index), `${label}: index.mjs warns on a stale installed guard`);
  rmSync(outDir, { recursive: true, force: true });
}

scaffoldAndCheck('plain --harness', []);
scaffoldAndCheck('--harness --gateway', ['--gateway']);

if (failed) {
  console.error(`\n${failed} case(s) FAILED`);
  process.exit(1);
}
console.log('\nPASS — every scaffolded file (both --harness and --harness --gateway) parses.');

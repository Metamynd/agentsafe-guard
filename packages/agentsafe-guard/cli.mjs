#!/usr/bin/env node
// cli.mjs — the package's only executable. Its whole job is to make the offline
// demo reachable without cloning anything:
//
//   npx @metamynd/agentsafe-guard demo
//
// Kept deliberately thin: no argument parser, no dependencies, no network.
const [, , cmd] = process.argv;

const flag = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? null : (process.argv[i + 1] ?? '');
};

if (cmd === 'demo') {
  await import('./demo.mjs');
} else if (cmd === 'verify') {
  // Governance as a build step. Exits non-zero when a configured control does not hold,
  // or when a control named by --require is not configured at all.
  const { verify } = await import('./verify.mjs');
  try {
    const result = await verify({
      configPath: flag('config') ?? './agent.metamynd.json',
      require: (flag('require') ?? '').split(',').map((s) => s.trim()).filter(Boolean),
      json: process.argv.includes('--json'),
    });
    process.exit(result.ok ? 0 : 1);
  } catch (e) {
    // Failing to verify is not the same as verifying a pass, and CI must not read it as one.
    console.error(`verify could not run: ${e.message}`);
    process.exit(2);
  }
} else if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
  console.log(`
  @metamynd/agentsafe-guard — runtime governance for Node AI agents

  Usage
    npx @metamynd/agentsafe-guard demo     Run the offline policy demo
                                           (no account, no API key, no network)

    npx @metamynd/agentsafe-guard verify   Assert this agent cannot exceed its
                                           mandate. Exit 1 if it can. For CI.

      --config <path>     agent config (default ./agent.metamynd.json)
      --require <a,b>     fail when a control is NOT configured, e.g.
                          --require merchants,perTxn
      --json              machine-readable output

    A control the mandate does not set is reported, never passed: an empty
    merchant allow-list permits every merchant, and this says so rather than
    calling it a pass.

  In your agent
    import { createGuard } from '@metamynd/agentsafe-guard';

  Docs   https://www.npmjs.com/package/@metamynd/agentsafe-guard
  Hosted https://metamynd.ai
`);
} else {
  console.error(`Unknown command: ${cmd}\nTry: npx @metamynd/agentsafe-guard demo`);
  process.exit(1);
}

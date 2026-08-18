#!/usr/bin/env node
// cli.mjs — the package's only executable. Its whole job is to make the offline
// demo reachable without cloning anything:
//
//   npx @metamynd/agentsafe-guard demo
//
// Kept deliberately thin: no argument parser, no dependencies, no network.
const [, , cmd] = process.argv;

if (cmd === 'demo') {
  await import('./demo.mjs');
} else if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
  console.log(`
  @metamynd/agentsafe-guard — runtime governance for Node AI agents

  Usage
    npx @metamynd/agentsafe-guard demo     Run the offline policy demo
                                           (no account, no API key, no network)

  In your agent
    import { createGuard } from '@metamynd/agentsafe-guard';

  Docs   https://www.npmjs.com/package/@metamynd/agentsafe-guard
  Hosted https://metamynd.ai
`);
} else {
  console.error(`Unknown command: ${cmd}\nTry: npx @metamynd/agentsafe-guard demo`);
  process.exit(1);
}

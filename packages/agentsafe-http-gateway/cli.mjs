#!/usr/bin/env node
// cli.mjs — `npx @metamynd/agentsafe-http-gateway <command>`: the two steps of putting a tool behind the gateway that used
// to need hand-written code (pre-beta evaluation 2026-10-09, M4).
//
//   service-id [--out service-identity.json] [--force]
//       Make the gateway's own identity (a did:key and its key) and save it, owner-readable only. Prints the DID to register.
//   accept-challenge [--identity service-identity.json] "<challenge>"
//       Sign the challenge Trusted Counterparties shows when you register that DID. Prints the signature to paste back.
//       Reads the challenge from stdin when it is not given (or is "-").
//   serve
//       Run the gateway (server.mjs), configured by its environment variables — see the README.
//
// Neither needs the owner's password: the owner registers the gateway in the dashboard; the gateway only proves its key.

import { createServiceIdentity, writeServiceIdentity, readServiceIdentity, acceptChallenge } from './service-identity.mjs';

const DEFAULT_FILE = 'service-identity.json';

function flag(args, name) {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

const USAGE = `Usage:
  agentsafe-gateway service-id [--out ${DEFAULT_FILE}] [--force]
  agentsafe-gateway accept-challenge [--identity ${DEFAULT_FILE}] "<challenge>"   (or pipe the challenge on stdin)
  agentsafe-gateway serve                                                       (runs server.mjs; see the README)`;

async function main(argv = process.argv.slice(2), io = { log: console.log, error: console.error, stdin: readStdin }) {
  const args = [...argv];
  const command = args.shift();
  try {
    if (command === 'serve') {
      await import('./server.mjs'); // starts listening; the process stays up on the server
      return null;
    }
    if (command === 'service-id') {
      const force = args.includes('--force');
      if (force) args.splice(args.indexOf('--force'), 1);
      const out = flag(args, '--out') ?? DEFAULT_FILE;
      const id = createServiceIdentity();
      writeServiceIdentity(out, id, { force });
      io.log(`Gateway identity written to ${out} (keep it secret: it is this gateway's signing key).`);
      io.log('');
      io.log(`  Service DID: ${id.serviceDid}`);
      io.log('');
      io.log('Next:');
      io.log(`  1. Start the gateway with SERVICE_IDENTITY_FILE=${out} (or SERVICE_DID / SERVICE_KEY from the file).`);
      io.log('  2. In the dashboard, Trusted Counterparties → Register a service: paste the DID above, press "Get challenge".');
      io.log(`  3. Sign it here: agentsafe-gateway accept-challenge --identity ${out} "<challenge>" — paste the signature back.`);
      return 0;
    }
    if (command === 'accept-challenge') {
      // An explicit --identity wins; then the server's own configuration (SERVICE_IDENTITY_FILE, or SERVICE_DID + SERVICE_KEY).
      const explicit = flag(args, '--identity');
      const identity =
        !explicit && !process.env.SERVICE_IDENTITY_FILE && process.env.SERVICE_DID && process.env.SERVICE_KEY
          ? { serviceDid: process.env.SERVICE_DID, serviceKey: process.env.SERVICE_KEY }
          : readServiceIdentity(explicit ?? process.env.SERVICE_IDENTITY_FILE ?? DEFAULT_FILE);
      const given = args.join(' ').trim();
      const message = given && given !== '-' ? given : (await io.stdin()).trim();
      if (!message) throw new Error('no challenge given: pass it as an argument or on stdin');
      io.log(await acceptChallenge(identity, message));
      return 0;
    }
    io.error(USAGE);
    return command === undefined || command === '--help' || command === '-h' ? 0 : 2;
  } catch (err) {
    io.error(`agentsafe-gateway ${command}: ${err?.message ?? err}`);
    return 1;
  }
}

main().then((code) => {
  if (code !== null) process.exit(code);
});

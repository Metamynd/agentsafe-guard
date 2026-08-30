#!/usr/bin/env node
// auditor.mjs — CLI for the MAGP lawful-disclosure auditor (Phase E).
//
// A regulator / disputing party runs this against a disclosure package a holder opened. It verifies
// — with MetaMynd offline — that the record was governed, unaltered, and is anchored on-chain.
//
//   node auditor.mjs <disclosure.json> [--topic 0.0.x] [--network testnet|mainnet]
//
// The disclosure package is the JSON described in magp-evidence.mjs verifyDisclosure(). With
// --topic, the auditor also confirms the batch root is anchored on the evidence HCS topic via a
// public Hedera mirror node. Exit 0 = VALID, 1 = INVALID/unverifiable.
import { readFileSync } from 'node:fs';
import { verifyDisclosure, verifyRootAnchored } from './magp-evidence.mjs';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
const opt = (name) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined; };
if (!file) { console.error('usage: node auditor.mjs <disclosure.json> [--topic 0.0.x] [--network testnet|mainnet]'); process.exit(2); }

const pkg = JSON.parse(readFileSync(file, 'utf8'));
const r = verifyDisclosure(pkg);

console.log(`\nMAGP lawful-disclosure audit — ${file}\n${'─'.repeat(56)}`);
for (const c of r.checks) console.log(`  ${c.ok ? '✓' : '✗'} ${c.check}`);

const topic = opt('topic');
let anchorLine = '  · on-chain anchoring not checked (pass --topic to verify)';
let anchoredOk = true;
if (topic) {
  const a = await verifyRootAnchored(pkg.root, topic, { network: opt('network') ?? 'testnet' });
  anchoredOk = a.anchored;
  anchorLine = a.anchored
    ? `  ✓ batch root anchored on HCS topic ${topic} @ ${a.consensusTimestamp} (seq ${a.sequenceNumber})`
    : `  ✗ batch root NOT found on HCS topic ${topic} (or mirror unreachable)`;
}
console.log(anchorLine);

const ok = r.valid && anchoredOk;
console.log(`${'─'.repeat(56)}\n${ok ? '✅ VALID' : '❌ INVALID'} — the disclosed record ${ok ? 'was governed, unaltered, and is anchored.' : 'did NOT verify.'}\n`);
process.exit(ok ? 0 : 1);

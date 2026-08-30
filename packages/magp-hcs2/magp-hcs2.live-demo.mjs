/**
 * The one exception to "everything in this package is offline." Anchors a REAL did:hedera
 * DID document on Hedera TESTNET, then resolves it back via `resolveDidViaMirror` against
 * the REAL public mirror node — no mocked fetch anywhere in this file. Every other test in
 * this package (magp-hcs2.test.mjs) injects a fake `fetchImpl`, which proves the parsing/
 * replay/key-binding LOGIC is correct but never proves the tool actually round-trips
 * against a live mirror node. This is that proof.
 *
 * NOT run by `npm test` or CI — same reasoning as mmt-graph.anchor-live-demo.mjs: a live
 * network call to external infrastructure, plus a real (if brief) mirror-node indexing
 * delay, is not something that should gate a test run. Run by hand:
 *
 *   HEDERA_OPERATOR_ID=... HEDERA_OPERATOR_KEY=... node magp-hcs2.live-demo.mjs
 *
 * or point it at backend/.env's existing dev testnet credentials:
 *
 *   MAGP_HCS2_DOTENV_PATH=../../backend/.env node magp-hcs2.live-demo.mjs
 *
 * Uses TESTNET HBAR, which has no real-world value.
 */
import { config as loadEnv } from 'dotenv';
import { Client, AccountId, PrivateKey, TopicCreateTransaction, TopicMessageSubmitTransaction } from '@hashgraph/sdk';
import { resolveDidViaMirror } from './magp-hcs2.mjs';

loadEnv(process.env.MAGP_HCS2_DOTENV_PATH ? { path: process.env.MAGP_HCS2_DOTENV_PATH } : undefined);

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
const multibaseBase58btc = (bytes) => 'z' + base58(bytes);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const operatorId = process.env.HEDERA_OPERATOR_ID;
  const operatorKey = process.env.HEDERA_OPERATOR_KEY;
  const network = process.env.HEDERA_NETWORK || 'testnet';
  if (!operatorId || !operatorKey) {
    console.error('Missing HEDERA_OPERATOR_ID / HEDERA_OPERATOR_KEY. See this file\'s header for how to run it.');
    process.exitCode = 1;
    return;
  }

  const client = network === 'mainnet' ? Client.forMainnet() : Client.forTestnet();
  client.setOperator(AccountId.fromString(operatorId), PrivateKey.fromString(operatorKey));

  console.log(`[live-demo] creating a throwaway HCS topic on ${network}...`);
  const topicTx = await new TopicCreateTransaction().execute(client);
  const topicReceipt = await topicTx.getReceipt(client);
  const topicId = topicReceipt.topicId.toString();
  console.log(`[live-demo] topic ${topicId} created`);

  const key = PrivateKey.generateED25519();
  const pubBytes = key.publicKey.toBytesRaw();
  const did = `did:hedera:${network}:${multibaseBase58btc(pubBytes)}_${topicId}`;
  console.log(`[live-demo] real did:hedera under test: ${did}`);

  const didDocument = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    controller: did,
    verificationMethod: [{ id: `${did}#did-root-key`, type: 'Ed25519VerificationKey2020', controller: did, publicKeyMultibase: multibaseBase58btc(pubBytes) }],
    authentication: [`${did}#did-root-key`],
    service: [{ type: 'MAGPEndpoint', serviceEndpoint: 'https://example.invalid/magp', channels: [], protoVersions: ['1.0'] }],
  };
  console.log('[live-demo] submitting op:did-create...');
  await (await new TopicMessageSubmitTransaction({ topicId, message: JSON.stringify({ op: 'did-create', didDocument }) }).execute(client)).getReceipt(client);

  console.log('[live-demo] waiting for mirror-node indexing (testnet is usually a few seconds behind consensus)...');
  let result = null;
  for (let attempt = 1; attempt <= 10 && !result; attempt++) {
    await sleep(3000);
    result = await resolveDidViaMirror(did, { network });
    console.log(`[live-demo] attempt ${attempt}: ${result ? 'resolved' : 'not yet indexed'}`);
  }

  client.close();

  if (!result) {
    console.error('[live-demo] FAILED — resolveDidViaMirror never resolved the document against the real mirror node.');
    process.exitCode = 1;
    return;
  }
  if (!result.verifiedKeyMatch) {
    console.error('[live-demo] FAILED — resolved a document, but its key did not match the DID\'s own embedded key.');
    process.exitCode = 1;
    return;
  }
  if (result.service?.serviceEndpoint !== 'https://example.invalid/magp') {
    console.error('[live-demo] FAILED — resolved, key matched, but the service endpoint was not read back correctly.');
    process.exitCode = 1;
    return;
  }
  console.log('[live-demo] PASS — resolveDidViaMirror round-tripped a REAL Hedera testnet anchor end to end:');
  console.log(JSON.stringify(result, null, 2));
}

main().catch((err) => { console.error('[live-demo] error:', err); process.exitCode = 1; });

// magp-hcs2.test.mjs — Phase D: a peer resolves a DID document + service endpoint from the DID's
// own HCS topic via a public Hedera mirror node, trustlessly, WITHOUT contacting MetaMynd.
// Run: node integrations/magp-hcs2/magp-hcs2.test.mjs
import {
  parseHederaDid, mirrorBase, parseRegistryMessages, replayDidRegistry, docVerificationKey, resolveDidViaMirror,
} from './magp-hcs2.mjs';

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; console.log(`  ✓ ${name}`); } else { fail++; console.log(`  ✗ ${name}`); } };

// A realistic did:hedera and its anchored document.
const KEY = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const TOPIC = '0.0.9459675';
const DID = `did:hedera:testnet:${KEY}_${TOPIC}`;
const docFor = (key = KEY, service = true) => ({
  '@context': ['https://www.w3.org/ns/did/v1'], id: DID,
  verificationMethod: [{ id: `${DID}#did-root-key`, type: 'Ed25519VerificationKey2020', controller: DID, publicKeyMultibase: key }],
  authentication: ['#did-root-key'],
  ...(service ? { service: [{ id: '#magp', type: 'MAGPEndpoint', serviceEndpoint: 'https://travel.example.com/magp', channels: ['https'], protoVersions: ['0.4'] }] } : {}),
});
// Encode ops as a mirror-node messages payload (base64), optionally out of order.
const asMirror = (ops) => ({ messages: ops.map((op, i) => ({ sequence_number: op._seq ?? i + 1, consensus_timestamp: `1700000000.${i}`, message: Buffer.from(JSON.stringify(op)).toString('base64') })) });

console.log('\n0. DID parsing + mirror base');
{
  const p = parseHederaDid(DID);
  ok('parses network / key / topic', p.network === 'testnet' && p.publicKeyMultibase === KEY && p.topicId === TOPIC);
  ok('rejects a malformed DID', parseHederaDid('did:web:example.com') === null);
  ok('testnet mirror base', mirrorBase('testnet').includes('testnet.mirrornode.hedera.com'));
  ok('mainnet mirror base', mirrorBase('mainnet').includes('mainnet.mirrornode.hedera.com'));
}

console.log('\n1. Registry replay — decode + order + latest-wins + deactivation');
{
  const ops = parseRegistryMessages(asMirror([{ op: 'did-create', didDocument: docFor() }]).messages);
  ok('base64 messages decode to ops', ops.length === 1 && ops[0].op === 'did-create');
  // Out-of-order messages are replayed in sequence order; the later update wins.
  const updated = docFor(KEY, true); updated.service[0].serviceEndpoint = 'https://travel.example.com/magp/v2';
  const outOfOrder = asMirror([{ op: 'did-update', didDocument: updated, _seq: 2 }, { op: 'did-create', didDocument: docFor(), _seq: 1 }]);
  const doc = replayDidRegistry(parseRegistryMessages(outOfOrder.messages), DID);
  ok('latest write wins regardless of API order', doc.service[0].serviceEndpoint.endsWith('/v2'));
  // Deactivation tombstones the DID.
  const deact = replayDidRegistry(parseRegistryMessages(asMirror([{ op: 'did-create', didDocument: docFor() }, { op: 'did-deactivate', subject: DID }]).messages), DID);
  ok('did-deactivate removes the document', deact === null);
  // Malformed JSON messages are skipped, not fatal.
  const withJunk = { messages: [{ sequence_number: 1, message: Buffer.from('not json{').toString('base64') }, ...asMirror([{ op: 'did-create', didDocument: docFor(), _seq: 2 }]).messages] };
  ok('malformed messages are skipped', replayDidRegistry(parseRegistryMessages(withJunk.messages), DID)?.id === DID);
  ok('docVerificationKey extracts the key', docVerificationKey(docFor()) === KEY);
}

console.log('\n2. resolveDidViaMirror — discovery with MetaMynd OFFLINE');
{
  // A mock mirror node (no MetaMynd anywhere in this path).
  const mirror = (payload) => async (url) => ({ ok: true, json: async () => payload });
  const res = await resolveDidViaMirror(DID, { fetchImpl: mirror(asMirror([{ op: 'did-create', didDocument: docFor() }])) });
  ok('resolves the document from the mirror node', res?.document?.id === DID && res.source === 'hcs-mirror');
  ok('surfaces the MAGP service endpoint (channel discovery)', res.service.serviceEndpoint === 'https://travel.example.com/magp');
  ok('confirms the key matches the DID (trustless)', res.verifiedKeyMatch === true);
  // The mirror node is asked for the DID's OWN topic — nothing else.
  let requestedUrl = '';
  await resolveDidViaMirror(DID, { fetchImpl: async (u) => { requestedUrl = u; return { ok: true, json: async () => asMirror([{ op: 'did-create', didDocument: docFor() }]) }; } });
  ok('reads only the DID-embedded topic', requestedUrl.includes(`/topics/${TOPIC}/messages`));
}

console.log('\n3. TRUSTLESS — a lying mirror cannot substitute a different key');
{
  // The mirror serves a document whose key does NOT match the key embedded in the DID.
  const forged = docFor('z6MkATTACKERkeyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  const mirror = async () => ({ ok: true, json: async () => ({ messages: [{ sequence_number: 1, message: Buffer.from(JSON.stringify({ op: 'did-create', didDocument: forged })).toString('base64') }] }) });
  const res = await resolveDidViaMirror(DID, { fetchImpl: mirror });
  ok('a document with a mismatched key is REJECTED', res === null);
}

console.log('\n4. Graceful failure — unreachable mirror / unknown DID → null (caller can fall back)');
{
  ok('a fetch error yields null (not a throw)', (await resolveDidViaMirror(DID, { fetchImpl: async () => { throw new Error('network'); } })) === null);
  ok('a topic with no did-create for this DID yields null', (await resolveDidViaMirror(DID, { fetchImpl: async () => ({ ok: true, json: async () => ({ messages: [] }) }) })) === null);
  ok('a malformed DID yields null', (await resolveDidViaMirror('did:web:x', {})) === null);
}

console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);

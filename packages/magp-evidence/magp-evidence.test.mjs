// magp-evidence.test.mjs — Phase E: a regulator verifies a holder-opened record with MetaMynd
// offline; disclosing one record reveals nothing about any other.
// Run: node integrations/magp-evidence/magp-evidence.test.mjs
import { createHash } from 'node:crypto';
import { evidenceLeaf, verifyMerkleProof, recomputeCommitment, verifyDisclosure, verifyRootAnchored } from './magp-evidence.mjs';

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; console.log(`  ✓ ${name}`); } else { fail++; console.log(`  ✗ ${name}`); } };

// Minimal batch builder (mirrors merkle.ts) so the test can produce real inclusion proofs.
const sha256Hex = (d) => createHash('sha256').update(d).digest('hex');
const hashNodes = (a, b) => sha256Hex(Buffer.concat([Buffer.from(a, 'hex'), Buffer.from(b, 'hex')]));
const nextLevel = (lvl) => { const n = []; for (let i = 0; i < lvl.length; i += 2) n.push(hashNodes(lvl[i], i + 1 < lvl.length ? lvl[i + 1] : lvl[i])); return n; };
const merkleRoot = (leaves) => { let l = leaves.slice(); while (l.length > 1) l = nextLevel(l); return l[0]; };
const merkleProof = (leaves, index) => { const p = []; let l = leaves.slice(), idx = index; while (l.length > 1) { const right = idx % 2 === 1; const pair = right ? idx - 1 : idx + 1; p.push({ sibling: pair < l.length ? l[pair] : l[idx], position: right ? 'left' : 'right' }); l = nextLevel(l); idx = Math.floor(idx / 2); } return p; };

// A batch of governed actions — evidence records carry only HASHES + outcome classes, no cleartext.
const records = [
  { eventId: 'ev-1', action: 'travel.booking', decision: 'allow', agentDid: 'did:hedera:testnet:agent', reasonCode: 'ZK_POLICY_OK', promptHash: 'sha256:aaa', outputHash: 'sha256:bbb', timestamp: '2026-07-13T10:00:00Z' },
  { eventId: 'ev-2', action: 'travel.booking', decision: 'block', agentDid: 'did:hedera:testnet:other', reasonCode: 'SOP_SPEND_CAP', promptHash: 'sha256:ccc', outputHash: 'sha256:ddd', timestamp: '2026-07-13T10:05:00Z' },
  { eventId: 'ev-3', action: 'hotel.booking', decision: 'escalate', agentDid: 'did:hedera:testnet:agent', reasonCode: 'RISK_REVIEW', approver: 'owner-42', promptHash: 'sha256:eee', outputHash: 'sha256:fff', timestamp: '2026-07-13T10:10:00Z' },
];
const leaves = records.map(evidenceLeaf);
const root = merkleRoot(leaves);
// The holder opens record ev-1 (index 0).
const disclose = (i) => ({ record: records[i], leaf: leaves[i], proof: merkleProof(leaves, i), root });

console.log('\n1. Inclusion — the opened record verifies against the anchored batch root');
{
  const pkg = disclose(0);
  const v = verifyDisclosure(pkg);
  ok('a genuine disclosure is VALID', v.valid && v.inclusionValid && v.leafMatches);
  ok('every record in the batch verifies', records.every((_, i) => verifyDisclosure(disclose(i)).valid));
  ok('the leaf is reproduced from the disclosed record', v.leaf === leaves[0]);
}

console.log('\n2. Tamper — altering the record, proof, or root fails');
{
  const pkg = disclose(1);
  const altered = { ...pkg, record: { ...pkg.record, decision: 'allow' } }; // flip block → allow
  ok('a mutated record (decision flipped) is REJECTED', verifyDisclosure(altered).valid === false);
  const wrongRoot = { ...pkg, root: sha256Hex('not-the-root') };
  ok('a wrong batch root is REJECTED', verifyDisclosure(wrongRoot).inclusionValid === false);
  const badProof = { ...pkg, proof: pkg.proof.map((s, i) => (i === 0 ? { ...s, sibling: sha256Hex('x') } : s)) };
  ok('a tampered inclusion proof is REJECTED', verifyDisclosure(badProof).valid === false);
  const claimedLeaf = { ...pkg, leaf: sha256Hex('wrong-leaf') };
  ok('a claimed leaf that does not match the record is REJECTED', verifyDisclosure(claimedLeaf).leafMatches === false);
}

console.log('\n3. Privacy — opening one record reveals nothing about any other');
{
  const pkg = disclose(0);
  const blob = JSON.stringify(pkg);
  // The package holds record 0 + sibling HASHES only — no other record\'s fields appear.
  ok('sibling records\' fields are absent from the disclosure', !blob.includes('SOP_SPEND_CAP') && !blob.includes('ev-2') && !blob.includes('owner-42') && !blob.includes('sha256:ccc'));
  ok('the proof carries only opaque sibling hashes', pkg.proof.every((s) => /^[0-9a-f]{64}$/.test(s.sibling)));
}

console.log('\n4. Commitment opening — disclosed values open to the anchored commitment');
{
  // MetaMynd anchored a salted commitment (never cleartext). The holder reveals {sensitive, salt}.
  const sensitive = { amount: 150, merchant: 'skyward-air' };
  const saltHex = '11'.repeat(32);
  const commitment = recomputeCommitment(sensitive, saltHex); // what was anchored
  const pkg = { ...disclose(0), opening: { sensitive, saltHex, commitment } };
  ok('correct {values, salt} open to the commitment', verifyDisclosure(pkg).commitmentValid === true);
  const lied = { ...pkg, opening: { sensitive: { amount: 5000, merchant: 'skyward-air' }, saltHex, commitment } };
  ok('a lie about the amount does NOT open to the commitment', verifyDisclosure(lied).valid === false);
  const wrongSalt = { ...pkg, opening: { sensitive, saltHex: '22'.repeat(32), commitment } };
  ok('a wrong salt does NOT open to the commitment', verifyDisclosure(wrongSalt).commitmentValid === false);
  ok('commitment format is the anchored "sha256-…" shape', commitment.startsWith('sha256-') && commitment.length === 7 + 64);
}

console.log('\n5. On-chain anchoring — the root is confirmed on the evidence topic (mirror node)');
{
  // A mock Hedera mirror node holding the batch-root anchor (MetaMynd offline).
  const mirror = async () => ({ ok: true, json: async () => ({ messages: [
    { sequence_number: 7, consensus_timestamp: '1700000000.123', message: Buffer.from(JSON.stringify({ op: 'evidence-batch-root', root, size: records.length })).toString('base64') },
  ] }) });
  const a = await verifyRootAnchored(root, '0.0.5000', { fetchImpl: mirror });
  ok('the anchored root is found on-chain with its timestamp', a.anchored === true && a.consensusTimestamp === '1700000000.123');
  const bad = await verifyRootAnchored(sha256Hex('other'), '0.0.5000', { fetchImpl: mirror });
  ok('a root that was never anchored is not found', bad.anchored === false);
  ok('verifyDisclosure with anchoredRoot cross-checks the root', verifyDisclosure(disclose(0), { anchoredRoot: root }).valid === true
    && verifyDisclosure(disclose(0), { anchoredRoot: sha256Hex('x') }).valid === false);
}

console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);

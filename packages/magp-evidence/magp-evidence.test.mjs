// magp-evidence.test.mjs — Phase E: a regulator verifies a holder-opened record with MetaMynd
// offline; disclosing one record reveals nothing about any other.
// Run: node integrations/magp-evidence/magp-evidence.test.mjs
import { createHash } from 'node:crypto';
import {
  evidenceLeaf, verifyMerkleProof, recomputeCommitment, verifyDisclosure, verifyRootAnchored,
  verifyCoverage, verifyPolicyAssignment, readPolicyUpdates, agentPolicyTopicId,
} from './magp-evidence.mjs';

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

console.log('\n6. Coverage — a removed record leaves a gap in its agent\'s sequence');
{
  const A = 'did:hedera:testnet:agentA_0.0.700';
  const B = 'did:hedera:testnet:agentB_0.0.701';
  const seq = (agentDid, agentSeq) => ({ eventId: `${agentDid}#${agentSeq}`, agentDid, agentSeq });
  const whole = [seq(A, 1), seq(A, 2), seq(A, 3), seq(B, 1), seq(B, 2)];
  ok('an unbroken record is complete', verifyCoverage(whole, { fromOne: true }).complete === true);
  const missing = verifyCoverage(whole.filter((r) => r.eventId !== `${A}#2`), { fromOne: true });
  const a = missing.agents.find((x) => x.agentDid === A);
  ok('removing #2 shows the gap 2..2 for that agent only', !missing.complete && a.gaps.length === 1 && a.gaps[0].from === 2 && a.gaps[0].to === 2
    && missing.agents.find((x) => x.agentDid === B).complete);
  ok('a missing start is a gap only when the set is the whole record', !verifyCoverage([seq(A, 2), seq(A, 3)], { fromOne: true }).complete
    && verifyCoverage([seq(A, 2), seq(A, 3)]).complete);
  ok('a number claimed twice is a duplicate', verifyCoverage([seq(A, 1), seq(A, 1), seq(A, 2)]).agents[0].duplicates[0] === 1);
  const legacy = verifyCoverage([{ eventId: 'old', agentDid: A }, seq(A, 1)]);
  ok('records written before sequencing are counted, not treated as gaps', legacy.complete && legacy.unsequenced === 1);
}

console.log('\n7. Policy assignment — the decision used the policy anchored for that agent');
{
  const did = 'did:hedera:testnet:z6MkAgent_0.0.4242';
  const op = (bundleHash, secs) => ({ did, bundleHash, sigDigest: `sha256:sig-${bundleHash}`, consensusTimestamp: `${secs}.000000000` });
  const t0 = Date.parse('2026-10-28T10:00:00Z') / 1000;
  const updates = [op('sha256:v1', t0), op('sha256:v2', t0 + 3600)];
  const rec = (bundleHash, iso) => ({ agentDid: did, bundleHash, timestamp: iso });
  ok('a decision under the policy in force is assigned', verifyPolicyAssignment(rec('sha256:v1', '2026-10-28T10:30:00Z'), updates).status === 'assigned');
  ok('a decision under the newer policy after it took effect is assigned', verifyPolicyAssignment(rec('sha256:v2', '2026-10-28T11:30:00Z'), updates).ok);
  ok('a decision under a policy already replaced is superseded', verifyPolicyAssignment(rec('sha256:v1', '2026-10-28T11:30:00Z'), updates).status === 'superseded');
  ok('a bundle never anchored for the agent is unanchored', verifyPolicyAssignment(rec('sha256:other', '2026-10-28T10:30:00Z'), updates).status === 'unanchored');
  ok('a bundle first anchored well after the decision is flagged', verifyPolicyAssignment(rec('sha256:v2', '2026-10-28T10:30:00Z'), updates).status === 'anchored-after-decision');
  ok('a bundle anchored seconds after the decision (within grace) is assigned', verifyPolicyAssignment(rec('sha256:v2', '2026-10-28T10:59:30Z'), updates).ok);
  ok('a record naming no bundle says so', verifyPolicyAssignment({ agentDid: did, timestamp: '2026-10-28T10:30:00Z' }, updates).status === 'no-bundle');
  ok('another agent\'s policy-update never matches', verifyPolicyAssignment(rec('sha256:v1', '2026-10-28T10:30:00Z'), updates.map((u) => ({ ...u, did: 'did:hedera:testnet:x_0.0.1' }))).status === 'unanchored');

  // readPolicyUpdates pages through the agent's own topic on a mirror node and keeps only its policy-update ops.
  const msg = (o, n, secs) => ({ sequence_number: n, consensus_timestamp: `${secs}.000000000`, message: Buffer.from(JSON.stringify(o)).toString('base64') });
  const pages = {
    '/api/v1/topics/0.0.4242/messages?limit=100&order=asc': { messages: [msg({ op: 'did-create', did }, 1, t0 - 10), msg({ op: 'policy-update', did, sigDigest: 's1', bundleHash: 'sha256:v1' }, 2, t0)], links: { next: '/api/v1/topics/0.0.4242/messages?limit=100&order=asc&sequencenumber=gt:2' } },
    '/api/v1/topics/0.0.4242/messages?limit=100&order=asc&sequencenumber=gt:2': { messages: [msg({ op: 'policy-update', did, sigDigest: 's2' }, 3, t0 + 3600)], links: { next: null } },
  };
  const mirror = async (url) => ({ ok: true, json: async () => pages[new URL(url).pathname + new URL(url).search] });
  const read = await readPolicyUpdates(did, { fetchImpl: mirror });
  ok('reads every page of the agent\'s topic, policy-update ops only', read.length === 2 && read[0].bundleHash === 'sha256:v1' && read[1].sequenceNumber === 3);
  ok('an op published before bundleHash existed reads as null', read[1].bundleHash === null);
  ok('a history longer than maxPages is not returned as if complete', (await readPolicyUpdates(did, { fetchImpl: mirror, maxPages: 1 })) === null);
  ok('a record with no valid timestamp is undated, not unanchored', verifyPolicyAssignment({ agentDid: did, bundleHash: 'sha256:v1', timestamp: 'n/a' }, updates).status === 'undated');
  ok('the topic comes from the DID', agentPolicyTopicId(did) === '0.0.4242' && agentPolicyTopicId('did:key:z6Mk') === null);
}

console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);

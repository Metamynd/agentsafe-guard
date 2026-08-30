// magp-evidence.mjs — MAGP Phase E: the lawful selective-disclosure auditor.
//
// MetaMynd/HCS hold only commitments, outcome-classes, peer signatures, and Merkle roots — never
// routine cleartext. The client/MCP keeps the raw record + its salt. On a lawful request (subpoena,
// regulator order, dispute) the holder opens ONE record; any verifier — with MetaMynd offline —
// confirms it was governed, unaltered, at that time, and that disclosing it reveals nothing about
// any other record. This module is that verifier (the auditor's cryptographic core).
//
// It reproduces EXACTLY the backend's leaf/commitment construction so it verifies REAL anchors:
//   • evidence leaf   = sha256( canonical(record) )                       (evidence-batch.ts)
//   • Merkle root/proof over sha256 leaves, lone node duplicated          (merkle.ts)
//   • tx commitment   = "sha256-" ‖ sha256("MAGP-TX-COMMITMENT-v1\0" ‖ JSON(sensitive) ‖ "\0" ‖ salt)
//                                                                          (mandate.service anchorCommitment)
//
// Zero dependencies: node:crypto + fetch only. A regulator can run it standalone.
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';

const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');
const hashNodes = (a, b) => sha256Hex(Buffer.concat([Buffer.from(a, 'hex'), Buffer.from(b, 'hex')]));

// ── Merkle inclusion (mirrors backend/src/features/magp/merkle.ts) ────────────────────────────
/** Verify a leaf's inclusion proof reproduces the anchored root. `proof` = [{sibling, position}]. */
export function verifyMerkleProof(leaf, proof, root) {
  let computed = leaf;
  for (const step of proof ?? []) {
    computed = step.position === 'left' ? hashNodes(step.sibling, computed) : hashNodes(computed, step.sibling);
  }
  return computed === root;
}

// ── Evidence leaf (mirrors backend/src/features/magp/evidence-batch.ts) ───────────────────────
/** Canonical JSON: keys sorted, undefined→null, as an array of [k, v] pairs — hash-stable. */
function canonical(obj) {
  return JSON.stringify(Object.keys(obj).sort().map((k) => [k, obj[k] ?? null]));
}
/** The reproducible Merkle leaf for an evidence record (hashes-only fields; never cleartext). */
export function evidenceLeaf(record) {
  return sha256Hex(canonical({ ...record }));
}

// ── Transaction commitment opening (mirrors mandate.service anchorCommitment §4.4) ────────────
/** Recompute the anchored commitment from the disclosed sensitive values + the record's salt.
 *  `saltHex` is the raw salt the holder reveals (NOT the server master key). */
export function recomputeCommitment(sensitive, saltHex) {
  return 'sha256-' + createHash('sha256')
    .update('MAGP-TX-COMMITMENT-v1\x00')
    .update(JSON.stringify(sensitive))
    .update('\x00')
    .update(Buffer.from(String(saltHex).replace(/^0x/, ''), 'hex'))
    .digest('hex');
}
/** Verify a disclosed {sensitive, salt} opens to the anchored commitment. */
export function verifyCommitmentOpening({ sensitive, saltHex, commitment }) {
  return !!commitment && recomputeCommitment(sensitive, saltHex) === commitment;
}

// ── On-chain root check (Phase D tie-in — read the evidence topic via a mirror node) ──────────
const mirrorBase = (network) => (network === 'mainnet' ? 'https://mainnet.mirrornode.hedera.com' : 'https://testnet.mirrornode.hedera.com');
/**
 * Confirm `root` was anchored on the evidence HCS topic (op:'evidence-batch-root') by reading the
 * topic from a public Hedera mirror node — MetaMynd offline. Returns
 * { anchored, consensusTimestamp, sequenceNumber } (anchored:false if not found/unreachable).
 */
export async function verifyRootAnchored(root, topicId, opts = {}) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${mirrorBase(opts.network ?? 'testnet')}/api/v1/topics/${topicId}/messages?limit=${opts.limit ?? 200}&order=asc`;
  let body = null;
  try { body = await fetchImpl(url).then((r) => (r.ok ? r.json() : null)); } catch { return { anchored: false, consensusTimestamp: null, sequenceNumber: null }; }
  for (const m of body?.messages ?? []) {
    try {
      const op = JSON.parse(Buffer.from(m.message, 'base64').toString('utf8'));
      if (op.op === 'evidence-batch-root' && op.root === root) {
        return { anchored: true, consensusTimestamp: m.consensus_timestamp ?? null, sequenceNumber: m.sequence_number ?? null };
      }
    } catch { /* skip non-JSON */ }
  }
  return { anchored: false, consensusTimestamp: null, sequenceNumber: null };
}

// ── The auditor's verdict ─────────────────────────────────────────────────────────────────────
/**
 * Verify a lawful-disclosure package. Shape:
 *   {
 *     record:   <EvidenceLeafInput>,          // the opened evidence record (hashes-only fields)
 *     proof:    [{sibling, position}, …],      // Merkle inclusion proof
 *     root:     "<hex>",                        // the batch root the holder claims
 *     leaf?:    "<hex>",                        // optional; recomputed if absent
 *     opening?: { sensitive, saltHex, commitment },  // optional tx-commitment opening
 *     anchor?:  { topicId, consensusTimestamp } // optional; where the root is anchored
 *   }
 * Returns { valid, leafMatches, inclusionValid, commitmentValid, checks[] }. `valid` requires
 * inclusion (and commitment, if an opening is supplied). Root-anchoring is checked separately
 * (verifyRootAnchored) since it needs network; pass `anchoredRoot` to assert it here.
 */
export function verifyDisclosure(pkg, { anchoredRoot } = {}) {
  const checks = [];
  const leaf = evidenceLeaf(pkg.record);
  const leafMatches = pkg.leaf == null || pkg.leaf === leaf;
  checks.push({ check: 'leaf reproduced from the disclosed record', ok: leafMatches });

  const inclusionValid = verifyMerkleProof(leaf, pkg.proof, pkg.root);
  checks.push({ check: 'Merkle inclusion proof reproduces the batch root', ok: inclusionValid });

  let rootAnchored = true;
  if (anchoredRoot != null) {
    rootAnchored = pkg.root === anchoredRoot;
    checks.push({ check: 'batch root matches the on-chain anchored root', ok: rootAnchored });
  }

  let commitmentValid = true;
  if (pkg.opening) {
    commitmentValid = verifyCommitmentOpening(pkg.opening);
    checks.push({ check: 'disclosed values open to the anchored commitment', ok: commitmentValid });
  }

  const valid = leafMatches && inclusionValid && rootAnchored && commitmentValid;
  return { valid, leafMatches, inclusionValid, commitmentValid, rootAnchored, leaf, checks };
}

export const _evidence = { sha256Hex, canonical };

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
// Beyond one record it checks two properties of an agent's record as a whole:
//   • coverage   — every number in each agent's evidence sequence (`agentSeq`) is accounted for (verifyCoverage)
//   • assignment — a decision's `bundleHash` is the policy anchored for that agent on its own HCS topic at the time
//                  (readPolicyUpdates + verifyPolicyAssignment)
//   • egress     — a sandbox network policy someone is shown is the one anchored for the agent (egressPolicyHash,
//                  readEgressPolicyAnchors + verifyEgressPolicy)
//
// Zero dependencies: node:crypto + fetch only. A regulator can run it standalone.
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';

const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');
const hashNodes = (a, b) => sha256Hex(Buffer.concat([Buffer.from(a, 'hex'), Buffer.from(b, 'hex')]));

// ── Merkle inclusion (mirrors the issuer's evidence Merkle tree) ──────────────────────────────
/** Verify a leaf's inclusion proof reproduces the anchored root. `proof` = [{sibling, position}]. */
export function verifyMerkleProof(leaf, proof, root) {
  let computed = leaf;
  for (const step of proof ?? []) {
    computed = step.position === 'left' ? hashNodes(step.sibling, computed) : hashNodes(computed, step.sibling);
  }
  return computed === root;
}

// ── Evidence leaf (mirrors the issuer's evidence-batch leaf encoding) ─────────────────────────
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

// ── Coverage (no record removed) ──────────────────────────────────────────────────────────────
/**
 * Whether a set of evidence records accounts for every number in each agent's sequence. A record written for an agent
 * DID carries `agentSeq` (1, 2, 3… per DID) in its leaf; a missing number is a gap, a number claimed twice a duplicate.
 * Pass `{ fromOne: true }` when the set is the agent's whole record, so a missing start is a gap too. Records without
 * `agentSeq` predate sequencing and are counted as `unsequenced`. A record removed after the highest number held is not
 * detectable here; anchoring bounds that window.
 * Returns { complete, unsequenced, agents: [{ agentDid, first, last, count, gaps: [{from,to}], duplicates, complete }] }.
 */
export function verifyCoverage(records, { fromOne = false } = {}) {
  const byAgent = new Map();
  let unsequenced = 0;
  for (const r of records ?? []) {
    if (!r?.agentDid) continue;
    if (r.agentSeq == null) { unsequenced++; continue; }
    if (!byAgent.has(r.agentDid)) byAgent.set(r.agentDid, []);
    byAgent.get(r.agentDid).push(Number(r.agentSeq));
  }
  const agents = [...byAgent.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([agentDid, seqs]) => {
      seqs.sort((a, b) => a - b);
      const gaps = [];
      const duplicates = [];
      let expected = fromOne ? 1 : seqs[0];
      for (let i = 0; i < seqs.length; i++) {
        const s = seqs[i];
        if (i > 0 && s === seqs[i - 1]) { if (duplicates[duplicates.length - 1] !== s) duplicates.push(s); continue; }
        if (s > expected) gaps.push({ from: expected, to: s - 1 });
        expected = s + 1;
      }
      return { agentDid, first: seqs[0], last: seqs[seqs.length - 1], count: seqs.length, gaps, duplicates, complete: gaps.length === 0 && duplicates.length === 0 };
    });
  return { complete: agents.every((a) => a.complete), unsequenced, agents };
}

// ── Policy assignment (the decision used the policy issued to that agent) ────────────────────
/** A mirror-node consensus timestamp ("seconds.nanoseconds") in milliseconds, or NaN. */
export function consensusToMs(ts) {
  const [s, ns = '0'] = String(ts ?? '').split('.');
  return Number(s) * 1000 + Number(ns.padEnd(9, '0').slice(0, 3));
}

/** The HCS topic a did:hedera DID's policy is anchored on: the part after its last `_`. */
export function agentPolicyTopicId(did) {
  const topic = String(did ?? '').split('_').pop();
  return /^\d+\.\d+\.\d+$/.test(topic) ? topic : null;
}

/**
 * Read an agent's `policy-update` ops from its own HCS topic via a public mirror node, oldest first:
 * [{ did, bundleHash, sigDigest, versionLabel, consensusTimestamp, sequenceNumber }]. `bundleHash` is null on ops
 * published before it was added. Returns null when the topic cannot be read in full — unreachable, or longer than
 * `maxPages` pages of 100 — since a partial history could hide the op that names or supersedes a bundle.
 */
export async function readPolicyUpdates(did, opts = {}) {
  const topicId = opts.topicId ?? agentPolicyTopicId(did);
  if (!topicId) return null;
  return readTopicOps(topicId, opts, (op, m) => (op.op === 'policy-update' && op.did === did ? {
    did: op.did,
    bundleHash: op.bundleHash ?? null,
    sigDigest: op.sigDigest ?? null,
    versionLabel: op.versionLabel ?? null,
    consensusTimestamp: m.consensus_timestamp ?? null,
    sequenceNumber: m.sequence_number ?? null,
  } : null));
}

/**
 * Every message of an HCS topic, oldest first, via a public mirror node, mapped by `pick(op, message)` (null skips it).
 * Null when the topic cannot be read in full: unreachable, or longer than `maxPages` pages of 100.
 */
async function readTopicOps(topicId, opts, pick) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = mirrorBase(opts.network ?? 'testnet');
  let url = `${base}/api/v1/topics/${topicId}/messages?limit=100&order=asc`;
  const out = [];
  for (let page = 0; url && page < (opts.maxPages ?? 50); page++) {
    let body = null;
    try { body = await fetchImpl(url).then((r) => (r.ok ? r.json() : null)); } catch { return null; }
    if (!body) return null;
    for (const m of body.messages ?? []) {
      let op = null;
      try { op = JSON.parse(Buffer.from(m.message, 'base64').toString('utf8')); } catch { continue; /* skip non-JSON */ }
      const picked = op && typeof op === 'object' ? pick(op, m) : null;
      if (picked) out.push(picked);
    }
    url = body.links?.next ? `${base}${body.links.next}` : null;
  }
  return url ? null : out;
}

// ── Egress policy (the sandbox the agent ran in allowed no route around the gateway) ─────────
/**
 * The hash anchored for a sandbox's egress policy: "sha256:" + hex sha256 over the policy text exactly as the runtime
 * reports it (OpenShell `sandbox get <name> --policy-only`), with line endings normalised to LF and trailing whitespace
 * at the end of the text removed — so a copy saved on another platform, or with a final newline added, still matches.
 */
export function egressPolicyHash(policyText) {
  const normalised = String(policyText).replace(/\r\n?/g, '\n').replace(/\s+$/, '');
  return `sha256:${sha256Hex(Buffer.from(normalised, 'utf8'))}`;
}

/**
 * Read the `egress-policy` ops anchored for an agent, oldest first:
 * [{ did, runtime, sandboxId, egressPolicyHash, generation, consensusTimestamp, sequenceNumber }]. They are on the
 * agent's own topic when its DID names one; pass `topicId` for an agent whose DID does not (the issuer's
 * `egress-policies` topic). Null when the topic cannot be read in full.
 */
export async function readEgressPolicyAnchors(did, opts = {}) {
  const topicId = opts.topicId ?? agentPolicyTopicId(did);
  if (!topicId) return null;
  return readTopicOps(topicId, opts, (op, m) => (op.op === 'egress-policy' && op.did === did ? {
    did: op.did,
    runtime: op.runtime ?? null,
    sandboxId: op.sandboxId ?? null,
    egressPolicyHash: op.egressPolicyHash ?? null,
    generation: op.generation ?? null,
    consensusTimestamp: m.consensus_timestamp ?? null,
    sequenceNumber: m.sequence_number ?? null,
  } : null));
}

/**
 * Whether a policy someone has been shown is the one anchored for an agent's sandbox. Returns
 * { ok, hash, anchor, latest } — `anchor` the most recent op with this hash (and `sandboxId`, when given), `latest`
 * whether no op with a different hash was anchored for that sandbox after it (one means the policy changed since). A
 * policy changed and then changed back is current again. `ok` needs a matching anchor only.
 */
export function verifyEgressPolicy(policyText, anchors, { sandboxId } = {}) {
  const hash = egressPolicyHash(policyText);
  const id = sandboxId ? String(sandboxId).toLowerCase() : null;
  const ordered = [...(anchors ?? [])]
    .filter((a) => !id || a.sandboxId === id)
    .sort((a, b) => consensusToMs(a.consensusTimestamp) - consensusToMs(b.consensusTimestamp));
  const index = ordered.findLastIndex((a) => a.egressPolicyHash === hash);
  if (index < 0) return { ok: false, hash, anchor: null, latest: false };
  const anchor = ordered[index];
  const later = ordered.slice(index + 1).some((a) => a.sandboxId === anchor.sandboxId && a.egressPolicyHash !== hash);
  return { ok: true, hash, anchor, latest: !later };
}

/**
 * Whether an evidence record was decided under the policy issued to its agent at the time. `record` is the disclosed
 * leaf record (its `bundleHash` and `timestamp`); `updates` are the agent's `policy-update` ops (readPolicyUpdates).
 * `graceMs` (default 2 minutes) absorbs the gap between a policy taking effect and its op reaching consensus.
 *
 * Status:
 *   assigned                  the bundle was the agent's anchored policy when the record was decided
 *   superseded                a different policy had been anchored for the agent before the decision
 *   anchored-after-decision   the bundle was first anchored more than `graceMs` after the decision
 *   unanchored                no policy-update for the agent names this bundle
 *   undated                   the bundle is anchored, but the record has no valid timestamp to place it against
 *   no-bundle                 the record names no bundle
 *
 * The record's `timestamp` is the issuer's; it is bounded by the consensus time of the batch root the record is
 * included in (verifyRootAnchored), which a verifier should check as well.
 */
export function verifyPolicyAssignment(record, updates, { graceMs = 120_000 } = {}) {
  const result = (status, extra = {}) => ({ ok: status === 'assigned', status, anchoredAt: null, supersededAt: null, ...extra });
  if (!record?.bundleHash) return result('no-bundle');
  const ordered = [...(updates ?? [])]
    .filter((u) => !record.agentDid || u.did === record.agentDid)
    .map((u) => ({ ...u, at: consensusToMs(u.consensusTimestamp) }))
    .filter((u) => Number.isFinite(u.at))
    .sort((a, b) => a.at - b.at);
  const first = ordered.find((u) => u.bundleHash === record.bundleHash);
  if (!first) return result('unanchored');
  const anchoredAt = first.consensusTimestamp;
  const decidedAt = Date.parse(record.timestamp);
  if (!Number.isFinite(decidedAt)) return result('undated', { anchoredAt });
  if (first.at > decidedAt + graceMs) return result('anchored-after-decision', { anchoredAt });
  // Superseded only by a policy anchored AFTER this bundle and more than graceMs before the decision. An older op in force
  // at the decision time (the bundle reached consensus just after it, within grace) does not count.
  const inForce = ordered.filter((u) => u.at <= decidedAt).pop();
  if (inForce && inForce.bundleHash !== record.bundleHash && inForce.at > first.at && inForce.at < decidedAt - graceMs) {
    return result('superseded', { anchoredAt, supersededAt: inForce.consensusTimestamp });
  }
  return result('assigned', { anchoredAt });
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

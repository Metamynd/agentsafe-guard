# magp-evidence — lawful selective-disclosure auditor (MAGP Phase E)

MetaMynd and HCS hold only **commitments, outcome-classes, peer signatures, and Merkle roots** —
never routine cleartext. The client/MCP keeps the raw record and its salt. On a **lawful request**
(subpoena, regulator order, dispute) the holder opens **one** record; any verifier — **with MetaMynd
offline** — confirms it was governed, unaltered, at that time, and that opening it reveals nothing
about any other record. This package is that verifier.

## What it proves (the §1 disclosure model)

Given a disclosure package a holder opened, the auditor checks:

1. **Leaf integrity** — the evidence Merkle leaf recomputes from the disclosed record.
2. **Inclusion** — the Merkle proof reproduces the anchored batch **root**.
3. **On-chain anchoring** — that root was anchored on the evidence HCS topic
   (`op:'evidence-batch-root'`), read from a public Hedera **mirror node** (Phase D), with its
   consensus timestamp — so *this record was governed, at that time*.
4. **Commitment opening** (optional) — the disclosed `{values, salt}` open to the anchored
   `sha256-…` transaction commitment — so *these exact amount/merchant were the ones governed*.

Because the proof carries only **sibling hashes** and each commitment has an **independent salt**,
disclosing one record reveals nothing about any other.

## What it proves about an agent's whole record

Two further checks run over a set of an agent's disclosed records:

5. **Coverage** (`verifyCoverage`) — each record written for an agent DID carries `agentSeq`
   (1, 2, 3… per DID) in its leaf. The check reports every gap and every number claimed twice,
   so a record removed from the set is visible. Pass `{ fromOne: true }` when the set is the
   agent's whole record. Records written before sequencing existed are counted as `unsequenced`.
   A record removed after the highest number held is not detectable this way; anchoring bounds
   that window.
6. **Policy assignment** (`readPolicyUpdates` + `verifyPolicyAssignment`) — a decision's leaf
   carries `bundleHash`, the compiled policy bundle it was judged under. The issuer publishes the
   same hash in a `policy-update` op on the agent's own HCS topic (the topic named in its
   `did:hedera` DID) each time it issues the agent a new bundle. The check reads that topic from a
   mirror node and reports `assigned`, `superseded` (a newer policy had been issued before the
   decision), `anchored-after-decision`, `unanchored`, `undated` or `no-bundle`. `readPolicyUpdates`
   returns null rather than a partial history when the topic cannot be read in full.

```js
import { verifyCoverage, readPolicyUpdates, verifyPolicyAssignment } from './magp-evidence.mjs';
const coverage = verifyCoverage(records, { fromOne: true });          // { complete, agents: [{ gaps, duplicates, … }] }
const updates = await readPolicyUpdates(record.agentDid);            // the agent's policy-update ops, oldest first
const assignment = verifyPolicyAssignment(record, updates);          // { ok, status, anchoredAt, supersededAt }
```

## It matches the backend exactly

`evidenceLeaf`, the Merkle verification, and `recomputeCommitment` reproduce the backend's
construction byte-for-byte (`evidence-batch.ts`, `merkle.ts`, `mandate.service` `anchorCommitment`),
verified by a cross-check that builds a batch with the backend and verifies it with this module — so
the auditor verifies **real** on-chain anchors, not a re-implementation.

## Use

```bash
# Verify a holder-opened disclosure package (offline: leaf + inclusion + commitment):
node integrations/magp-evidence/auditor.mjs disclosure.json

# Also confirm the batch root is anchored on-chain via a Hedera mirror node (MetaMynd offline):
node integrations/magp-evidence/auditor.mjs disclosure.json --topic 0.0.5000 --network testnet
```

Programmatic:

```js
import { verifyDisclosure, verifyRootAnchored } from './magp-evidence.mjs';
const v = verifyDisclosure(pkg);                 // { valid, checks[], leaf, … }
const a = await verifyRootAnchored(pkg.root, topicId); // { anchored, consensusTimestamp }
```

Disclosure package shape: `{ record, proof, root, leaf?, opening?: { sensitive, saltHex, commitment }, anchor? }`.

## Run tests

```bash
node integrations/magp-evidence/magp-evidence.test.mjs   # 34 assertions
```

## Status / caveats

- **Zero dependencies** (node:crypto + fetch). Standalone — a regulator can run it without MetaMynd.
- The **holder** must retain each record's salt for the regulatory retention period (losing a salt
  makes that record unopenable — but never forgeable). Retention/escrow is a client policy, not
  MetaMynd's (§1).
- Live mirror-node reads are network-dependent; the offline checks (leaf + inclusion + commitment)
  need no network.

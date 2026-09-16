/**
 * Canonical signed-message builder for a signer daemon's log-checkpoint anchor request
 * (docs/design/agent-key-custody-local-signer-daemon-plan.md, T11 — periodically hash-chaining
 * the daemon's own local log and anchoring a digest through the platform's existing HCS evidence
 * infrastructure).
 *
 * The signature is an Ed25519 signature over the UTF-8 string formed by joining these six
 * fields, in this exact order, with the `|` (U+007C) delimiter:
 *
 *   agentDid | checkpointHash | previousCheckpointHash | entryCount | nonce | issuedAt
 *
 * Lives in policy-core for the same reason buildAuthMessage (canonical.ts) does: the signer
 * daemon (integrations/agentsafe-signer/daemon.mjs's `sign-log-checkpoint` operation) and the
 * backend endpoint that verifies and anchors the checkpoint must independently build IDENTICAL
 * bytes — a single generated source avoids the hand-copy drift that has caused real interop bugs
 * elsewhere in this system (see agentsafe-signer's own README "Status" history).
 */

import { escapeField } from './canonical.js';

export interface CheckpointAnchorMessageFields {
  agentDid: string;
  checkpointHash: string;
  previousCheckpointHash: string;
  entryCount: number;
  nonce: string;
  issuedAt: string;
}

/** Build the canonical UTF-8 message a verifier reconstructs from received fields. */
export function buildCheckpointAnchorMessage(f: CheckpointAnchorMessageFields): string {
  return [f.agentDid, f.checkpointHash, f.previousCheckpointHash, f.entryCount, f.nonce, f.issuedAt]
    .map((v) => escapeField(String(v)))
    .join('|');
}

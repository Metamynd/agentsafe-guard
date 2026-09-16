import { describe, it, expect } from 'vitest';
import { buildCheckpointAnchorMessage } from './checkpoint-anchor.js';

const base = {
  agentDid: 'did:hedera:testnet:zAgent_0.0.1',
  checkpointHash: 'a'.repeat(64),
  previousCheckpointHash: 'b'.repeat(64),
  entryCount: 12,
  nonce: 'n-1',
  issuedAt: '2026-01-01T00:00:00.000Z',
};

describe('buildCheckpointAnchorMessage', () => {
  it('joins the six fields with | in the documented order', () => {
    expect(buildCheckpointAnchorMessage(base)).toBe(
      `${base.agentDid}|${base.checkpointHash}|${base.previousCheckpointHash}|${base.entryCount}|${base.nonce}|${base.issuedAt}`,
    );
  });

  it('is identical for the same inputs regardless of call order (deterministic, no hidden state)', () => {
    expect(buildCheckpointAnchorMessage({ ...base })).toBe(buildCheckpointAnchorMessage({ ...base }));
  });

  it('a different checkpointHash produces a different message (nothing is silently ignored)', () => {
    const a = buildCheckpointAnchorMessage(base);
    const b = buildCheckpointAnchorMessage({ ...base, checkpointHash: 'c'.repeat(64) });
    expect(a).not.toBe(b);
  });

  it('escapes a literal | the same way buildAuthMessage does, so a malformed agentDid cannot shift field boundaries', () => {
    const withPipe = buildCheckpointAnchorMessage({ ...base, agentDid: 'did:key:z|evil' });
    expect(withPipe).toBe(`did:key:z\\|evil|${base.checkpointHash}|${base.previousCheckpointHash}|${base.entryCount}|${base.nonce}|${base.issuedAt}`);
  });
});

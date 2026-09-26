import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AUTH_MESSAGE_V2_TAG, buildAuthMessage } from './canonical.js';

/**
 * Conformance vectors for the v2 authorize message (spec §8.3.12): docs/protocol/authorize-v2-vectors.json. A separate file
 * from the v1 vectors on purpose — every client that pins authorize-vectors.json asserts eight fields, and must keep passing
 * until it implements v2. An SDK that signs `jurisdiction` reproduces these before it is trusted with a real request.
 */
const doc = JSON.parse(readFileSync(join(process.cwd(), '..', 'docs', 'protocol', 'authorize-v2-vectors.json'), 'utf8')) as {
  fieldOrder: string[];
  versionTag: string;
  seed: string;
  publicKey: string;
  vectors: { name: string; fields: Record<string, string | number | null>; message: string; signature: string }[];
};
const privateKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(doc.seed, 'hex')]), format: 'der', type: 'pkcs8' });
const publicKey = crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(doc.publicKey, 'hex')]), format: 'der', type: 'spki' });

describe('authorize-message v2 conformance vectors (docs/protocol/authorize-v2-vectors.json)', () => {
  it('declares the v2 shape: the eight v1 fields, the version tag, the jurisdiction', () => {
    expect(doc.versionTag).toBe(AUTH_MESSAGE_V2_TAG);
    expect(doc.fieldOrder).toEqual(['agentDid', 'action', 'amount', 'currency', 'merchant', 'resource', 'nonce', 'issuedAt', 'MAGP-AUTH-v2', 'jurisdiction']);
    expect(doc.publicKey).toBe('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'); // RFC 8032 test vector 1
  });

  for (const v of doc.vectors) {
    it(`${v.name}: buildAuthMessage reproduces the message, and the seed reproduces the signature`, () => {
      const f = v.fields;
      const message = buildAuthMessage({
        agentDid: f.agentDid as string,
        action: f.action as string,
        amount: f.amount as number,
        currency: f.currency as string,
        merchant: (f.merchant as string | null) ?? undefined,
        resource: (f.resource as string | null) ?? undefined,
        nonce: f.nonce as string,
        issuedAt: f.issuedAt as string,
        jurisdiction: (f.jurisdiction as string | null) ?? undefined,
      });
      expect(message).toBe(v.message);
      expect(message.endsWith(`|${AUTH_MESSAGE_V2_TAG}|${f.jurisdiction}`)).toBe(f.jurisdiction !== null);
      expect(crypto.verify(null, Buffer.from(v.message, 'utf8'), publicKey, Buffer.from(v.signature, 'hex'))).toBe(true);
      expect(crypto.sign(null, Buffer.from(v.message, 'utf8'), privateKey).toString('hex')).toBe(v.signature);
    });
  }

  it('a v2 signature never verifies as the v1 message of the same request (so stripping the field fails the signature)', () => {
    const v2 = doc.vectors.find((v) => v.name === 'v2 minimal jurisdiction')!;
    const v1 = doc.vectors.find((v) => v.name === 'v1 control (no jurisdiction)')!;
    expect(crypto.verify(null, Buffer.from(v1.message, 'utf8'), publicKey, Buffer.from(v2.signature, 'hex'))).toBe(false);
    expect(crypto.verify(null, Buffer.from(v2.message, 'utf8'), publicKey, Buffer.from(v1.signature, 'hex'))).toBe(false);
  });
});

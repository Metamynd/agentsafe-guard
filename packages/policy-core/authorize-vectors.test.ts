import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildAuthMessage } from './canonical.js';

/**
 * The shared conformance vectors for the signed authorize message (spec §8.3): docs/protocol/authorize-vectors.json.
 *
 * The Python client shipped a SEVEN-field signer to PyPI while the gate required EIGHT, and nothing noticed: the
 * client's own selftest asserted hand-written strings, and no test anywhere compared it to the TypeScript builder,
 * so every request from the published package failed CLIENT_PROTOCOL_VERSION_UNSUPPORTED. This file is one half of
 * the fix. The other half is integrations/metamynd-client/tests/test_protocol_vectors.py, which reads the SAME file:
 * change the message format here and the vectors (and therefore the Python client's test) fail until both agree.
 */
const FILE = join(process.cwd(), '..', 'docs', 'protocol', 'authorize-vectors.json');
const doc = JSON.parse(readFileSync(FILE, 'utf8')) as {
  algorithm: string;
  fieldOrder: string[];
  delimiter: string;
  seed: string;
  publicKey: string;
  vectors: { name: string; note: string; fields: Record<string, unknown>; message: string; signature: string }[];
};

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(doc.seed, 'hex')]), format: 'der', type: 'pkcs8' });
const publicKey = crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(doc.publicKey, 'hex')]), format: 'der', type: 'spki' });

/** Split on an UNESCAPED delimiter, so a literal "\|" inside a field is not counted as a field boundary. */
function splitFields(message: string): string[] {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < message.length; i++) {
    const c = message[i];
    if (c === '\\') { cur += c + (message[i + 1] ?? ''); i++; continue; }
    if (c === '|') { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

describe('authorize-message conformance vectors (docs/protocol/authorize-vectors.json)', () => {
  it('declares the protocol it pins: Ed25519, "|" delimited, eight fields in this exact order', () => {
    expect(doc.algorithm).toBe('Ed25519');
    expect(doc.delimiter).toBe('|');
    expect(doc.fieldOrder).toEqual(['agentDid', 'action', 'amount', 'currency', 'merchant', 'resource', 'nonce', 'issuedAt']);
    expect(doc.vectors.length).toBeGreaterThanOrEqual(10);
  });

  it('the seed is the PUBLIC RFC 8032 test vector 1 key (a test key, never a secret) and derives the published public key', () => {
    expect(doc.seed).toBe('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    expect(crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex')).toBe(doc.publicKey);
    expect(doc.publicKey).toBe('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  });

  for (const v of (doc.vectors ?? [])) {
    describe(v.name, () => {
      const f = v.fields as Record<string, string | number | null>;
      const rebuilt = () =>
        buildAuthMessage({
          agentDid: f.agentDid as string,
          action: f.action as string,
          amount: f.amount as number,
          currency: f.currency as string,
          merchant: (f.merchant as string | null) ?? undefined,
          resource: (f.resource as string | null) ?? undefined,
          nonce: f.nonce as string,
          issuedAt: f.issuedAt as string,
        });

      it('buildAuthMessage reproduces the stored message byte for byte', () => {
        expect(rebuilt()).toBe(v.message);
      });

      it('the message has exactly eight fields (escaped delimiters are not boundaries)', () => {
        expect(splitFields(v.message)).toHaveLength(8);
      });

      it('the stored signature is Ed25519 over the UTF-8 message under the published key — and is what the seed produces', () => {
        expect(crypto.verify(null, Buffer.from(v.message, 'utf8'), publicKey, Buffer.from(v.signature, 'hex'))).toBe(true);
        expect(crypto.sign(null, Buffer.from(v.message, 'utf8'), privateKey).toString('hex')).toBe(v.signature); // deterministic
      });

      it('changing any one field breaks the signature (the message is bound to every field)', () => {
        const tampered = v.message.replace(/^(.*?)\|/, '$1x|'); // alter the first field
        expect(crypto.verify(null, Buffer.from(tampered, 'utf8'), publicKey, Buffer.from(v.signature, 'hex'))).toBe(false);
      });
    });
  }

  it('the vectors cover the traps that have each broken a client: float text, escaping, resource, unicode, absent fields', () => {
    const names = doc.vectors.map((v) => v.name).join(' | ');
    for (const needle of ['integral float', 'delimiter in a field', 'merchant and resource', 'unicode', 'minimal', 'resource only', 'large integral', 'sub-cent amount', 'exponent form small', 'exponent form large', 'integer beyond 2**53']) expect(names).toContain(needle);
    // JavaScript's own spelling, which Python's repr() gets wrong: "5e-05" vs "0.00005", "1e-07" vs "1e-7"
    expect(doc.vectors.find((v) => v.name === 'sub-cent amount')!.message).toContain('|0.00005|');
    expect(doc.vectors.find((v) => v.name === 'exponent form small')!.message).toContain('|1.5e-7|');
    expect(doc.vectors.find((v) => v.name === 'exponent form large')!.message).toContain('|1e+21|');
    // the integral float vector is the "150" vs "150.0" trap: its message must carry the JavaScript form
    expect(doc.vectors.find((v) => v.name === 'integral float')!.message).toContain('|150|');
    expect(doc.vectors.find((v) => v.name === 'large integral')!.message).toContain('|100000000000000000000|');
  });
});

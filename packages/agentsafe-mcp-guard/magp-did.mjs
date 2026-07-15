// GENERATED from backend/src/features/magp/did.ts — do not edit. Regenerate: npm run build:mcp-guard-core

// src/features/magp/did.ts
import crypto from "node:crypto";

// src/features/agent-identity/did.util.ts
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = carry / 58 | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = carry / 58 | 0;
    }
  }
  let out = "";
  for (let k = 0; k < zeros; k++) out += BASE58_ALPHABET[0];
  for (let q = digits.length - 1; q >= 0; q--) out += BASE58_ALPHABET[digits[q]];
  return out;
}
function multibaseBase58btc(bytes) {
  return "z" + base58(bytes);
}
function buildHederaDid(network, publicKeyBytes, topicId) {
  return `did:hedera:${network}:${multibaseBase58btc(publicKeyBytes)}_${topicId}`;
}
function base58Decode(str) {
  const bytes = [0];
  for (const ch of str) {
    const value = BASE58_ALPHABET.indexOf(ch);
    if (value === -1) throw new Error(`invalid base58 character '${ch}'`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 255;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 255);
      carry >>= 8;
    }
  }
  let zeros = 0;
  for (let k = 0; k < str.length && str[k] === BASE58_ALPHABET[0]; k++) zeros++;
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i];
  return out;
}
function parseHederaDid(did) {
  const m = /^did:hedera:(mainnet|testnet|previewnet|devnet):(z[1-9A-HJ-NP-Za-km-z]+)_(\d+\.\d+\.\d+)$/.exec(did ?? "");
  if (!m) return null;
  const [, network, publicKeyMultibase, topicId] = m;
  let publicKeyBytes;
  try {
    publicKeyBytes = base58Decode(publicKeyMultibase.slice(1));
  } catch {
    return null;
  }
  if (publicKeyBytes.length !== 32) return null;
  return { network, publicKeyMultibase, publicKeyBytes, topicId };
}
var ED25519_MULTICODEC = Uint8Array.of(237, 1);
function buildDidKey(publicKeyBytes) {
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + publicKeyBytes.length);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(publicKeyBytes, ED25519_MULTICODEC.length);
  return `did:key:${multibaseBase58btc(prefixed)}`;
}
function parseDidKey(did) {
  const m = /^did:key:(z[1-9A-HJ-NP-Za-km-z]+)$/.exec(did ?? "");
  if (!m) return null;
  const multibase = m[1];
  let decoded;
  try {
    decoded = base58Decode(multibase.slice(1));
  } catch {
    return null;
  }
  if (decoded.length !== ED25519_MULTICODEC.length + 32) return null;
  if (decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) return null;
  return { method: "key", publicKeyMultibase: multibase, publicKeyBytes: decoded.slice(ED25519_MULTICODEC.length) };
}
function didPublicKeyBytes(did) {
  return parseHederaDid(did)?.publicKeyBytes ?? parseDidKey(did)?.publicKeyBytes ?? null;
}

// src/features/magp/did.ts
var ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function ed25519KeyFromRaw(raw) {
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}
function verifyDidSignature(did, message, signatureHex) {
  const publicKeyBytes = didPublicKeyBytes(did);
  if (!publicKeyBytes) return false;
  try {
    const key = ed25519KeyFromRaw(publicKeyBytes);
    return crypto.verify(null, Buffer.from(message, "utf8"), key, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}
function buildDidDocument(did, service) {
  const hedera = parseHederaDid(did);
  const key = hedera ? null : parseDidKey(did);
  if (!hedera && !key) return null;
  const publicKeyMultibase = hedera ? hedera.publicKeyMultibase : key.publicKeyMultibase;
  const fragment = hedera ? "#did-root-key" : `#${key.publicKeyMultibase}`;
  const vmId = `${did}${fragment}`;
  const doc = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    controller: did,
    verificationMethod: [
      {
        id: vmId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase
      }
    ],
    authentication: [vmId]
  };
  if (service) {
    doc.service = [
      {
        id: `${did}#magp`,
        type: "MAGPEndpoint",
        serviceEndpoint: service.serviceEndpoint,
        channels: service.channels,
        protoVersions: service.protoVersions
      }
    ];
  }
  return doc;
}
export {
  base58,
  base58Decode,
  buildDidDocument,
  buildDidKey,
  buildHederaDid,
  didPublicKeyBytes,
  ed25519KeyFromRaw,
  multibaseBase58btc,
  parseDidKey,
  parseHederaDid,
  verifyDidSignature
};

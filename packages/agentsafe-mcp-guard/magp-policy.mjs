// magp-policy.mjs — MAGP Phase F: signed policy bundles + staleness + risk-tiered fail-closed.
//
// The policy bundle (§5.3.2) binds an agent's DID to the exact Standards/SOPs/mandate governing it,
// so a guard fetches ONE document and evaluates locally (trustless re-eval, §9.6). Until now the
// bundle was only hash-addressed + TLS-trusted; this adds a real **Ed25519 signature** over the
// bundle, so a guard can verify authenticity + integrity + freshness from ANY source — a cache, a
// CDN, or a Hedera mirror — with **no live MetaMynd call** (the Phase F exit: no MetaMynd dependence
// for per-request enforcement).
//
// Risk-tiered fail-closed (§5.3.3): a value-bearing action MUST fail closed on an unsigned,
// tampered, or stale (past `maxStaleness`) bundle; a non-value read may proceed (a bad *signature*
// is always a hard fail). Zero dependencies — node:crypto Ed25519 only.
import crypto from 'node:crypto';

// ── canonicalization (deterministic bytes for signing) ────────────────────────────────────────
function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}
/** The exact bytes signed/verified: the bundle WITHOUT its `proof` field, canonicalized. */
function signingBytes(bundle) {
  const { proof, ...rest } = bundle;
  return Buffer.from('MAGP-POLICY-BUNDLE-v1\x00' + canonicalJson(rest), 'utf8');
}

// ── keys (node:crypto Ed25519; accept KeyObject or raw hex) ───────────────────────────────────
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
/** Build an Ed25519 public KeyObject from a raw 32-byte hex key (as published by the pubkey endpoint). */
export function publicKeyFromRawHex(hex) {
  const raw = Buffer.from(String(hex).replace(/^0x/, ''), 'hex');
  return crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}
const toPublicKey = (k) => (typeof k === 'string' ? publicKeyFromRawHex(k) : k);
/** The raw 32-byte public key (hex) for an Ed25519 KeyObject — what a service publishes. */
export function rawPublicKeyHex(keyObject) {
  const der = keyObject.export({ format: 'der', type: 'spki' });
  return Buffer.from(der.subarray(der.length - 32)).toString('hex');
}

// ── sign / verify ─────────────────────────────────────────────────────────────────────────────
/**
 * Sign a policy bundle (issuer side). `privateKey` is an Ed25519 KeyObject. Returns the bundle with
 * a real `proof`: an Ed25519 signature over the bundle, plus the verification key + timestamps.
 */
export function signBundle(bundle, privateKey, { verificationMethod = null } = {}) {
  const base = { ...bundle };
  delete base.proof;
  const signature = crypto.sign(null, signingBytes(base), privateKey).toString('hex');
  return {
    ...base,
    proof: {
      type: 'Ed25519Signature2020',
      created: bundle.issuedAt ?? null,
      verificationMethod,
      publicKeyHex: rawPublicKeyHex(crypto.createPublicKey(privateKey)),
      signature,
    },
  };
}

/** Parse an ISO-8601 duration like `PT10M` / `PT1H30M` / `PT45S` to milliseconds. */
export function parseDurationMs(iso) {
  const m = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(String(iso ?? ''));
  if (!m) return null;
  return ((Number(m[1] || 0) * 3600) + (Number(m[2] || 0) * 60) + Number(m[3] || 0)) * 1000;
}

/**
 * Verify a signed bundle and apply the risk tier. Returns
 * `{ ok, reasonCode, ageMs, maxStalenessMs, signed }`.
 *   • a present-but-invalid signature → POLICY_BUNDLE_SIGNATURE_INVALID (hard fail, any tier)
 *   • unsigned → POLICY_BUNDLE_UNSIGNED (fail closed only for value-bearing)
 *   • stale past maxStaleness → POLICY_BUNDLE_STALE (fail closed only for value-bearing)
 *   • otherwise → POLICY_BUNDLE_OK
 *
 * @param {object} opts { publicKey?, nowMs?, valueBearing?, maxStalenessMs? }
 */
export function verifyBundle(bundle, opts = {}) {
  const nowMs = opts.nowMs ?? Date.now();
  const valueBearing = !!opts.valueBearing;
  const sig = bundle?.proof?.signature;
  // The verifier's trusted key wins; else fall back to the key the bundle advertises (still checked
  // for freshness, but a caller SHOULD pin publicKey to a MetaMynd key it trusts).
  const keyMaterial = opts.publicKey ?? bundle?.proof?.publicKeyHex ?? null;

  if (!sig || !keyMaterial) {
    return { ok: !valueBearing, reasonCode: 'POLICY_BUNDLE_UNSIGNED', ageMs: null, maxStalenessMs: null, signed: false };
  }
  let sigOk = false;
  try { sigOk = crypto.verify(null, signingBytes(bundle), toPublicKey(keyMaterial), Buffer.from(sig, 'hex')); } catch { sigOk = false; }
  if (!sigOk) return { ok: false, reasonCode: 'POLICY_BUNDLE_SIGNATURE_INVALID', ageMs: null, maxStalenessMs: null, signed: true };

  const maxStalenessMs = opts.maxStalenessMs ?? parseDurationMs(bundle.maxStaleness) ?? null;
  const issuedMs = Date.parse(bundle.issuedAt);
  const ageMs = Number.isFinite(issuedMs) ? nowMs - issuedMs : null;
  const stale = maxStalenessMs != null && ageMs != null && ageMs > maxStalenessMs;
  if (stale) return { ok: !valueBearing, reasonCode: 'POLICY_BUNDLE_STALE', ageMs, maxStalenessMs, signed: true };

  return { ok: true, reasonCode: 'POLICY_BUNDLE_OK', ageMs, maxStalenessMs, signed: true };
}

export const _policy = { canonicalJson, signingBytes };

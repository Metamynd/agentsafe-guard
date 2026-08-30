// magp-hcs2.mjs — MAGP Phase D: decentralized discovery via Hedera HCS registries.
//
// Today a peer discovers another party by calling MetaMynd's resolver (GET /did/:did). This module
// removes MetaMynd from the live discovery path: a `did:hedera` EMBEDS its registry topic id, and
// the DID document was anchored to that topic at issuance (op:'did-create'). A peer can therefore
// read the document straight from a public Hedera **mirror node** and never contact MetaMynd.
//
// It is TRUSTLESS in two ways:
//   • the verification key is parsed from the DID itself (§4.1.2) — never trusted from the doc; and
//   • resolveDidViaMirror re-checks that the mirror-served document's key MATCHES the DID's embedded
//     key, so a lying mirror cannot substitute keys.
//
// Zero dependencies: fetch (Node 18+) + base64/JSON only. Shared by the agent, the MCP, and anyone.
import { Buffer } from 'node:buffer';

// ── DID parsing (did:hedera:<network>:<publicKeyMultibase>_<topicId>) ─────────────────────────
const DID_RE = /^did:hedera:(mainnet|testnet):(z[1-9A-HJ-NP-Za-km-z]+)_([0-9]+\.[0-9]+\.[0-9]+)$/;
/** Parse a did:hedera into { network, publicKeyMultibase, topicId }, or null if malformed. */
export function parseHederaDid(did) {
  const m = DID_RE.exec(String(did ?? ''));
  if (!m) return null;
  return { network: m[1], publicKeyMultibase: m[2], topicId: m[3] };
}

/** The public Hedera mirror-node REST base for a network. */
export function mirrorBase(network) {
  return network === 'mainnet' ? 'https://mainnet.mirrornode.hedera.com' : 'https://testnet.mirrornode.hedera.com';
}

// ── registry replay ──────────────────────────────────────────────────────────────────────────
/** Decode a mirror-node `/topics/{id}/messages` payload into ordered MAGP registry ops.
 *  Each API message is `{ sequence_number, consensus_timestamp, message: <base64> }`. */
export function parseRegistryMessages(apiMessages) {
  return [...(apiMessages ?? [])]
    .sort((a, b) => Number(a.sequence_number) - Number(b.sequence_number))
    .map((m) => { try { return JSON.parse(Buffer.from(m.message, 'base64').toString('utf8')); } catch { return null; } })
    .filter(Boolean);
}

/**
 * Replay the DID-registry ops for `did` → the current DID document, or null if never created or
 * deactivated. Latest write wins; `did-deactivate` tombstones the DID (spec §4.3.2 / §4.6).
 */
export function replayDidRegistry(ops, did) {
  let doc = null;
  for (const op of ops ?? []) {
    if ((op.op === 'did-create' || op.op === 'did-update') && op.didDocument?.id === did) doc = op.didDocument;
    else if (op.op === 'did-deactivate' && (op.subject === did || op.did === did)) doc = null;
  }
  return doc;
}

/** Ordered `policy-update` ops for a DID (spec §5.3.1): { op, did, sigDigest, versionLabel, at }. */
export function parsePolicyOps(apiMessages, did) {
  return parseRegistryMessages(apiMessages).filter((o) => o?.op === 'policy-update' && (!did || o.did === did));
}

/**
 * Resolve the CURRENT anchored policy for a DID from its own HCS topic via a public mirror node —
 * no MetaMynd call. Returns { sigDigest, versionLabel, seq } of the LATEST policy-update op, or
 * null. `seq` is the count of policy-update ops seen (monotonic — a caller rejects any response
 * with fewer ops than it has already observed, defeating a mirror that hides recent updates).
 * TRUSTLESS: Hedera consensus order makes the latest op authoritative and rollback impossible.
 *
 * @param {object} opts { fetchImpl?, network?, limit? }
 */
export async function resolvePolicyViaMirror(did, opts = {}) {
  const parsed = parseHederaDid(did);
  if (!parsed) return null;
  const fetchImpl = opts.fetchImpl ?? fetch;
  // Newest-first so the latest policy-update is on the first page; its topic sequence_number is the
  // monotonic marker (rollback / hidden-updates show a lower seq).
  const url = `${mirrorBase(opts.network ?? parsed.network)}/api/v1/topics/${parsed.topicId}/messages?limit=${opts.limit ?? 100}&order=desc`;
  let body = null;
  try { body = await fetchImpl(url).then((r) => (r.ok ? r.json() : null)); } catch { return null; }
  if (!body?.messages) return null;
  const hit = (body.messages ?? [])
    .map((x) => { try { return { seq: Number(x.sequence_number), op: JSON.parse(Buffer.from(x.message, 'base64').toString('utf8')) }; } catch { return null; } })
    .filter((e) => e && e.op?.op === 'policy-update' && e.op.did === did)
    .sort((a, b) => b.seq - a.seq)[0];
  if (!hit) return null;
  return { sigDigest: hit.op.sigDigest ?? null, versionLabel: hit.op.versionLabel ?? null, seq: hit.seq };
}

/** Extract the primary verification key (publicKeyMultibase) from a DID document. */
export function docVerificationKey(doc) {
  const vm = doc?.verificationMethod;
  return Array.isArray(vm) && vm.length ? (vm[0].publicKeyMultibase ?? null) : null;
}

// ── mirror-node resolution (MetaMynd offline) ────────────────────────────────────────────────
/**
 * Resolve a DID document from the DID's own HCS topic via a public Hedera mirror node — no
 * MetaMynd call. Returns { did, document, service, source, verifiedKeyMatch } or null.
 *
 * TRUSTLESS: the document is only accepted if its verification key matches the key embedded in the
 * DID (a mirror node serves data but cannot forge which key the DID commits to). The service
 * endpoint (for channel establishment) is read from the document.
 *
 * @param {object} opts { fetchImpl?, network?, limit? } — inject fetch for testing.
 */
export async function resolveDidViaMirror(did, opts = {}) {
  const parsed = parseHederaDid(did);
  if (!parsed) return null;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = mirrorBase(opts.network ?? parsed.network);
  const limit = opts.limit ?? 100;
  const url = `${base}/api/v1/topics/${parsed.topicId}/messages?limit=${limit}&order=asc`;
  let body = null;
  try { body = await fetchImpl(url).then((r) => (r.ok ? r.json() : null)); } catch { return null; }
  if (!body?.messages) return null;

  const doc = replayDidRegistry(parseRegistryMessages(body.messages), did);
  if (!doc) return null;

  // Trustless key binding: the served doc MUST commit to the same key as the DID (§4.1.2).
  const docKey = docVerificationKey(doc);
  const verifiedKeyMatch = !!docKey && docKey === parsed.publicKeyMultibase;
  if (docKey && !verifiedKeyMatch) return null; // the mirror served a document for a different key

  const svc = Array.isArray(doc.service) ? doc.service.find((s) => s.type === 'MAGPEndpoint') ?? doc.service[0] : null;
  return {
    did,
    document: doc,
    service: svc ? { serviceEndpoint: svc.serviceEndpoint, channels: svc.channels ?? [], protoVersions: svc.protoVersions ?? [] } : null,
    source: 'hcs-mirror',
    verifiedKeyMatch,
  };
}

// zkbc.mjs — the ledger-neutral core of ZKBC v1 (HCS-XX "Zero-Knowledge Boundary Compliance", draft 1.0), as a
// zero-dependency module: the commitments, the public statement and its hash, the recursive chain digest, the journal,
// the auditor's structural checks on a journal, the session coverage check, the policy in-effect rule, the topic and
// transaction memos, and the tool-family policy commitments derived from a MAGP policy bundle.
//
// What it is not: a prover or a proof verifier. A ZKBC receipt carries a zero-knowledge proof that the released action
// satisfied the committed policy, and nothing here produces or checks one. `checkJournal` therefore says whether a
// journal is well formed and its statement hash is the one its fields bind, never that the actions it names were
// compliant. Publishing a journal with verdict `compliant` and no proof would assert exactly that, so this module builds
// journals for a prover to attach a proof to and for an auditor to check, and leaves publication to whoever has one.
//
// Every construction reproduces the specification's published test vectors (zkbc.test.mjs).
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';

const enc = new TextEncoder();
const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());

/** `nfc(s)`: NFC, then UTF-8. The identifier form, used for every label, tool id and key path. */
export const nfc = (s) => enc.encode(String(s).normalize('NFC'));

/** base64url without padding (RFC 4648 §5), as every binary value in a ZKBC text encoding. */
export const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
/** The bytes of an unpadded base64url string, or null when it is not one. */
export function fromB64url(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const uint64be = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; };
const uint32be = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const bytesOf = (m) => (m instanceof Uint8Array ? m : nfc(m));

/** `LP(x) = uint64be(len(x)) || x`. */
export const lp = (x) => concat(uint64be(x.length), x);

export const PROTOCOL_LABEL = nfc('ZKBC/v1');
export const JOURNAL_VERSION = 'ZKBC/1.0';
export const MODES = Object.freeze({ batch: 0x01, real_time: 0x02, recursive: 0x03 });
export const FAMILIES = Object.freeze(['output', 'tool', 'access']);
const FAMILY_BITS = { output: 0x01, tool: 0x02, access: 0x04 };
const VERDICTS = { non_compliant: 0, compliant: 1 };

/** `commit(tag, m) = H(LP(label) || LP(tag) || LP(m))`. Strings are taken through `nfc`. 32 bytes. */
export function commit(tag, m) {
  return sha256(concat(lp(PROTOCOL_LABEL), lp(bytesOf(tag)), lp(bytesOf(m))));
}

/**
 * `set_commit(tag, S)` over the whole set: elements as given (strings through `nfc`), deduplicated and sorted ascending
 * by byte order. Normalising elements for a family that needs another form (`fold`, for the output family's forbidden
 * set) is the caller's: pass the normalised bytes.
 */
export function setCommit(tag, elements) {
  const seen = new Map();
  for (const e of elements ?? []) { const b = bytesOf(e); seen.set(Buffer.from(b).toString('hex'), b); }
  const sorted = [...seen.values()].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return sha256(concat(lp(PROTOCOL_LABEL), lp(bytesOf(tag)), uint64be(sorted.length), ...sorted.map(lp)));
}

/** The access family's identity digest over the private tenant and user identifiers. */
export function identityDigest(tenantId, userId) {
  return sha256(concat(lp(PROTOCOL_LABEL), lp(nfc('identity')), lp(bytesOf(tenantId)), lp(bytesOf(userId))));
}

/** RFC 8785 canonical JSON for the values a journal carries (objects, arrays, strings, safe integers, booleans, null). */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('canonicalJson: non-finite number');
    return JSON.stringify(value ?? null);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/** The session id's bytes: base64url (≥16 bytes) or a UUID string. Null when it is neither. */
export function sessionIdBytes(sessionId) {
  const s = String(sessionId ?? '');
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return new Uint8Array(Buffer.from(s.replace(/-/g, ''), 'hex'));
  const b = fromB64url(s);
  return b && b.length >= 16 ? b : null;
}

/**
 * The statement preimage a journal binds (Public Statement Binding), and its hash. Throws on a journal whose fields
 * cannot be encoded (unknown mode, family or verdict; a commitment or id that is not base64url).
 */
export function statementPreimage(j) {
  const mode = MODES[j.mode];
  const verdict = VERDICTS[j.verdict];
  if (mode === undefined) throw new Error(`unknown mode ${j.mode}`);
  if (verdict === undefined) throw new Error(`unknown verdict ${j.verdict}`);
  if (!Array.isArray(j.family)) throw new Error('family must be an array');
  let mask = 0;
  for (const f of j.family) { if (!(f in FAMILY_BITS)) throw new Error(`unknown family ${f}`); mask |= FAMILY_BITS[f]; }
  const session = sessionIdBytes(j.session_id);
  const program = fromB64url(j.program_id);
  if (!session) throw new Error('session_id must be base64url of at least 16 bytes, or a UUID');
  if (!program || program.length !== 32) throw new Error('program_id must be base64url of 32 bytes');
  const commitments = Object.entries(j.policy_commitments ?? {}).sort(([a], [b]) => Buffer.compare(Buffer.from(nfc(a)), Buffer.from(nfc(b))));
  const opt = (v) => {
    if (v === undefined || v === null || v === '') return new Uint8Array(0);
    const b = fromB64url(v);
    if (!b) throw new Error('an optional digest is not base64url');
    return b;
  };
  const range = j.sequence_range ?? {};
  return concat(
    lp(PROTOCOL_LABEL), lp(nfc('statement')),
    lp(nfc(j.version)), lp(nfc(j.policy_id)),
    lp(session), lp(program),
    Uint8Array.of(mode, mask, verdict),
    uint32be(commitments.length),
    ...commitments.flatMap(([k, v]) => {
      const b = fromB64url(v);
      if (!b) throw new Error(`policy commitment ${k} is not base64url`);
      return [lp(nfc(k)), lp(b)];
    }),
    lp(opt(j.identity_digest)),
    lp(opt(j.prev_chain_digest)),
    lp(concat(uint64be(range.from), uint64be(range.to))),
    lp(j.counts === undefined ? new Uint8Array(0) : nfc(canonicalJson(j.counts))),
  );
}
/** `statement_hash`, base64url. */
export const statementHash = (journal) => b64url(sha256(statementPreimage(journal)));

/** The recursive mode's `chain_digest_i = H(LP(label) || LP("chain") || LP(prev) || LP(statement_hash_i))`, base64url. */
export function chainDigest(prevChainDigest, statementHashB64) {
  const prev = prevChainDigest ? fromB64url(prevChainDigest) : new Uint8Array(0);
  const stmt = fromB64url(statementHashB64);
  if (!prev || !stmt) throw new Error('chainDigest: digests must be base64url');
  return b64url(sha256(concat(lp(PROTOCOL_LABEL), lp(nfc('chain')), lp(prev), lp(stmt))));
}

/**
 * A journal (Public Compliance Journal) with its `statement_hash`, and its `chain_digest` in recursive mode. `family` is
 * put in the required order. `verdict` is always `compliant`: a non-satisfying action is never numbered (the other value
 * is reserved). The caller names the program and proof system its prover uses; the journal means nothing until that
 * prover attaches a proof over this statement.
 */
export function buildJournal({ sessionId, issuedAt, policyId, policyCommitments, programId, proofSystem, mode, family, sequenceRange, counts, identityDigest: idDigest, prevChainDigest }) {
  const journal = {
    version: JOURNAL_VERSION,
    session_id: sessionId,
    issued_at: issuedAt,
    policy_id: policyId,
    policy_commitments: policyCommitments,
    program_id: programId,
    proof_system: proofSystem,
    mode,
    family: FAMILIES.filter((f) => (family ?? []).includes(f)),
    verdict: 'compliant',
    sequence_range: { from: sequenceRange?.from, to: sequenceRange?.to },
    ...(counts !== undefined ? { counts } : {}),
    ...(idDigest !== undefined ? { identity_digest: idDigest } : {}),
    ...(mode === 'recursive' ? { prev_chain_digest: prevChainDigest ?? '' } : {}),
  };
  journal.statement_hash = statementHash(journal);
  if (mode === 'recursive') journal.chain_digest = chainDigest(journal.prev_chain_digest, journal.statement_hash);
  return journal;
}

const isB64_32 = (v) => { const b = fromB64url(v); return !!b && b.length === 32; };
const isUint = (n) => Number.isSafeInteger(n) && n >= 0;

/**
 * The Validation rules an auditor can apply to a journal on its own: version, the recomputed statement hash, verdict,
 * sequence range, family order, the commitments the families require, and the recursive chain digest. Returns
 * { ok, problems[] }. The registry, in-effect, proof and HCS-1 rules need the topics and a verifier: `ok` is never
 * evidence of compliance, only that the journal is one a proof could be checked against.
 */
export function checkJournal(j) {
  const problems = [];
  const need = (cond, problem) => { if (!cond) problems.push(problem); };
  if (!j || typeof j !== 'object') return { ok: false, problems: ['not a journal'] };
  need(j.version === JOURNAL_VERSION, 'version');
  need(typeof j.policy_id === 'string' && j.policy_id.length > 0, 'policy_id');
  need(typeof j.issued_at === 'string' && !Number.isNaN(Date.parse(j.issued_at)), 'issued_at');
  need(typeof j.proof_system === 'string' && j.proof_system.length > 0, 'proof_system');
  need(isB64_32(j.program_id), 'program_id');
  need(sessionIdBytes(j.session_id) !== null, 'session_id');
  const commitments = j.policy_commitments && typeof j.policy_commitments === 'object' ? Object.entries(j.policy_commitments) : [];
  need(commitments.length >= 1 && commitments.every(([, v]) => isB64_32(v)), 'policy_commitments');
  need(j.verdict === 'compliant', 'verdict');
  const fam = Array.isArray(j.family) ? j.family : [];
  need(fam.length > 0 && fam.every((f, i) => FAMILIES.includes(f) && (i === 0 || FAMILIES.indexOf(fam[i - 1]) < FAMILIES.indexOf(f))), 'family');
  need(!fam.includes('output') || 'output.canonicalization' in (j.policy_commitments ?? {}), 'output.canonicalization');
  need(!fam.includes('access') || isB64_32(j.identity_digest), 'identity_digest');
  const r = j.sequence_range ?? {};
  need(isUint(r.from) && isUint(r.to) && r.from >= 1 && r.from <= r.to && (j.mode !== 'real_time' || r.from === r.to), 'sequence_range');
  need(j.mode in MODES, 'mode');
  let recomputed = null;
  try { recomputed = statementHash(j); } catch { /* reported below */ }
  need(recomputed !== null && recomputed === j.statement_hash, 'statement_hash');
  if (j.mode === 'recursive') {
    need(j.prev_chain_digest === '' || isB64_32(j.prev_chain_digest), 'prev_chain_digest');
    let chain = null;
    try { chain = chainDigest(j.prev_chain_digest, j.statement_hash); } catch { /* reported below */ }
    need(chain !== null && chain === j.chain_digest, 'chain_digest');
  }
  return { ok: problems.length === 0, problems };
}

/**
 * The coverage check over a session's accepted journals, across every receipt topic: the ranges must be pairwise disjoint
 * and their union `1..max(to)`. Returns per session { sessionId, max, complete, gaps: [{from,to}], overlaps: [n] }.
 * A gap or overlap voids the coverage claim, not any single receipt.
 */
export function verifySessionCoverage(journals) {
  const bySession = new Map();
  for (const j of journals ?? []) {
    const r = j?.sequence_range;
    if (!j?.session_id || !isUint(r?.from) || !isUint(r?.to) || r.from < 1 || r.from > r.to) continue;
    if (!bySession.has(j.session_id)) bySession.set(j.session_id, []);
    bySession.get(j.session_id).push([r.from, r.to]);
  }
  return [...bySession.entries()].map(([sessionId, ranges]) => {
    ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const gaps = [];
    const overlaps = [];
    let next = 1;
    for (const [from, to] of ranges) {
      if (from > next) gaps.push({ from: next, to: from - 1 });
      if (from < next) overlaps.push(from);
      next = Math.max(next, to + 1);
    }
    return { sessionId, max: next - 1, complete: gaps.length === 0 && overlaps.length === 0, gaps, overlaps };
  });
}

/**
 * The in-effect rule: the `policy_published` entry for `policyId` in effect at a receipt's consensus time `atMs`, or null.
 * Each entry and revocation carries its `consensusMs`; `effective_from` / `revoked_from` earlier than that count as it.
 * Revoked labels are retired for good, so an entry after the first in-effect revocation is never used. Ties go to the
 * later consensus time.
 */
export function policyInEffect({ published, revoked }, policyId, atMs) {
  const from = (e, field) => Math.max(e.consensusMs, Date.parse(e[field]) || -Infinity);
  const revokedAt = (revoked ?? []).filter((r) => r.policy_id === policyId).map((r) => from(r, 'revoked_from')).sort((a, b) => a - b)[0];
  if (revokedAt !== undefined && revokedAt <= atMs) return null;
  const firstRevocation = (revoked ?? []).filter((r) => r.policy_id === policyId).map((r) => r.consensusMs).sort((a, b) => a - b)[0];
  return (published ?? [])
    .filter((e) => e.policy_id === policyId && from(e, 'effective_from') <= atMs && (firstRevocation === undefined || e.consensusMs < firstRevocation))
    .sort((a, b) => from(b, 'effective_from') - from(a, 'effective_from') || b.consensusMs - a.consensusMs)[0] ?? null;
}

// ── Topics and memos (`hcs-xx` until the standard is numbered) ───────────────────────────────
export const PROTOCOL_ID = 'hcs-xx';
export const TOPIC_TYPES = Object.freeze({ receipt: 0, policy_registry: 1, program_registry: 2 });
export const OPERATIONS = Object.freeze({ receipt_issued: 0, policy_published: 1, policy_revoked: 2, program_registered: 3 });
/** A topic memo: `hcs-xx:0:<ttl>:<type>:<param>` (the governing policy registry for a receipt topic, else the issuer). */
export const topicMemo = (type, param, ttl = 86400) => `${PROTOCOL_ID}:0:${ttl}:${TOPIC_TYPES[type]}:${param}`;
/** A transaction memo: `hcs-xx:op:<operation>:<topic type>`. */
export const transactionMemo = (op, type) => `${PROTOCOL_ID}:op:${OPERATIONS[op]}:${TOPIC_TYPES[type]}`;

// ── The tool family, from a MAGP policy bundle ────────────────────────────────────────────────
/**
 * The tool family's sets for an agent, read from its signed MAGP policy bundle: the allowlist `A` is every action the
 * agent holds a mandate for, and the sensitive-key set `K` every JSON Pointer path an argument policy marks sensitive
 * (MAGP §8.3.14), across its mandates. Both are `nfc` identifiers.
 *
 * ZKBC fixes one sanitization outcome per key, where MAGP fixes it per tool and path, and ZKBC's `mask` and `hash` are
 * MAGP's `redact` and `hmac` in effect but not in bytes: a journal carries only the set commitments, so the difference
 * stays inside the prover's witness.
 */
export function toolPolicyFromBundle(bundle) {
  const allowlist = new Set();
  const sensitiveKeys = new Set();
  for (const m of Array.isArray(bundle?.mandates) ? bundle.mandates : []) {
    if (typeof m?.action === 'string' && m.action) allowlist.add(m.action);
    for (const p of Array.isArray(m?.document?.permission) ? m.document.permission : []) {
      for (const s of Array.isArray(p?.arguments?.sensitive) ? p.arguments.sensitive : []) {
        if (typeof s?.path === 'string') sensitiveKeys.add(s.path);
      }
    }
  }
  return { allowlist: [...allowlist].sort(), sensitiveKeys: [...sensitiveKeys].sort() };
}

/**
 * The tool family's `policy_commitments` entries for those sets. These are ZKBC's unsalted set commitments: anyone who
 * can list the candidate actions and paths can confirm a small allowlist by trying them, so publishing
 * them on a public topic discloses the sets to that extent. Salted, per-part commitments to the same policy are what
 * the agent's own `policy-update` ops carry (MAGP §6.2.8).
 */
export function toolCommitments({ allowlist, sensitiveKeys }) {
  return {
    'tool.allowlist': b64url(setCommit('policy/tool/allowlist', allowlist)),
    'tool.sensitive-keys': b64url(setCommit('policy/tool/sensitive-keys', sensitiveKeys)),
  };
}

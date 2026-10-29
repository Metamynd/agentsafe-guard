// zkbc.test.mjs — the ZKBC v1 core reproduces every digest the specification publishes (HCS-XX draft 1.0, Test
// Vectors), and the auditor's journal, coverage and in-effect checks behave as its Validation section requires.
// Run: node integrations/magp-evidence/zkbc.test.mjs
import { Buffer } from 'node:buffer';
import {
  b64url, commit, setCommit, identityDigest, statementHash, chainDigest, buildJournal, checkJournal,
  verifySessionCoverage, policyInEffect, topicMemo, transactionMemo, toolPolicyFromBundle, toolCommitments, nfc, canonicalJson,
} from './zkbc.mjs';

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; console.log(`  ✓ ${name}`); } else { fail++; console.log(`  ✗ ${name}`); } };
const hex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

console.log('1. The specification\'s test vectors');
const programId = b64url(hex('7a6b5c4d3e2f10010203040506070809a0b1c2d3e4f5061728394a5b6c7d8e9f'));
const sessionId = b64url(hex('4a1f9c0e8b7d6a5f4e3c2b1a09876543'));
const descriptor = '{"identifier_form":"nfc","matching_form":"nfkc+casefold","tokenizer":"uax29-words","unicode":"16.0.0"}';
const forbidden = b64url(setCommit('policy/output/forbidden', ['ssn', 'credit_card']));
const canonicalization = b64url(commit('policy/canonicalization', descriptor));
ok('program_id', programId === 'emtcTT4vEAECAwQFBgcICaCxwtPk9QYXKDlKW2x9jp8');
ok('session_id', sessionId === 'Sh-cDot9al9OPCsaCYdlQw');
ok('set_commit forbidden', forbidden === 'bhvFupsp0G827gHRZoI0GVvoryPXhZEnqFvU-v9TbwU');
ok('set_commit allowlist (order and duplicates do not matter)', b64url(setCommit('policy/tool/allowlist', ['search', 'calculator', 'email.send', 'search'])) === '6DIBHki0Y_W8SCJGEBcbQ9GtqVXQwn7eqbRP1uT_p6g');
ok('set_commit sensitive keys', b64url(setCommit('policy/tool/sensitive-keys', ['to', 'ssn', 'password'])) === 'MGm2aiwVvB7qr6sZi23lXTx8Scbd3yGpYIGmgQl6JlM');
ok('commit canonicalization descriptor', canonicalization === 'Hjqh1F8wQGk4ird2ieABh7z51GFvBdmuSAiSfKsLAWQ');
ok('identity_digest', b64url(identityDigest('acme', 'alice@acme.example')) === '9D17KQnykuItOrT_8T8MvBdToKflK-Xc5TpsIK4v54k');
ok('vk_id', b64url(commit('vk', hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'))) === '761BxFWRjz9Ye36ZQMcsnIJrjs2frx4Zi8LFYpEs4ys');

const base = {
  sessionId, issuedAt: '2026-07-09T12:00:00Z', policyId: 'acme.pii.v3', programId, proofSystem: 'stark_v1', family: ['output'],
  policyCommitments: { 'output.forbidden': forbidden, 'output.canonicalization': canonicalization },
};
const rt = buildJournal({ ...base, mode: 'real_time', sequenceRange: { from: 1, to: 1 }, counts: { output: { token_count: 128, distinct_token_count: 42, hit_count: 0 } } });
ok('statement_hash real_time', rt.statement_hash === '3G4E9re7hfevvMcL0ua9mVvjBiLbrLq72kuryUTpAF0');
const batch = buildJournal({ ...base, mode: 'batch', sequenceRange: { from: 1, to: 3 } });
ok('statement_hash batch', batch.statement_hash === 'JQkHNtF0yDqTPFpVQMMfJ2EF8LC2Ajdy_wWWTtzRFDI');
const r0 = buildJournal({ ...base, mode: 'recursive', sequenceRange: { from: 1, to: 3 } });
ok('statement_hash recursive #0', r0.statement_hash === 'Q9gW471uRmIHzK2VrVDRrBRuax3v2mvN-De1TAkJ6Dg');
ok('chain_digest recursive #0', r0.chain_digest === 'Gn_susg9G4WHbo6E78tYrDEo7LGD65OIIB50G6NC1ew');
const r1 = buildJournal({ ...base, mode: 'recursive', sequenceRange: { from: 4, to: 5 }, prevChainDigest: r0.chain_digest });
ok('statement_hash recursive #1', r1.statement_hash === '31Xka7cAiRbD9GDNEyWH3oeQ3Aknw8wlhcxf4UmP298');
ok('chain_digest recursive #1', r1.chain_digest === 'uS9qoR41YFg9HgUC5qZmMuQqKgVlqXDjdUXruQO2iK4');
ok('chainDigest is the same construction', chainDigest(r0.chain_digest, r1.statement_hash) === r1.chain_digest);

// The conforming journal the specification prints, as an auditor would read it off a topic.
const printed = {
  version: 'ZKBC/1.0', session_id: 'Sh-cDot9al9OPCsaCYdlQw', issued_at: '2026-07-09T12:00:00Z', policy_id: 'acme.pii.v3',
  policy_commitments: { 'output.canonicalization': 'Hjqh1F8wQGk4ird2ieABh7z51GFvBdmuSAiSfKsLAWQ', 'output.forbidden': 'bhvFupsp0G827gHRZoI0GVvoryPXhZEnqFvU-v9TbwU' },
  program_id: 'emtcTT4vEAECAwQFBgcICaCxwtPk9QYXKDlKW2x9jp8', proof_system: 'stark_v1', mode: 'real_time', family: ['output'], verdict: 'compliant',
  statement_hash: '3G4E9re7hfevvMcL0ua9mVvjBiLbrLq72kuryUTpAF0', sequence_range: { from: 1, to: 1 },
  counts: { output: { token_count: 128, distinct_token_count: 42, hit_count: 0 } },
};
ok('the printed journal checks', checkJournal(printed).ok && statementHash(printed) === printed.statement_hash);
ok('the built journal is byte-identical to the printed one after RFC 8785', canonicalJson(rt) === canonicalJson(printed));
ok('memo vectors', topicMemo('receipt', '0.0.600002') === 'hcs-xx:0:86400:0:0.0.600002' && topicMemo('policy_registry', '0.0.500100') === 'hcs-xx:0:86400:1:0.0.500100'
  && topicMemo('program_registry', '0.0.500100') === 'hcs-xx:0:86400:2:0.0.500100' && transactionMemo('receipt_issued', 'receipt') === 'hcs-xx:op:0:0' && transactionMemo('policy_published', 'policy_registry') === 'hcs-xx:op:1:1');

console.log('\n2. Validation: the spec\'s expected outcomes, and the other structural gates');
const problems = (j) => checkJournal(j).problems;
ok('verdict changed to non_compliant: rejected (statement hash no longer matches, value reserved)', problems({ ...printed, verdict: 'non_compliant' }).includes('statement_hash') && problems({ ...printed, verdict: 'non_compliant' }).includes('verdict'));
ok('sequence_range changed to 2..2: rejected', problems({ ...printed, sequence_range: { from: 2, to: 2 } }).includes('statement_hash'));
ok('real_time with from ≠ to: rejected', problems({ ...printed, sequence_range: { from: 1, to: 2 } }).includes('sequence_range'));
ok('from = 0: rejected', problems(buildJournal({ ...base, mode: 'batch', sequenceRange: { from: 0, to: 2 } })).includes('sequence_range'));
ok('family out of order: rejected', problems({ ...printed, family: ['tool', 'output'] }).includes('family'));
ok('family with a duplicate: rejected', problems({ ...printed, family: ['output', 'output'] }).includes('family'));
ok('empty family: rejected', problems({ ...printed, family: [] }).includes('family'));
ok('output without output.canonicalization: rejected', problems({ ...printed, policy_commitments: { 'output.forbidden': forbidden } }).includes('output.canonicalization'));
ok('access without identity_digest: rejected', problems(buildJournal({ ...base, family: ['access'], mode: 'batch', sequenceRange: { from: 1, to: 1 } })).includes('identity_digest'));
ok('a tampered commitment: rejected', problems({ ...printed, policy_commitments: { ...printed.policy_commitments, 'output.forbidden': canonicalization } }).includes('statement_hash'));
ok('an unknown version: rejected', problems({ ...printed, version: 'ZKBC/2.0' }).includes('version'));
ok('a recursive journal checks, and a broken chain does not', checkJournal(r1).ok && problems({ ...r1, chain_digest: r0.chain_digest }).includes('chain_digest'));
ok('a re-pointed chain changes the statement hash', problems({ ...r1, prev_chain_digest: '' }).includes('statement_hash'));
ok('build puts family in the required order', buildJournal({ ...base, family: ['tool', 'output'], mode: 'batch', sequenceRange: { from: 1, to: 1 } }).family.join() === 'output,tool');
ok('a UUID session id is accepted', checkJournal(buildJournal({ ...base, sessionId: '4a1f9c0e-8b7d-6a5f-4e3c-2b1a09876543', mode: 'batch', sequenceRange: { from: 1, to: 1 } })).ok);

console.log('\n3. Session coverage');
const j = (s, from, to) => ({ session_id: s, sequence_range: { from, to } });
const cov = (list) => verifySessionCoverage(list);
ok('contiguous ranges across topics and modes are complete', cov([j('a', 4, 5), j('a', 1, 3), j('a', 6, 6)])[0].complete && cov([j('a', 4, 5), j('a', 1, 3)])[0].max === 5);
ok('a second receipt covering position 1 voids coverage (overlap)', cov([j('a', 1, 1), j('a', 1, 1)])[0].overlaps.join() === '1');
ok('a missing start is a gap', JSON.stringify(cov([j('a', 3, 4)])[0].gaps) === JSON.stringify([{ from: 1, to: 2 }]));
ok('a hole in the middle is a gap', JSON.stringify(cov([j('a', 1, 2), j('a', 5, 5)])[0].gaps) === JSON.stringify([{ from: 3, to: 4 }]));
ok('sessions are checked separately', cov([j('a', 1, 1), j('b', 2, 2)]).find((s) => s.sessionId === 'a').complete && !cov([j('a', 1, 1), j('b', 2, 2)]).find((s) => s.sessionId === 'b').complete);

console.log('\n4. The in-effect rule');
const t = (s) => Date.parse(s);
const entry = (policy_id, consensus, effective_from) => ({ policy_id, consensusMs: t(consensus), effective_from });
const reg = {
  published: [entry('acme.pii.v3', '2026-07-01T00:00:00Z', '2026-07-01T00:00:00Z'), entry('acme.pii.v3', '2026-07-05T00:00:00Z', '2026-07-10T00:00:00Z')],
  revoked: [{ policy_id: 'acme.pii.v3', consensusMs: t('2026-07-20T00:00:00Z'), revoked_from: '2026-07-01T00:00:00Z' }],
};
ok('the first entry is in effect before the pre-published one takes effect', policyInEffect(reg, 'acme.pii.v3', t('2026-07-08T00:00:00Z')) === reg.published[0]);
ok('the pre-published entry takes over at its effective_from', policyInEffect(reg, 'acme.pii.v3', t('2026-07-12T00:00:00Z')) === reg.published[1]);
ok('nothing is in effect before the first publication', policyInEffect(reg, 'acme.pii.v3', t('2026-06-30T00:00:00Z')) === null);
ok('a revocation cannot reach back before its own consensus time', policyInEffect(reg, 'acme.pii.v3', t('2026-07-19T00:00:00Z')) === reg.published[1]);
ok('after the revocation nothing is in effect', policyInEffect(reg, 'acme.pii.v3', t('2026-07-21T00:00:00Z')) === null);
ok('a label reused after revocation is ignored', policyInEffect({ ...reg, revoked: [{ policy_id: 'acme.pii.v3', consensusMs: t('2026-08-01T00:00:00Z'), revoked_from: '2026-09-01T00:00:00Z' }], published: [...reg.published, entry('acme.pii.v3', '2026-08-02T00:00:00Z', '2026-08-02T00:00:00Z')] }, 'acme.pii.v3', t('2026-08-03T00:00:00Z')) === reg.published[1]);

console.log('\n5. The tool family from a MAGP bundle');
const bundle = { mandates: [
  { action: 'send-email', document: { permission: [{ target: 'send-email', arguments: { allow: ['/to', '/body'], sensitive: [{ path: '/to', mode: 'hmac' }, { path: '/body', mode: 'redact' }] } }] } },
  { action: 'search', document: { permission: [{ target: 'search' }] } },
  { action: 'send-email', document: { permission: [{ target: 'send-email', arguments: { allow: ['/to'], sensitive: [{ path: '/to', mode: 'redact' }] } }] } },
] };
const tool = toolPolicyFromBundle(bundle);
ok('the allowlist is the mandated actions, once each', tool.allowlist.join() === 'search,send-email');
ok('the sensitive keys are every sensitive path, once each', tool.sensitiveKeys.join() === '/body,/to');
const tc = toolCommitments(tool);
ok('its commitments are ZKBC set commitments', tc['tool.allowlist'] === b64url(setCommit('policy/tool/allowlist', ['send-email', 'search'])) && tc['tool.sensitive-keys'] === b64url(setCommit('policy/tool/sensitive-keys', ['/to', '/body'])));
ok('a tool-family journal over them checks', checkJournal(buildJournal({ ...base, family: ['tool'], policyCommitments: tc, mode: 'batch', sequenceRange: { from: 1, to: 2 }, counts: { tool: { invocation_count: 2, argument_count: 3, sensitive_argument_count: 2 } } })).ok);
ok('identifiers are NFC: a decomposed é names the same tool as a composed one', b64url(setCommit('t', ['café'])) === b64url(setCommit('t', ['café'])) && nfc('é').length === 2);
ok('an empty bundle gives empty sets that still commit', toolPolicyFromBundle({}).allowlist.length === 0 && toolCommitments(toolPolicyFromBundle({}))['tool.allowlist'].length === 43);

console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);

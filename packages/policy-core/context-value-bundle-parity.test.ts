import { basename, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as source from './index.js';

/**
 * Bundle parity for the owner-keyed context atoms (pre-beta rerun 6, NF-RISK-SELF). A gateway evaluates SOPs locally with
 * the policy-core bundle it ships; if a bundle were not regenerated, the hosted gate would escalate `op: delete-all` and a
 * gateway judging from its bundle would let it run. Each committed bundle must reach the same verdict, the same signal
 * and the same normalisation as the source on every vector below.
 */
const ALL_BUNDLES = [
  'integrations/agentsafe-guard/policy-core.mjs',
  'integrations/agentsafe-mcp-guard/policy-core.mjs',
  'integrations/agentsafe-a2a-guard/policy-core.mjs',
  'integrations/agentsafe-signer/policy-core.mjs',
  'frontend/src/lib/policy-core.mjs',
];

/**
 * This file runs in two layouts: backend/src/policy-core here, packages/policy-core in the public mirror
 * (scripts/oss/publish-guard-repo.mjs), where each mirrored integrations/<pkg> lives at packages/<pkg> and the signer
 * and frontend bundles are not published. Here every bundle is required; the mirror checks the ones it carries.
 */
const HERE = dirname(fileURLToPath(import.meta.url));
const MIRROR = basename(dirname(HERE)) === 'packages';
const REPO = MIRROR ? join(HERE, '..', '..') : join(HERE, '..', '..', '..');
const MIRRORED = ['agentsafe-guard', 'agentsafe-mcp-guard', 'agentsafe-a2a-guard'];
const BUNDLES = MIRROR
  ? ALL_BUNDLES.flatMap((rel) => {
      const pkg = rel.split('/')[1];
      return rel.startsWith('integrations/') && MIRRORED.includes(pkg) ? [`packages/${pkg}/policy-core.mjs`] : [];
    })
  : ALL_BUNDLES;

const RULES = [
  { id: 'deny', combinator: 'any', atoms: [{ id: 'a', predicate: 'context-value-in', config: { field: 'params.op', values: ['delete'], match: 'contains', missing: 'fire', actions: ['records'] } }], decision: 'escalate', reasonCode: 'OPERATION_NEEDS_APPROVAL' },
  { id: 'allow', combinator: 'any', atoms: [{ id: 'b', predicate: 'context-value-not-in', config: { field: 'kind', values: ['note', 'memo'] } }], decision: 'block', reasonCode: 'OPERATION_NOT_ALLOWED' },
];

const VECTORS: Record<string, unknown>[] = [
  { riskLevel: 'low', params: { op: 'delete-all' } },
  { riskLevel: 'low', params: { op: 'DELETE_ALL' } },
  { riskLevel: 'low', params: { op: 'dеlete' } },
  { riskLevel: 'low', params: { op: 'ｄｅｌｅｔｅ' } },
  { riskLevel: 'low', params: { op: 'read' } },
  { riskLevel: 'low', params: { op: ['read', 'purge', 'bulk-delete'] } },
  { riskLevel: 'low', params: { op: { verb: 'read' } } },
  { riskLevel: 'low' },
  { riskLevel: 'low', 'params.op': 'read', params: { op: 'delete' } },
  { riskLevel: 'low', params: { op: 'read' }, kind: 'Memo ' },
  { riskLevel: 'low', params: { op: 'read' }, kind: 'invoice' },
  { riskLevel: 'low', params: { op: 'read' }, kind: 'nоte' },
];

const ACTIONS = ['records', 'weather'];

function verdicts(core: typeof source) {
  const out: unknown[] = [];
  for (const action of ACTIONS) {
    for (const v of VECTORS) {
      const ctx = core.buildRuleContext({ unsigned: v, signed: { action } });
      const r = core.evaluateBoundStandards([{ standardKey: 'sop:1', document: { molecules: RULES as never } }], ctx as never);
      const verdict = core.evaluate({ sops: [{ standardKey: 'sop:1', document: { molecules: RULES as never } }], context: ctx as never });
      out.push({ decision: r.decision, reasonCode: r.reasonCode, signals: core.contextRiskSignals(r), verdict: verdict.decision });
    }
  }
  return out;
}

describe('the committed policy-core bundles agree with the source on owner-keyed context values', () => {
  const expected = verdicts(source);

  it('finds a bundle to check in this layout', () => {
    expect(BUNDLES.length).toBe(MIRROR ? MIRRORED.length : ALL_BUNDLES.length);
  });

  it('the source vectors are not trivial (some escalate, some block, some allow)', () => {
    const decisions = new Set((expected as { decision: string }[]).map((e) => e.decision));
    expect([...decisions].sort()).toEqual(['allow', 'block', 'escalate']);
  });

  for (const rel of BUNDLES) {
    it(rel, async () => {
      const core = (await import(pathToFileURL(join(REPO, rel)).href)) as typeof source;
      expect(Object.keys(core.ATOM_REGISTRY).sort()).toEqual(Object.keys(source.ATOM_REGISTRY).sort());
      expect(core.ATOM_SPECS.map((s) => s.predicate)).toEqual(source.ATOM_SPECS.map((s) => s.predicate));
      expect(verdicts(core)).toEqual(expected);
      for (const s of ['Delete-All', 'dеlеte', 'ｐｕｒｇｅ', 'a​b']) expect(core.normalizeContextToken(s)).toBe(source.normalizeContextToken(s));
    });
  }
});

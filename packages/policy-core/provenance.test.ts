import { describe, expect, it } from 'vitest';
import {
  PROVENANCE_KEY,
  PROVENANCE_LEVELS,
  buildRuleContext,
  contextFieldProblem,
  maxRisk,
  meetsProvenance,
  normalizeRiskLevel,
  provenanceOf,
  requiresPayloadBindingFor,
  riskFloorFor,
} from './provenance.js';
import { evaluateStandardRules, moleculeUnverifiable, validateMolecules, type Molecule } from './standards-rules.js';
import { evaluate } from './evaluate.js';
import type { EvaluationContext } from './types.js';

const riskMolecule = (over: Partial<Molecule> = {}): Molecule => ({
  id: 'risk-review',
  combinator: 'all',
  atoms: [{ id: 'a', predicate: 'risk-at-or-above', config: { level: 'high' } }],
  decision: 'escalate',
  reasonCode: 'RISK_REVIEW',
  ...over,
});

/** A context the way the gate assembles it: the agent's itinerary plus the signed fields. */
const ctxOf = (unsigned: Record<string, unknown>, extra: Parameters<typeof buildRuleContext>[0] = {}) =>
  buildRuleContext({ unsigned, signed: { action: 'flight-purchase', amount: 250, currency: 'USD' }, ...extra }) as EvaluationContext;

describe('normalizeRiskLevel', () => {
  it('reads case and whitespace tolerantly and rejects everything that is not a level', () => {
    expect(normalizeRiskLevel('HIGH')).toBe('high');
    expect(normalizeRiskLevel('  Medium ')).toBe('medium');
    for (const bad of ['', '  ', 'banana', 'hi gh', 1, true, null, undefined, {}, ['high']]) expect(normalizeRiskLevel(bad)).toBeNull();
  });
  it('maxRisk ignores nulls and orders low < medium < high < critical', () => {
    expect(maxRisk('low', null, 'high', 'medium')).toBe('high');
    expect(maxRisk(null, undefined)).toBeNull();
    expect(maxRisk('critical', 'low')).toBe('critical');
  });
});

describe('provenance labels', () => {
  it('every field is labelled by where it came from, most trusted source winning a collision', () => {
    const ctx = buildRuleContext({
      unsigned: { tool: 'book-flight', amount: 1, cumulativeSpend: 0 },
      signed: { amount: 250, action: 'x' },
      gatewayDerived: { tool: 'gateway-says' },
      serverDerived: { cumulativeSpend: 900 },
    });
    expect(ctx.amount).toBe(250); // signed beats the unsigned claim (the applySignedLast invariant)
    expect(ctx.tool).toBe('gateway-says'); // the gateway's derivation beats the agent's claim
    expect(ctx.cumulativeSpend).toBe(900); // and the issuer's beats everything
    expect(provenanceOf(ctx, 'amount')).toBe('agent_signed');
    expect(provenanceOf(ctx, 'tool')).toBe('gateway_derived');
    expect(provenanceOf(ctx, 'cumulativeSpend')).toBe('authoritative');
    expect(provenanceOf(ctx, 'action')).toBe('agent_signed');
  });

  it('an unlabelled context, and an unlabelled field, read as the agent\'s own word — never more trusted', () => {
    expect(provenanceOf({ riskLevel: 'low' }, 'riskLevel')).toBe('agent_asserted');
    expect(provenanceOf(buildRuleContext({ unsigned: { a: 1 } }), 'never-seen')).toBe('agent_asserted');
    expect(provenanceOf(null, 'x')).toBe('agent_asserted');
  });

  it('an agent cannot forge a label: not with a string key, not with a nested map, not by spreading', () => {
    const forged = ctxOf({ riskLevel: 'low', provenance: { riskLevel: 'attested' }, __provenance: { riskLevel: 'attested' } });
    expect(provenanceOf(forged, 'riskLevel')).toBe('agent_asserted');
    // JSON — all an agent can send — cannot carry a symbol at all
    const viaJson = JSON.parse(JSON.stringify({ riskLevel: 'low', [PROVENANCE_KEY]: { riskLevel: 'attested' } }));
    expect(provenanceOf({ ...viaJson }, 'riskLevel')).toBe('agent_asserted');
    // and the labels survive the copies the evaluator makes
    expect(provenanceOf({ ...buildRuleContext({ serverDerived: { cumulativeSpend: 5 } }) }, 'cumulativeSpend')).toBe('authoritative');
  });

  it('the labels never leak into the context keys (decision records store Object.keys)', () => {
    const ctx = buildRuleContext({ unsigned: { a: 1 }, signed: { b: 2 } });
    expect(Object.keys(ctx).sort()).toEqual(['a', 'b']);
    expect(JSON.stringify(ctx)).toBe('{"a":1,"b":2}');
  });

  it('meetsProvenance follows the trust order', () => {
    expect(PROVENANCE_LEVELS).toEqual(['agent_asserted', 'agent_signed', 'gateway_derived', 'authoritative', 'attested']);
    expect(meetsProvenance('authoritative', 'gateway_derived')).toBe(true);
    expect(meetsProvenance('agent_signed', 'gateway_derived')).toBe(false);
    expect(meetsProvenance('agent_asserted', 'agent_asserted')).toBe(true);
  });
});

describe('the risk floor — an agent may raise its risk, never lower it below a trusted source', () => {
  it('the owner\'s tier beats a lower claim, keeps a higher one, and is authoritative', () => {
    const lie = ctxOf({ riskLevel: 'low' }, { riskFloor: 'high' });
    expect(lie.riskLevel).toBe('high');
    expect(provenanceOf(lie, 'riskLevel')).toBe('authoritative');
    expect(ctxOf({ riskLevel: 'critical' }, { riskFloor: 'high' }).riskLevel).toBe('critical'); // raising is always allowed
    expect(ctxOf({}, { riskFloor: 'medium' }).riskLevel).toBe('medium'); // and omitting changes nothing: the floor stands
  });

  it('garbage from the agent cannot hurt a floor, and a floor rescues a missing claim', () => {
    for (const junk of ['banana', 'HIGH!', null, 5, {}]) expect(ctxOf({ riskLevel: junk }, { riskFloor: 'high' }).riskLevel).toBe('high');
  });

  it('a gateway- or server-derived risk is a floor too, with its own provenance', () => {
    const gw = ctxOf({ riskLevel: 'low' }, { gatewayDerived: { riskLevel: 'high' } });
    expect(gw.riskLevel).toBe('high');
    expect(provenanceOf(gw, 'riskLevel')).toBe('gateway_derived');
    const both = ctxOf({ riskLevel: 'low' }, { gatewayDerived: { riskLevel: 'medium' }, riskFloor: 'high' });
    expect(both.riskLevel).toBe('high');
    expect(provenanceOf(both, 'riskLevel')).toBe('authoritative'); // the most trusted floor present
  });

  it('with no floor the claim is just normalised ("HIGH " -> high) and stays agent_asserted', () => {
    const c = ctxOf({ riskLevel: ' HIGH ' });
    expect(c.riskLevel).toBe('high');
    expect(provenanceOf(c, 'riskLevel')).toBe('agent_asserted');
  });

  it('malformed with no floor stays malformed, so the rule layer can refuse it', () => {
    expect(ctxOf({ riskLevel: 'banana' }).riskLevel).toBe('banana');
    expect(contextFieldProblem(ctxOf({ riskLevel: 'banana' }), 'riskLevel')).toBe('malformed');
  });

  it('riskFloorFor reads the mandate\'s tier for the target, the highest if granted twice, null otherwise', () => {
    const mandate = { permission: [{ target: 'wire', riskTier: 'high' }, { target: 'wire', riskTier: 'medium' }, { target: 'read' }, { target: 'odd', riskTier: 'bogus' }] };
    expect(riskFloorFor(mandate, 'wire')).toBe('high');
    expect(riskFloorFor(mandate, 'read')).toBeNull();
    expect(riskFloorFor(mandate, 'odd')).toBeNull(); // an unrecognised tier is no floor (issuance validates it)
    expect(riskFloorFor(mandate, 'other')).toBeNull();
    expect(riskFloorFor(null, 'wire')).toBeNull();
    expect(riskFloorFor({ target: 'wire', permission: [{ riskTier: 'critical' }] }, 'wire')).toBe('critical'); // default target
  });
});

describe('review findings: a trusted source that says nothing usable must not lend its label to the agent\'s claim', () => {
  const strictGw = riskMolecule({ requireProvenance: { riskLevel: 'gateway_derived' } });

  it('a gateway deriver whose lookup MISSED (undefined / junk) leaves the agent\'s claim labelled as the agent\'s — a rule requiring gateway provenance is NOT satisfied', () => {
    for (const bad of [undefined, null, 'severe', 7, {}, '']) {
      const ctx = ctxOf({ riskLevel: 'low' }, { gatewayDerived: { riskLevel: bad } });
      expect(ctx.riskLevel, String(bad)).toBe('low');
      expect(provenanceOf(ctx, 'riskLevel'), String(bad)).toBe('agent_asserted');
      expect(evaluateStandardRules([strictGw], ctx), String(bad)).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE' });
    }
  });

  it('the same for a server-derived source, and the deriver\'s junk never overwrites a valid agent claim with garbage', () => {
    const ctx = ctxOf({ riskLevel: 'HIGH' }, { serverDerived: { riskLevel: 'nope' } });
    expect(ctx.riskLevel).toBe('high');
    expect(provenanceOf(ctx, 'riskLevel')).toBe('agent_asserted');
  });

  it('a valid trusted value alongside still earns its label, and the agent\'s garbage cannot take it away', () => {
    const ctx = ctxOf({ riskLevel: 'banana' }, { gatewayDerived: { riskLevel: 'low' } });
    expect(ctx.riskLevel).toBe('low');
    expect(provenanceOf(ctx, 'riskLevel')).toBe('gateway_derived');
    expect(evaluateStandardRules([strictGw], ctx)).toMatchObject({ decision: 'allow' });
  });

  it('with NO claim at all, a trusted source\'s junk riskLevel leaves the field absent and unlabelled — it is not kept and dressed as gateway_derived', () => {
    for (const bad of [undefined, null, 'severe', 7]) {
      for (const src of [{ gatewayDerived: { riskLevel: bad } }, { serverDerived: { riskLevel: bad } }]) {
        const ctx = ctxOf({}, src);
        expect(Object.prototype.hasOwnProperty.call(ctx, 'riskLevel'), `${String(bad)} ${Object.keys(src)[0]}`).toBe(false);
        expect(provenanceOf(ctx, 'riskLevel')).toBe('agent_asserted');
        expect(contextFieldProblem(ctx, 'riskLevel')).toBe('missing');
        // so a rule that requires the trusted source escalates on ABSENCE, and the default risk rule does too
        expect(evaluateStandardRules([strictGw], ctx)).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE' });
      }
    }
  });

  it('a claim that is labelled by where it CAME FROM: signed -> agent_signed, unsigned -> agent_asserted', () => {
    expect(provenanceOf(buildRuleContext({ signed: { riskLevel: 'medium' } }), 'riskLevel')).toBe('agent_signed');
    expect(provenanceOf(buildRuleContext({ unsigned: { riskLevel: 'medium' } }), 'riskLevel')).toBe('agent_asserted');
  });
});

describe('review findings: hostile keys and documents never throw and never change a prototype', () => {
  it('an itinerary carrying "__proto__" becomes a harmless own property, not the context\'s prototype', () => {
    const evil = JSON.parse('{"__proto__": {"riskLevel": "low", "polluted": true}, "riskLevel": "high"}');
    const ctx = buildRuleContext({ unsigned: evil, signed: { action: 'x' } });
    expect(Object.getPrototypeOf(ctx)).toBe(Object.prototype);
    expect((ctx as { polluted?: boolean }).polluted).toBeUndefined();
    expect(ctx.riskLevel).toBe('high');
    expect(Object.prototype.hasOwnProperty.call(ctx, '__proto__')).toBe(true);
    // and a field literally named __proto__ is judged like any other field (missing/agent word), never inherited
    expect(provenanceOf(ctx, '__proto__')).toBe('agent_asserted');
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined(); // global prototype untouched
  });

  it('a "constructor" / "__proto__" predicate is refused by validation and does not make evaluation throw', () => {
    for (const predicate of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
      const m: Molecule = { id: 'x', combinator: 'all', atoms: [{ id: 'a', predicate }], decision: 'block', reasonCode: 'X' };
      expect(() => moleculeUnverifiable(m, ctxOf({}))).not.toThrow();
      expect(() => evaluateStandardRules([m], ctxOf({}))).not.toThrow();
    }
  });

  it('riskFloorFor tolerates a hand-authored document with junk permission entries', () => {
    const mandate = { permission: [null, 7, 'x', undefined, { target: 'wire', riskTier: 'high' }] } as never;
    expect(riskFloorFor(mandate, 'wire')).toBe('high');
    expect(() => riskFloorFor({ permission: [null] } as never, 'wire')).not.toThrow();
  });
});

describe('D-03: a risk rule no longer passes when the agent hides or garbles the field', () => {
  const judge = (unsigned: Record<string, unknown>, extra?: Parameters<typeof buildRuleContext>[0]) =>
    evaluateStandardRules([riskMolecule()], ctxOf(unsigned, extra));

  it('the original attacks: omit riskLevel, send it upper-case, send it with a space', () => {
    expect(judge({})).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE', unverifiableContext: ['riskLevel'] });
    expect(judge({ riskLevel: 'HIGH' })).toMatchObject({ decision: 'escalate', reasonCode: 'RISK_REVIEW' }); // read, and it fires
    expect(judge({ riskLevel: 'high ' })).toMatchObject({ decision: 'escalate', reasonCode: 'RISK_REVIEW' });
  });

  it('unrecognised or wrongly typed values escalate as unverifiable, never read as "not risky"', () => {
    for (const bad of ['banana', '', '  ', null, 7, true, ['high'], {}]) {
      expect(judge({ riskLevel: bad }), JSON.stringify(bad)).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE' });
    }
  });

  it('a RAW context (not built by buildRuleContext — a guard\'s local path, a legacy caller) is read tolerantly by the atom too', () => {
    for (const risk of ['HIGH', ' high ', 'Critical']) {
      expect(evaluateStandardRules([riskMolecule()], { action: 'x', riskLevel: risk as never }), risk).toMatchObject({ decision: 'escalate', reasonCode: 'RISK_REVIEW' });
    }
    // and an unlabelled raw context is only ever the agent's word, so it can never satisfy a trusted-source rule
    expect(evaluateStandardRules([riskMolecule({ requireProvenance: { riskLevel: 'gateway_derived' } })], { action: 'x', riskLevel: 'low' })).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE' });
  });

  it('an honest low still passes, and an honest high still escalates with the rule\'s own reason', () => {
    expect(judge({ riskLevel: 'low' })).toMatchObject({ decision: 'allow', reasonCode: null });
    expect(judge({ riskLevel: 'medium' })).toMatchObject({ decision: 'allow' });
    expect(judge({ riskLevel: 'high' })).toMatchObject({ decision: 'escalate', reasonCode: 'RISK_REVIEW' });
  });

  it('a lie about a high-risk action is judged high once the owner has classified it', () => {
    expect(judge({ riskLevel: 'low' }, { riskFloor: 'high' })).toMatchObject({ decision: 'escalate', reasonCode: 'RISK_REVIEW' });
    expect(judge({}, { riskFloor: 'high' })).toMatchObject({ decision: 'escalate', reasonCode: 'RISK_REVIEW' }); // hiding it does not help either
  });

  it('a rule with a stricter effect keeps it when the context is unverifiable AND it fires; observe is raised to escalate', () => {
    const blocker = riskMolecule({ decision: 'block', reasonCode: 'RISK_BLOCK' });
    expect(evaluateStandardRules([blocker], ctxOf({ riskLevel: 'high' }))).toMatchObject({ decision: 'block', reasonCode: 'RISK_BLOCK' });
    // it cannot fire without a risk to read, so unverifiable => escalate (never weaker than escalate)
    expect(evaluateStandardRules([blocker], ctxOf({}))).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE' });
    const observer = riskMolecule({ decision: 'observe', reasonCode: 'RISK_WATCH' });
    expect(evaluateStandardRules([observer], ctxOf({}))).toMatchObject({ decision: 'escalate' });
    expect(evaluateStandardRules([observer], ctxOf({ riskLevel: 'high' }))).toMatchObject({ decision: 'observe', reasonCode: 'RISK_WATCH' });
  });

  it('holds whatever the combinator — a `none` rule must not read absence as "nothing wrong"', () => {
    for (const combinator of ['all', 'any', 'none'] as const) {
      const m = riskMolecule({ combinator });
      expect(evaluateStandardRules([m], ctxOf({})).decision, combinator).toBe('escalate');
    }
  });

  it('only rules that JUDGE risk are affected: a rule that does not use the risk atom ignores a missing riskLevel', () => {
    const cap: Molecule = { id: 'cap', combinator: 'all', atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 1000 } }], decision: 'block', reasonCode: 'CAP' };
    expect(evaluateStandardRules([cap], ctxOf({}))).toMatchObject({ decision: 'allow' });
  });

  it('flows through the composed evaluate() exactly as through the rule layer', () => {
    expect(evaluate({ sops: [{ standardKey: 's', document: { molecules: [riskMolecule()] } }], context: ctxOf({}) })).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE' });
  });
});

describe('requireProvenance — a rule can demand a trusted source, per field', () => {
  const strict = (field = 'riskLevel', level: Molecule['requireProvenance'] extends infer R ? R extends Record<string, infer L> ? L : never : never = 'authoritative') =>
    riskMolecule({ requireProvenance: { [field]: level } });

  it('an agent-asserted riskLevel is not enough for an authoritative rule — even an honest "low"', () => {
    const r = evaluateStandardRules([strict()], ctxOf({ riskLevel: 'low' }));
    expect(r).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE', unverifiableContext: ['riskLevel'] });
  });

  it('it is satisfied by an owner tier, by a server-derived value, and by nothing weaker', () => {
    expect(evaluateStandardRules([strict()], ctxOf({ riskLevel: 'low' }, { riskFloor: 'low' }))).toMatchObject({ decision: 'allow' });
    expect(evaluateStandardRules([strict()], ctxOf({}, { serverDerived: { riskLevel: 'low' } }))).toMatchObject({ decision: 'allow' });
    expect(evaluateStandardRules([strict('riskLevel', 'gateway_derived')], ctxOf({ riskLevel: 'low' }, { gatewayDerived: { riskLevel: 'low' } }))).toMatchObject({ decision: 'allow' });
    expect(evaluateStandardRules([strict('riskLevel', 'authoritative')], ctxOf({ riskLevel: 'low' }, { gatewayDerived: { riskLevel: 'low' } }))).toMatchObject({ decision: 'escalate' });
    expect(evaluateStandardRules([strict('riskLevel', 'attested')], ctxOf({}, { riskFloor: 'low' }))).toMatchObject({ decision: 'escalate' }); // authoritative < attested
  });

  it('works for any field and any atom — and an unmet requirement escalates even when the atoms would not fire', () => {
    const tool: Molecule = { id: 't', combinator: 'all', atoms: [{ id: 'a', predicate: 'tool-not-allowed', config: { allowed: ['book-flight'] } }], decision: 'block', reasonCode: 'TOOL', requireProvenance: { tool: 'gateway_derived' } };
    expect(evaluateStandardRules([tool], ctxOf({ tool: 'book-flight' }))).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE' }); // allowed, but only the agent says so
    expect(evaluateStandardRules([tool], ctxOf({ tool: 'book-flight' }, { gatewayDerived: { tool: 'book-flight' } }))).toMatchObject({ decision: 'allow' });
    expect(evaluateStandardRules([tool], ctxOf({}))).toMatchObject({ decision: 'escalate' }); // missing => unverifiable
    expect(evaluateStandardRules([tool], ctxOf({ tool: 'wire' }, { gatewayDerived: { tool: 'wire' } }))).toMatchObject({ decision: 'block', reasonCode: 'TOOL' }); // trusted and disallowed: the rule's own block
  });

  it('a malformed value fails even at the lowest requirement (present and well-formed is the floor)', () => {
    const m: Molecule = { id: 'c', combinator: 'all', atoms: [{ id: 'a', predicate: 'consent-missing' }], decision: 'block', reasonCode: 'NO_CONSENT', requireProvenance: { consent: 'agent_asserted' } };
    expect(evaluateStandardRules([m], ctxOf({ consent: 'true' }))).toMatchObject({ decision: 'escalate', reasonCode: 'CONTEXT_UNVERIFIABLE' }); // a string, not a boolean
    expect(evaluateStandardRules([m], ctxOf({}))).toMatchObject({ decision: 'escalate' });
    expect(evaluateStandardRules([m], ctxOf({ consent: true }))).toMatchObject({ decision: 'allow' });
    expect(evaluateStandardRules([m], ctxOf({ consent: false }))).toMatchObject({ decision: 'block', reasonCode: 'NO_CONSENT' });
  });

  it('a mis-authored level reads as the STRICTEST requirement — a typo can only refuse more', () => {
    const typo = riskMolecule({ requireProvenance: { riskLevel: 'authorative' as never } });
    expect(moleculeUnverifiable(typo, ctxOf({ riskLevel: 'low' }, { riskFloor: 'low' }))).toEqual(['riskLevel']);
  });

  it('validateMolecules rejects a malformed declaration and accepts a good one', () => {
    expect(validateMolecules([strict()]).ok).toBe(true);
    for (const bad of [{ riskLevel: 'authorative' }, ['riskLevel'], 'authoritative', null, { '': 'attested' }]) {
      expect(validateMolecules([riskMolecule({ requireProvenance: bad as never })]).ok, JSON.stringify(bad)).toBe(false);
    }
  });

  it('an existing document (no requireProvenance) is untouched unless it uses the risk atom', () => {
    const plain: Molecule = { id: 'p', combinator: 'all', atoms: [{ id: 'a', predicate: 'jurisdiction-not-allowed', config: { allowed: ['MY'] } }], decision: 'block', reasonCode: 'J' };
    expect(evaluateStandardRules([plain], ctxOf({}))).toMatchObject({ decision: 'allow' }); // absent jurisdiction still passes here, as documented
  });
});

describe('requiresPayloadBindingFor', () => {
  it('is true only for a literal `true` on a permission for the target', () => {
    const mandate = { target: 'wire', permission: [{ target: 'wire', requirePayloadBinding: true }, { target: 'other' }] };
    expect(requiresPayloadBindingFor(mandate, 'wire')).toBe(true);
    expect(requiresPayloadBindingFor(mandate, 'other')).toBe(false);
    expect(requiresPayloadBindingFor(mandate, 'missing')).toBe(false);
  });

  it('any grant of the target requiring it is enough (the strict reading)', () => {
    expect(requiresPayloadBindingFor({ permission: [{ target: 'wire' }, { target: 'wire', requirePayloadBinding: true }] }, 'wire')).toBe(true);
  });

  it('never throws on a hand-authored document, and never reads a non-boolean as required', () => {
    expect(requiresPayloadBindingFor(null, 'wire')).toBe(false);
    expect(requiresPayloadBindingFor(undefined, 'wire')).toBe(false);
    expect(requiresPayloadBindingFor({ permission: [null as never, 'x' as never, {}] }, 'wire')).toBe(false);
    for (const v of ['true', 'yes', 1, {}, [], null]) expect(requiresPayloadBindingFor({ permission: [{ target: 'wire', requirePayloadBinding: v }] }, 'wire')).toBe(false);
  });
});

// agentsafe-guard verify — assert an agent cannot exceed its mandate, in CI.
//
//   npx @metamynd/agentsafe-guard verify
//
// The point is to turn governance into a repo artifact rather than a dashboard someone
// visits. A build that fails when an agent CAN do something it should not is a control;
// a screen that would have shown you is not.
//
// The design decision that matters is the one this package learned the hard way. A
// conversion test paid an unapproved supplier $250 through the public sandbox and it went
// through, because the sandbox mandate was issued with `merchants: []` — and an empty
// allow-list is not an allow-list with nothing on it, it is NO allow-list. Meanwhile
// MERCHANT_NOT_ALLOWED sat documented in the example's own glossary of reason codes.
// Nothing caught it because nothing looked.
//
// So this never reports a control as holding when the control does not exist. Every check
// resolves to one of three states, and only the first is a pass:
//
//   HELD            the control is configured, and it refused the violation
//   NOT CONFIGURED  the mandate says nothing about it — reported, never passed
//   FAILED          the control is configured and it did NOT refuse. Exit 1.
//
// `--require <control,...>` promotes NOT CONFIGURED to a build failure, which is how a
// team states "our agents must carry a merchant allow-list" and finds out when one does not.
//
// Evaluation is LOCAL and pure: the same policy-core the gate runs, over the agent's signed
// bundle. No holds are minted, no nonces are spent, no budget is consumed, and a CI run
// costs one GET. Verifying an agent must not be an action the agent takes.

import { createGuardFromConfig } from './agentsafe-guard.mjs';

const CONTROLS = {
  scope: {
    label: 'action scope',
    detail: 'the set of actions this mandate grants at all',
    /** Always present: every mandate grants SOMETHING, so there is always a beyond. */
    configured: () => ({ configured: true, summary: 'default-deny' }),
  },
  perTxn: {
    label: 'per-transaction cap',
    detail: 'the ceiling on any single action',
    configured: (c) => {
      const k = c.find((x) => x.leftOperand === 'mm:payAmount' && x.operator === 'lteq');
      return k ? { configured: true, summary: `${k.rightOperand}${k.unit ? ' ' + k.unit : ''}`, limit: Number(k.rightOperand) } : { configured: false };
    },
  },
  cumulative: {
    label: 'cumulative cap',
    detail: 'the ceiling on total spend across actions',
    configured: (c) => {
      const k = c.find((x) => x.leftOperand === 'mm:cumulativeSpend' && x.operator === 'lteq');
      return k ? { configured: true, summary: `${k.rightOperand}${k.unit ? ' ' + k.unit : ''}`, limit: Number(k.rightOperand) } : { configured: false };
    },
  },
  merchants: {
    label: 'merchant allow-list',
    detail: 'which counterparties this agent may pay',
    configured: (c) => {
      const k = c.find((x) => x.leftOperand === 'mm:merchant' && x.operator === 'isAnyOf');
      if (!k) {
        // The shape that bit us. `issueMandate` OMITS the constraint when the list is
        // empty, so the mandate says nothing about merchants and every merchant is
        // permitted. Absent, and it must never read as a pass.
        return { configured: false };
      }
      const list = Array.isArray(k.rightOperand) ? k.rightOperand : [];
      // A PRESENT constraint over an empty list is the opposite of vacuous, which is worth
      // stating because the intuition runs the other way: `[].includes(x)` is always false,
      // so the permission never grants and the agent may pay NOBODY. That is configured —
      // pathologically — and the baseline check below is what surfaces it, by failing.
      return list.length
        ? { configured: true, summary: list.join(', '), list }
        : { configured: true, summary: 'EMPTY — this permits no merchant at all', list: [], empty: true };
    },
  },
};

const PASS = 'held';
const ABSENT = 'not-configured';
const FAIL = 'failed';

/** Map a raw bundle into the shape evaluateLocally expects, for one action. */
function packsFor(bundle, action) {
  return {
    contained: bundle.contained ?? null,
    operatingMode: bundle.operatingMode ?? null,
    standards: (bundle.standards ?? []).map((s) => ({ standardKey: s.key ?? s.id ?? 'standard', document: s.document })).filter((s) => s.document),
    sops: (bundle.sops ?? []).map((s) => ({ standardKey: s.id ?? 'sop', document: s.document })).filter((s) => s.document),
    mandate: ((bundle.mandates ?? []).find((m) => m.action === action) ?? (bundle.mandates ?? [])[0])?.document,
  };
}

const permits = (v) => v.decision === 'allow' || v.decision === 'observe';

export async function verify({ configPath = './agent.metamynd.json', require: required = [], json = false, log = console.log, env = process.env } = {}) {
  // AGENT_KEY / AGENT_DID / METAMYND_API from the environment win over the config file.
  // CI is the whole point of this command, and a CI story that requires committing the
  // agent's signing key to the repository is not one — so a key-less config plus a secret
  // has to work.
  const overrides = {
    ...(env.AGENT_KEY ? { agentKey: env.AGENT_KEY } : {}),
    ...(env.AGENT_DID ? { agentDid: env.AGENT_DID } : {}),
    ...(env.METAMYND_API ? { api: env.METAMYND_API } : {}),
  };
  const guard = await createGuardFromConfig(configPath, overrides);
  const bundle = await guard.loadBundle();

  const mandates = bundle.mandates ?? [];
  if (!mandates.length) throw new Error('This agent has no mandate in its policy bundle — there is nothing to verify.');

  const action = mandates[0].action;
  const packs = packsFor(bundle, action);
  const constraints = (packs.mandate?.permission ?? []).flatMap((p) => p.constraint ?? []);
  const evaluate = (request) => guard.evaluateLocally({ ...packs, request });

  const found = {};
  for (const [key, spec] of Object.entries(CONTROLS)) found[key] = spec.configured(constraints);

  const checks = [];
  const add = (control, status, assertion, verdict, note) =>
    checks.push({ control, status, assertion, decision: verdict?.decision ?? null, reasonCode: verdict?.reasonCode ?? null, note });

  // 1. Ordinary work still runs. A governed agent that cannot do its job is not governed,
  //    it is broken — and every refusal below means nothing if this one does not pass.
  {
    const amount = found.perTxn.configured ? Math.max(1, Math.floor(found.perTxn.limit / 2)) : 1;
    const merchant = found.merchants.list?.length ? found.merchants.list[0] : 'any-merchant';
    const v = evaluate({ action, amount, merchant, context: { riskLevel: 'low' } });
    add('baseline', permits(v) ? PASS : FAIL, 'permits ordinary in-scope work', v,
      permits(v) ? null : 'the agent cannot perform the action it was issued for');
  }

  // 2. Scope. Needs no configuration and no special anti-self-escalation rule: an agent
  //    cannot name an action nobody delegated to it.
  {
    const v = evaluate({ action: 'permissions.update', amount: 100000, merchant: 'any-merchant', context: {} });
    add('scope', permits(v) ? FAIL : PASS, 'refuses an action the mandate never granted', v,
      permits(v) ? 'THIS AGENT CAN ACT OUTSIDE ITS MANDATE' : null);
  }

  // 3–5. Only assert a limit the mandate actually sets. Asserting an absent control is how
  //      you end up believing in one.
  if (found.perTxn.configured) {
    const v = evaluate({ action, amount: found.perTxn.limit + 1, merchant: found.merchants.list?.length ? found.merchants.list[0] : 'any-merchant', context: {} });
    add('perTxn', permits(v) ? FAIL : PASS, `refuses ${found.perTxn.limit + 1} against a cap of ${found.perTxn.limit}`, v,
      permits(v) ? 'the per-transaction cap did not hold' : null);
  } else {
    add('perTxn', ABSENT, 'no per-transaction cap in this mandate', null, 'any single amount is permitted');
  }

  if (found.cumulative.configured) {
    const v = evaluate({
      action, amount: 1, merchant: found.merchants.list?.length ? found.merchants.list[0] : 'any-merchant',
      cumulativeSpend: found.cumulative.limit + 1, context: {},
    });
    add('cumulative', permits(v) ? FAIL : PASS, `refuses spending past a total of ${found.cumulative.limit}`, v,
      permits(v) ? 'the cumulative cap did not hold' : null);
  } else {
    add('cumulative', ABSENT, 'no cumulative cap in this mandate', null, 'total spend is unbounded');
  }

  if (found.merchants.empty) {
    add('merchants', FAIL, 'merchant allow-list is present but EMPTY', null,
      'this permits no merchant at all — the agent cannot transact with anyone');
  } else if (found.merchants.configured) {
    // Deliberately UNDER any cap: a refusal at an amount that also trips a spend limit
    // proves nothing about merchants, which is exactly how this went unnoticed before.
    const amt = found.perTxn.configured ? Math.max(1, Math.floor(found.perTxn.limit / 2)) : 1;
    const v = evaluate({ action, amount: amt, merchant: '__unapproved_supplier__', context: {} });
    add('merchants', permits(v) ? FAIL : PASS, 'refuses an unlisted merchant, under the cap', v,
      permits(v) ? 'the merchant allow-list did not hold' : null);
  } else {
    add('merchants', ABSENT, 'no merchant allow-list in this mandate', null, 'EVERY merchant is permitted');
  }

  const failed = checks.filter((c) => c.status === FAIL);
  const absent = checks.filter((c) => c.status === ABSENT);
  const requiredMissing = absent.filter((c) => required.includes(c.control));
  const ok = failed.length === 0 && requiredMissing.length === 0;

  if (json) {
    log(JSON.stringify({ ok, agent: guard.agentDid, action, checks, required }, null, 2));
    return { ok, checks, failed, absent, requiredMissing };
  }

  const mark = { [PASS]: '  ok  ', [FAIL]: ' FAIL ', [ABSENT]: ' n/a  ' };
  log('');
  log(`  agentsafe verify — ${guard.agentDid}`);
  log(`  scope: ${action}`);
  log('');
  for (const c of checks) {
    log(`${mark[c.status]} ${c.assertion}${c.reasonCode ? `  → ${c.decision}/${c.reasonCode}` : ''}`);
    if (c.note) log(`        ${c.note}`);
  }
  log('');
  if (failed.length) {
    log(`  ${failed.length} control(s) did NOT hold. This agent can exceed its mandate.`);
  }
  if (absent.length) {
    log(`  ${absent.length} control(s) are not configured — reported, not passed.`);
    if (!requiredMissing.length) {
      log(`  Fail the build on these with:  verify --require ${absent.map((c) => c.control).join(',')}`);
    }
  }
  if (requiredMissing.length) {
    log(`  ${requiredMissing.length} REQUIRED control(s) are missing: ${requiredMissing.map((c) => c.control).join(', ')}`);
  }
  if (ok) log('  Every configured control held, and nothing required is missing.');
  log('');

  return { ok, checks, failed, absent, requiredMissing };
}

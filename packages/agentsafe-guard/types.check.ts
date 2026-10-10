// types.check.ts — compiled by `tsc --noEmit` (CI: backend's TypeScript) to keep agentsafe-guard.d.ts honest against the way
// an agent uses the package. Never run; never published.
import { createGuard, createGuardFromConfig, type GovernanceBlocked, type ToolDecision, type Verdict } from './agentsafe-guard.mjs';

async function example(): Promise<void> {
  const guard = await createGuardFromConfig('./agent.metamynd.json', { mode: 'remote' });
  const direct = createGuard({ api: 'https://metamynd.ai/api/v1', agentDid: 'did:key:z6Mk', agentKey: '302e...' });

  const verdict: Verdict = await guard.authorize({ action: 'invoice.pay', amount: 120, currency: 'USD', merchant: 'acme', context: { riskLevel: 'low' } });
  if (verdict.decision === 'allow' && verdict.authorizationId) await direct.capture(verdict.authorizationId, 120);

  type PayArgs = { amount: number; merchant: string };
  const pay = guard.guardTool(
    'invoice.pay',
    async (args: PayArgs, decision: ToolDecision) => {
      const headers = await decision.governanceHeaders();
      return { ok: true, headers, amount: args.amount };
    },
    (args) => ({ amount: args.amount, currency: 'USD', merchant: args.merchant, payload: args }),
    { settle: 'capture', releaseOnError: (err) => err instanceof TypeError },
  );
  try {
    const out = await pay({ amount: 10, merchant: 'acme' });
    const ok: boolean = out.ok;
    void ok;
  } catch (err) {
    const refused = err as GovernanceBlocked;
    if (refused.name === 'GovernanceBlocked' && refused.governance.escalationId) {
      await pay.resume(refused.governance.escalationId, { amount: 10, merchant: 'acme' });
    }
  }
}
void example;

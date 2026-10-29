// types.check.ts — compiled by `tsc --noEmit` (the SDK type-check test) to keep agentsafe-mcp-guard.d.mts honest
// against the way a Service uses the package. Never run; never published.
import { createMcpGuard, payloadDigestOf, type GovernanceBlocked, type ServiceVerdict, type SignedRequest } from './agentsafe-mcp-guard.mjs';

async function example(signed: SignedRequest): Promise<void> {
  const guard = createMcpGuard({
    serviceDid: 'did:key:z6Mk',
    serviceKey: '302e...',
    issuerApi: 'https://metamynd.ai/api/v1',
    policyPublicKey: 'ab',
    requireAuthorization: true,
    allowedAgents: ['did:hedera:testnet:zAgent_0.0.1'],
    gatewayOwnerPrincipal: 'did:hedera:testnet:zOwner_0.0.2',
    bundleCache: { maxAgeMs: 30_000 },
    argumentKey: 'k'.repeat(32),
  });
  const checked: true = guard.checksArguments;
  void checked;
  const withArgs = await guard.verifyRequest(signed, { arguments: { to: 'a@b.c' } });
  if (withArgs.arguments) void withArgs.arguments.to;

  const verdict: ServiceVerdict = await guard.verifyRequest(signed, { payloadDigest: payloadDigestOf({ amount: 10 }), trustedContext: { riskLevel: 'high' } });
  if (verdict.decision === 'allow' && verdict.authorizationId) {
    await guard.captureAuthorization({ authorizationId: verdict.authorizationId, claimToken: verdict.claimToken, amountCharged: 10 });
  }

  const book = guard.guardIncomingTool('flight-purchase', async (req: SignedRequest, body: { amount: number }) => ({ pnr: 'P1', amount: body.amount, by: req.agentDid }), { settle: true, bindPayload: true });
  try {
    const out = await book(signed, { amount: 10 });
    const pnr: string = out.pnr;
    void pnr;
  } catch (err) {
    if ((err as GovernanceBlocked).name === 'GovernanceBlocked') return;
  }
  const signature: string = await guard.acceptCounterpartyChallenge('MAGP-COUNTERPARTY-ACCEPT-v1|...');
  void signature;
  guard.close();
}
void example;

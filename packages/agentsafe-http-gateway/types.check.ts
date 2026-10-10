// types.check.ts — compiled by `tsc --noEmit` (backend/scripts/sdk-types.test.ts) to keep the gateway's .d.mts files honest
// against the way an operator embeds the gateway. Never run; never published.
import { createHttpGateway, type GatewayGuard, type GatewayResponse, type Route } from './gateway.mjs';
import { matchRoute } from './route-match.mjs';
import { acceptChallenge, createServiceIdentity, readServiceIdentity, writeServiceIdentity } from './service-identity.mjs';

declare const guard: GatewayGuard;

async function example(): Promise<void> {
  const routes: Route[] = [{ method: 'POST', path: '/payments', action: 'invoice.pay', valueFields: ['amount', 'currency', 'merchant'] }];
  const gateway = createHttpGateway({
    guard,
    routes,
    denyByDefault: true,
    forward: async (req) => ({ status: 200, body: { forwarded: req.path } }),
    resolveCredential: async ({ route }) => (route.credential === false ? null : { header: 'Authorization', value: 'Bearer sk_test' }),
    reportOutcomes: true,
  });
  const res: GatewayResponse = await gateway({ method: 'POST', path: '/payments', headers: { 'x-magp-request': '{}' }, rawBody: Buffer.from('{}') });
  const status: number = res.status;
  await gateway.drainSettlements(1000);
  const route: Route | null = matchRoute(routes, 'POST', '/payments');

  const id = createServiceIdentity();
  writeServiceIdentity('service-identity.json', id, { force: true });
  const again = readServiceIdentity('service-identity.json');
  const signature: string = await acceptChallenge(again, 'MAGP-COUNTERPARTY-ACCEPT-v1|...');
  void status;
  void route;
  void signature;
}
void example;

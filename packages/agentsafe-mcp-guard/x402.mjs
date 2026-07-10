// GENERATED from backend/src/features/magp/x402-binding.ts — do not edit. Regenerate: npm run build:mcp-guard-core

// src/features/magp/x402-binding.ts
function toMinorUnits(amount, decimals) {
  if (!Number.isFinite(amount) || amount < 0) throw new Error("amount must be a non-negative number");
  const factor = 10 ** decimals;
  return String(Math.round(amount * factor));
}
function buildPaymentRequirements(input) {
  if (!input.authorizationId) throw new Error("buildPaymentRequirements requires an authorizationId");
  const decimals = input.decimals ?? 6;
  return {
    x402Version: 1,
    accepts: [
      {
        scheme: "exact",
        network: input.network ?? "hedera-testnet",
        maxAmountRequired: toMinorUnits(input.amount, decimals),
        payTo: input.payTo,
        asset: input.asset,
        resource: input.resource,
        extra: { magpAuthorizationId: input.authorizationId, magpAgentDid: input.agentDid }
      }
    ]
  };
}
function checkSettlementBinding(requirements, claim) {
  const accept = requirements?.accepts?.[0];
  if (!accept?.extra?.magpAuthorizationId) return { ok: false, reasonCode: "MISSING_BINDING" };
  if (accept.extra.magpAuthorizationId !== claim.authorizationId) {
    return { ok: false, reasonCode: "AUTHORIZATION_MISMATCH" };
  }
  const authorizedMinor = Number(accept.maxAmountRequired);
  const paidMinor = Number(claim.paidAmountMinor);
  if (!Number.isFinite(paidMinor) || paidMinor < 0) return { ok: false, reasonCode: "AMOUNT_INVALID" };
  if (paidMinor > authorizedMinor) return { ok: false, reasonCode: "AMOUNT_MISMATCH" };
  return { ok: true, reasonCode: "BINDING_OK" };
}
export {
  buildPaymentRequirements,
  checkSettlementBinding,
  toMinorUnits
};

// handshake-nonce.smoke.mjs — the agent side of the mutual handshake (MAGP §8.2) signs the SERVICE's nonce with the agent's
// own key. It used to sign whatever the Service sent: a malicious or compromised Service could send, as its "nonce", a
// canonical authorize message for a purchase and walk away with this agent's valid signature on it — the gate would accept
// it as the agent's own request. The agent now signs only a plain token (found while reviewing the 2026-10-04 Gateway
// Authority Refinement Plan, whose proof-of-control step would otherwise have inherited the oracle).
//
//   node handshake-nonce.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createGuard, HANDSHAKE_NONCE } from './agentsafe-guard.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { did: buildHederaDid('testnet', spki.subarray(spki.length - 32), topic), privateKey, keyHex: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex') };
}
const agent = mint('0.0.100');
const service = mint('0.0.200');
const guard = createGuard({ api: 'http://127.0.0.1:9/api/v1', agentDid: agent.did, agentKey: agent.keyHex });
/** A Service that answers HELLO honestly except for the nonce it asks the agent to sign. */
const challengeFor = (nonceA, nonceB) => ({ toDid: service.did, nonceB, handshakeId: 'h1', sigB: crypto.sign(null, Buffer.from(nonceA, 'utf8'), service.privateKey).toString('hex') });

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`ok    ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}

await check('an ordinary handshake still completes (a UUID nonce is a plain token)', async () => {
  const hs = guard.handshake();
  const { nonceA } = hs.hello();
  const nonceB = crypto.randomUUID();
  assert.ok(HANDSHAKE_NONCE.test(nonceB));
  const { sigA } = await hs.prove({ nonceA, challenge: challengeFor(nonceA, nonceB) });
  assert.ok(crypto.verify(null, Buffer.from(nonceB, 'utf8'), crypto.createPublicKey({ key: Buffer.from(agent.keyHex, 'hex'), format: 'der', type: 'pkcs8' }), Buffer.from(sigA, 'hex')));
});

await check('a Service that sends an authorize message as its nonce gets no signature', async () => {
  const hs = guard.handshake();
  const { nonceA } = hs.hello();
  const purchase = buildAuthMessage({ agentDid: agent.did, action: 'flight-purchase', amount: 500, currency: 'USD', merchant: 'skyward-air', resource: null, nonce: crypto.randomUUID(), issuedAt: new Date().toISOString() });
  await assert.rejects(() => hs.prove({ nonceA, challenge: challengeFor(nonceA, purchase) }), (e) => e.name === 'HandshakeFailed' && /plain token/.test(e.message));
});

await check('nor for any other free text, an over-long token, or a non-string', async () => {
  for (const bad of ['MAGP-SERVICE-v1|claim|x|y', 'short', 'x'.repeat(129), 'has space in it 1234', 42]) {
    const hs = guard.handshake();
    const { nonceA } = hs.hello();
    await assert.rejects(() => hs.prove({ nonceA, challenge: challengeFor(nonceA, bad) }), /plain token|malformed/, `refuses ${String(bad).slice(0, 20)}`);
  }
});

if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log('\nPASS — the agent signs only a plain-token handshake nonce.');

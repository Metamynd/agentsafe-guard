// Payload binding at the HTTP gateway (spec 8.3.9): the gateway digests the body it is about to FORWARD, hands that digest
// to the guard, and refuses a request whose authorization bound a payload it cannot show is the one being executed.
// Fake guard => no network, deterministic.
import assert from 'node:assert/strict';
import { createHttpGateway, executedPayloadDigest, parseStrictJson } from './gateway.mjs';
import { payloadDigestOf } from './payload-binding.mjs';

let verifyArgs = null;
let forwarded = null;
const guard = {
  verifyRequest: async (...args) => { verifyArgs = args; return { decision: 'allow', reasonCode: 'AUTHORIZED', authorizationId: 'auth-1' }; },
};
const forward = async (req) => { forwarded = req; return { status: 200, body: { ran: true } }; };

const BODY = { amount: 250, merchant: 'skyward-air', currency: 'USD' };
const DIGEST = payloadDigestOf(BODY);
const SIGNED = { agentDid: 'did:x', action: 'flight-purchase', amount: 250, currency: 'USD', merchant: 'skyward-air', nonce: 'n', issuedAt: 'now', signature: 's' };
const BOUND = { ...SIGNED, payloadDigest: DIGEST, payloadSignature: 'ps' };

const mk = (opts = {}, routeExtra = {}) => createHttpGateway({
  guard, forward, denyByDefault: true,
  routes: [{ method: 'POST', path: '/book', action: 'flight-purchase', valueFields: ['amount', 'merchant'], allowedFields: null, ...routeExtra }],
  ...opts,
});
const call = (gw, body, signed = BOUND) => {
  verifyArgs = null; forwarded = null;
  return gw({ method: 'POST', path: '/book', headers: { 'x-magp-request': JSON.stringify(signed) }, rawBody: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)) });
};

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('executedPayloadDigest digests the JSON body that will be forwarded, key order and whitespace aside', () => {
  const a = executedPayloadDigest({ rawBody: Buffer.from('{"merchant":"skyward-air","amount":250,"currency":"USD"}') });
  const b = executedPayloadDigest({ rawBody: Buffer.from(' { "amount" : 250 , "currency":"USD", "merchant":"skyward-air" } ') });
  assert.equal(a.digest, DIGEST);
  assert.equal(b.digest, DIGEST);
});
test('an empty body has no digest ({ none })', () => {
  assert.deepEqual(executedPayloadDigest({ rawBody: Buffer.from('   ') }), { none: true });
  assert.deepEqual(executedPayloadDigest({ headers: {} }), { none: true });
});
test('a non-JSON body reports an error rather than a digest', () => {
  assert.ok(executedPayloadDigest({ rawBody: Buffer.from('amount=1&merchant=x') }).error);
});
test('route.payload(req) picks what is digested (a body plus path parameters)', () => {
  const r = executedPayloadDigest({ rawBody: Buffer.from('{"a":1}'), params: { id: 7 } }, { payload: (q) => ({ body: JSON.parse(q.rawBody.toString()), id: q.params.id }) });
  assert.equal(r.digest, payloadDigestOf({ body: { a: 1 }, id: 7 }));
});
test('a JS payload is digested as the JSON it becomes on the wire (NaN travels as null)', () => {
  assert.equal(executedPayloadDigest({}, { payload: () => ({ a: NaN, b: undefined }) }).digest, payloadDigestOf({ a: null }));
});
test('a payload JSON cannot carry (a lone surrogate, a bare function) reports an error', () => {
  assert.ok(executedPayloadDigest({}, { payload: () => ({ a: '\ud800' }) }).error);
  assert.ok(executedPayloadDigest({}, { payload: () => () => 1 }).error);
});

// The digest must mean the same to every reader of the forwarded bytes. JSON.parse is lossy where readers disagree, so the
// gateway refuses (never digests) a body that is ambiguous between them.
const digestOfText = (text) => executedPayloadDigest({ rawBody: Buffer.from(text) });
const digestOfBytes = (bytes) => executedPayloadDigest({ rawBody: Buffer.from(bytes) });
test('a duplicate key is refused, not digested last-wins (a first-wins upstream would run a different payee)', () => {
  assert.ok(digestOfText('{"payee":"evil","payee":"good","amount":5}').error);
  assert.ok(digestOfText('{"payee":"evil","\\u0070ayee":"good"}').error, 'compared after unescaping');
  assert.ok(digestOfText('{"a":{"k":1,"k":2}}').error, 'nested too');
  assert.ok(digestOfText('[{"k":1,"k":2}]').error, 'inside an array');
  assert.ok(digestOfText('{"payee":"good","amount":5}').digest, 'the same body without the repeat is fine');
});
test('a number a double cannot carry exactly is refused (two ids or amounts would share a digest)', () => {
  for (const bad of ['{"id":9007199254740992}', '{"id":9007199254740993}', '{"id":1152921504606846977}', '{"x":0.1000000000000000055511151231257827}', '{"x":1e-400}', '{"x":1e999}', '{"x":123456789012345680000}']) {
    assert.ok(digestOfText(bad).error, bad);
  }
  for (const good of ['{"id":9007199254740991}', '{"x":0.1}', '{"x":250.75}', '{"x":1e21}', '{"x":-0}', '{"x":0.000001}', '{"x":123456789012345}']) {
    assert.ok(digestOfText(good).digest, good);
  }
});
test('invalid UTF-8 and a byte-order mark are refused, not repaired to U+FFFD', () => {
  assert.ok(digestOfBytes([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]).error, '0xff inside a string');
  assert.ok(digestOfBytes([0xef, 0xbb, 0xbf, 0x7b, 0x7d]).error, 'a BOM');
  assert.ok(digestOfBytes([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xc3, 0xa9, 0x22, 0x7d]).digest, 'valid multi-byte UTF-8 is fine');
});
test('malformed and trailing JSON is refused', () => {
  for (const bad of ['{"a":1,}', '{"a" 1}', '[1,2', '{"a":1} x', '{"a":"tab\there"}', "{'a':1}", '{"a":01}', '{"a":+1}', '{"a":.5}', '{"a":NaN}']) {
    assert.ok(digestOfText(bad).error, bad);
  }
});
test('a key named __proto__ is a key, digested as one', () => {
  const r = digestOfText('{"__proto__":{"admin":true},"a":1}');
  assert.equal(r.digest, payloadDigestOf(JSON.parse('{"__proto__":{"admin":true},"a":1}')));
  assert.equal(parseStrictJson('{"__proto__":1}').constructor, Object, 'the prototype was not replaced');
});
test('the strict parser agrees with JSON.parse on everything it accepts', () => {
  for (const text of ['{}', '[]', '[1,2,{"a":[true,false,null]}]', '{"s":"a\\"b\\\\c\\n\\u00e9\\ud83d\\ude00"}', ' \n{"z":1,"a":2}\t', '"x"', '0', '-1.5e3', 'null']) {
    assert.deepEqual(parseStrictJson(text), JSON.parse(text), text);
  }
});
test('a request that binds a payload but whose body is ambiguous is refused before the guard', async () => {
  const r = await call(mk({ bind: false }), '{"payee":"evil","payee":"good"}');
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(verifyArgs, null); assert.equal(forwarded, null);
});
test('a request that binds a payload: the executed digest is handed to the guard', async () => {
  const r = await call(mk(), BODY);
  assert.equal(r.status, 200);
  assert.equal(verifyArgs[1].payloadDigest, DIGEST);
  assert.equal(verifyArgs[1].requirePayloadBinding, undefined);
});
test('the digest is over the bytes actually forwarded, not over what the agent signed', async () => {
  // Same signed amount/merchant (so the value binder passes), but an extra field the agent did not sign: the digest differs,
  // and it is THAT digest the guard is given, so the claim carries it and the issuer refuses.
  const tampered = { ...BODY, memo: 'x' };
  const r = await call(mk(), tampered);
  assert.equal(r.status, 200, 'the value binder alone cannot see this; the digest comparison downstream does');
  assert.equal(verifyArgs[1].payloadDigest, payloadDigestOf(tampered));
  assert.notEqual(verifyArgs[1].payloadDigest, DIGEST);
});
test('a request that binds a payload but whose body is not JSON is refused before the guard', async () => {
  const r = await call(mk({ bind: false }), 'amount=250');
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(r.body.field, 'payload');
  assert.equal(verifyArgs, null); assert.equal(forwarded, null);
});
test('a request that binds a payload but has no body is refused', async () => {
  const r = await call(mk({ bind: false }), '');
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
});
test('an unbound request is unchanged by default: no digest handed to the guard', async () => {
  const r = await call(mk(), BODY, SIGNED);
  assert.equal(r.status, 200);
  assert.deepEqual(verifyArgs, [SIGNED], 'the guard is called exactly as it always was');
});
test('requirePayloadBinding on an unbound authorization: the guard is told to require it, and its refusal stops the forward', async () => {
  const requiring = { verifyRequest: async (_r, o) => (o?.requirePayloadBinding ? { decision: 'block', reasonCode: 'PAYLOAD_BINDING_REQUIRED' } : { decision: 'allow' }) };
  const r = await call(mk({ guard: requiring, requirePayloadBinding: true }), BODY, SIGNED);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_BINDING_REQUIRED'); assert.equal(forwarded, null);
});
test('requirePayloadBinding on a bound request passes the flag and the digest to the guard', async () => {
  const r = await call(mk({ requirePayloadBinding: true }), BODY);
  assert.equal(r.status, 200);
  assert.equal(verifyArgs[1].requirePayloadBinding, true);
  assert.equal(verifyArgs[1].payloadDigest, DIGEST);
});
test('a route can require binding while the gateway does not, and a route can turn a gateway-wide requirement off', async () => {
  await call(mk({}, { requirePayloadBinding: true }), BODY, SIGNED);
  assert.equal(verifyArgs[1].requirePayloadBinding, true);
  await call(mk({ requirePayloadBinding: true }, { requirePayloadBinding: false }), BODY, SIGNED);
  assert.deepEqual(verifyArgs, [SIGNED], 'no digest, no flag: the guard is called exactly as it always was');
});
test('requirePayloadBinding with an empty body is refused', async () => {
  const r = await call(mk({ requirePayloadBinding: true, bind: false }), '', SIGNED);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_BINDING_REQUIRED');
});
test('a guard refusal (PAYLOAD_NOT_BOUND from the guard) is surfaced and nothing is forwarded', async () => {
  const refusing = { verifyRequest: async () => ({ decision: 'block', reasonCode: 'PAYLOAD_NOT_BOUND' }) };
  const r = await call(mk({ guard: refusing }), BODY);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(forwarded, null);
});

let pass = 0, fail = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m ' + name); pass++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m ' + name + '\n       ' + e.message); fail++; }
}
console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

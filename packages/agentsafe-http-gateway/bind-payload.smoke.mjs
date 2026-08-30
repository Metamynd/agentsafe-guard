// Unit tests for payload binding. Fake guard => no network, deterministic.
import assert from 'node:assert/strict';
import { createHttpGateway } from './gateway.mjs';

let guardCalls = 0, forwarded = null;
const guard = { verifyRequest: async () => { guardCalls++; return { decision: 'allow', reasonCode: 'AUTHORIZED' }; } };
const forward = async (req) => { forwarded = req; return { status: 200, body: { ran: true } }; };

const SIGNED = { agentDid: 'did:x', amount: 250, currency: 'USD', merchant: 'skyward-air', nonce: 'n', issuedAt: 'now', signature: 's' };
// valueFields set explicitly (matching the default anyway) so these tests exercise the
// binder itself, not the separate "no explicit binding decision" deprecation warning —
// that gets its own dedicated test below.
const mk = (opts = {}, routeExtra = {}) => createHttpGateway({
  guard, forward, denyByDefault: true,
  routes: [{ method: 'POST', path: '/book-flight', action: 'flight-purchase', valueFields: ['amount', 'merchant'], ...routeExtra }],
  ...opts,
});
const call = (gw, body, signed = SIGNED, path = '/book-flight') => {
  guardCalls = 0; forwarded = null;
  return gw({ method: 'POST', path, headers: { 'x-magp-request': JSON.stringify(signed) },
              rawBody: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)) });
};

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('honest payload matching the signature is forwarded', async () => {
  const r = await call(mk(), { amount: 250, merchant: 'skyward-air', riskLevel: 'low' });
  assert.equal(r.status, 200); assert.ok(forwarded);
});
test('tampered amount is blocked, naming the field', async () => {
  const r = await call(mk(), { amount: 5000, merchant: 'skyward-air' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
  assert.equal(r.body.field, 'amount'); assert.equal(forwarded, null);
});
test('tampered merchant is blocked', async () => {
  const r = await call(mk(), { amount: 250, merchant: 'evil-corp' });
  assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(r.body.field, 'merchant');
});
test('tampered currency is blocked', async () => {
  const r = await call(mk(), { amount: 250, currency: 'BTC', merchant: 'skyward-air' });
  assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(r.body.field, 'currency');
});
test('payload introducing a value the signature never mentioned is blocked', async () => {
  const bare = { agentDid: 'did:x', nonce: 'n', issuedAt: 'now', signature: 's' }; // no amount/merchant
  const r = await call(mk(), { amount: 9999 }, bare);
  // amount/merchant are required unconditionally now (see DEFAULT_VALUE_FIELDS) — merchant
  // being absent from this body is caught before amount's own value is even compared, but
  // the security property is the same: this request never reaches upstream.
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('a value the signature never mentioned mismatches once the required fields are otherwise present', async () => {
  const bare = { agentDid: 'did:x', nonce: 'n', issuedAt: 'now', signature: 's' }; // no amount/merchant
  const r = await call(mk(), { amount: 9999, merchant: 'evil-corp' }, bare);
  assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
});
test('binding runs BEFORE the guard - a tampered request burns no nonce', async () => {
  await call(mk(), { amount: 5000, merchant: 'skyward-air' });
  assert.equal(guardCalls, 0, 'guard.verifyRequest must not be reached');
});
test('numeric string in the body matches a numeric signed amount', async () => {
  const r = await call(mk(), { amount: '250', merchant: 'skyward-air' });
  assert.equal(r.status, 200);
});
test('a plain decimal with trailing zeros still matches (unambiguous everywhere)', async () => {
  const r = await call(mk(), { amount: '250.00', merchant: 'skyward-air' });
  assert.equal(r.status, 200);
});
// Number() coerces all of these to 250, so the OLD comparison treated them as a match and
// forwarded the body verbatim — but the bytes reaching the upstream are the ORIGINAL string,
// and an upstream doing a strict decimal parse, parseInt(_, 10), or literal string storage can
// read the exact same bytes as something other than 250. "The bind check said it matches" is
// only meaningful if every reasonable reader agrees what the number is.
test('a hex-formatted amount does NOT match, even though Number() would coerce it to 250', async () => {
  const r = await call(mk(), { amount: '0xFA', merchant: 'skyward-air' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
});
test('a scientific-notation amount does NOT match, even though Number() would coerce it to 250', async () => {
  const r = await call(mk(), { amount: '2.5e2', merchant: 'skyward-air' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
});
test('a whitespace-padded amount does NOT match, even though Number() would coerce it to 250', async () => {
  const r = await call(mk(), { amount: ' 250', merchant: 'skyward-air' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
});
// String(["skyward-air"]) === "skyward-air", so a naive stringify-and-compare would have
// treated a single-element array as a match even though it is a structurally different
// value than what was signed — and how an upstream reads an array where it expected a
// string is exactly the kind of divergence this binder exists to refuse, not assume about.
test('a single-element array merchant does NOT match, even though String() would coerce it to the same text', async () => {
  const r = await call(mk(), { amount: 250, merchant: ['skyward-air'] });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(r.body.field, 'merchant');
});
// SIGNED constrains a real amount (250) and merchant ('skyward-air'), so all four of these are
// now UNBINDABLE, not "nothing to check" — a real signed value with no way to confirm the body
// honors it is exactly the case this binder exists to refuse. Each was independently confirmed
// live-exploitable under the earlier design (empty body, form-encoded body).
test('an empty body is UNBINDABLE when the signature names a real amount/merchant', async () => {
  const r = await call(mk(), '');
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE'); assert.equal(guardCalls, 0);
});
test('a non-JSON (form-encoded) body is UNBINDABLE for the same reason — no longer an exception', async () => {
  const r = await call(mk(), 'amount=5000&merchant=evil');
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('an empty JSON object {} is UNBINDABLE', async () => {
  const r = await call(mk(), {});
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('an empty JSON array [] is UNBINDABLE', async () => {
  const r = await call(mk(), []);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
// amount/merchant are required BY DEFAULT regardless of what the signed request declares
// (see DEFAULT_VALUE_FIELDS) — deriving the requirement from the signed request itself was
// exactly the exploitable heuristic (amount:0 and an omitted amount key are cryptographically
// identical, and both used to waive the requirement). A route with no value fields at all
// must say so explicitly via `valueFields: []`, not rely on the signed request implying it.
test('a signed request with no real amount/merchant is STILL held to the default required fields', async () => {
  const bare = { agentDid: 'did:x', nonce: 'n', issuedAt: 'now', signature: 's' };
  const r = await call(mk(), '', bare);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('an explicit valueFields: [] opts a genuinely value-less route out, leaving any body shape unbound', async () => {
  const bare = { agentDid: 'did:x', nonce: 'n', issuedAt: 'now', signature: 's' };
  const r = await call(mk({}, { valueFields: [] }), '', bare);
  assert.equal(r.status, 200, 'the route explicitly declared no value fields');
});
// currency alone is never required — many real upstreams never repeat it in the body.
test('a body that omits currency (but includes the required amount/merchant) still binds fine', async () => {
  const r = await call(mk(), { amount: 250, merchant: 'skyward-air' }); // no currency field at all
  assert.equal(r.status, 200);
});
// A signed amount of exactly 0 is a real, deliberate value (the public authorize endpoint's
// own schema accepts it; amount-unknown/amount-over both treat it as known, not absent) — it
// must not drop amount out of the required set. Previously it did: a real merchant matching
// was the only remaining requirement, so a genuine amount hidden elsewhere in the body (e.g.
// nested, exactly as retest#1-#4 above exploit a MEANINGFULLY-signed amount) rode through
// completely unchecked once the issuer had granted a $0 authorization for the same merchant.
test('a signed amount of exactly 0 still requires the body to expose amount (present, matching)', async () => {
  const zeroSigned = { ...SIGNED, amount: 0 };
  const r = await call(mk(), { merchant: 'skyward-air' }, zeroSigned); // no amount key at all
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('a signed amount of 0 catches a real amount hidden elsewhere in the body (the reported bypass)', async () => {
  const zeroSigned = { ...SIGNED, amount: 0 };
  // Same shape as the nested-binder exploit above, but through the DEFAULT binder: a decoy
  // top-level merchant plus a real amount one level down. Previously allowed because amount
  // wasn't required at all once signed as 0; must now be UNBINDABLE like every other
  // meaningfully-signed-but-hidden amount.
  const r = await call(mk(), { merchant: 'skyward-air', booking: { amount: 5000 } }, zeroSigned);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('a signed amount of 0 still allows an honest body that also declares amount: 0', async () => {
  const zeroSigned = { ...SIGNED, amount: 0 };
  const r = await call(mk(), { amount: 0, merchant: 'skyward-air' }, zeroSigned);
  assert.equal(r.status, 200);
});
// Design constraint: verifyRequest() destructures `amount = 0` before rebuilding the canonical
// message, so a signed blob that OMITS the amount key entirely and one that explicitly signs
// amount:0 verify against the IDENTICAL signature — an attacker gains nothing extra by signing
// 0 versus never mentioning amount at all. A fix keyed on "was amount MEANINGFUL in the signed
// request" (whatever that value was) is therefore equally attacker-controlled either way; the
// required set must not depend on the signed request's amount at all (see DEFAULT_VALUE_FIELDS).
test('an OMITTED amount key is treated identically to a signed 0 — same bypass, same fix', async () => {
  const noAmountKey = { agentDid: 'did:x', currency: 'USD', merchant: 'skyward-air', nonce: 'n', issuedAt: 'now', signature: 's' };
  const r = await call(mk(), { merchant: 'skyward-air', booking: { amount: 5000 } }, noAmountKey);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('nested value needs a route binder - and then it blocks', async () => {
  const gw = mk({}, { bind: (req) => { const b = JSON.parse(req.rawBody.toString('utf8')); return { amount: b.booking?.amount }; } });
  const r = await call(gw, { booking: { amount: 5000 } });
  assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
});
// The exploit as reported: sign $250/skyward-air, ship the REAL values one level deeper than
// the DEFAULT binder looks. Before the UNBINDABLE fix these all forwarded with status 200 —
// the flat top-level matcher found none of amount/currency/merchant, returned null, and the
// gateway treated "found nothing" as "nothing to check" instead of "cannot confirm the match".
test('DEFAULT binder: a nested payload is blocked, not silently forwarded', async () => {
  const r = await call(mk(), { booking: { amount: 5000, merchant: 'evil-corp' } });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE'); assert.equal(forwarded, null);
});
test('DEFAULT binder: a JSON array payload is blocked', async () => {
  const r = await call(mk(), [{ amount: 5000, merchant: 'evil-corp' }]);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('DEFAULT binder: capitalized field names are blocked (exact key match only)', async () => {
  const r = await call(mk(), { Amount: 5000, Merchant: 'evil-corp' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('DEFAULT binder: a differently-named field is blocked', async () => {
  const r = await call(mk(), { total: 5000, vendor: 'evil-corp' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('DEFAULT binder: UNBINDABLE is reached BEFORE the guard - burns no nonce either', async () => {
  await call(mk(), { booking: { amount: 5000 } });
  assert.equal(guardCalls, 0, 'guard.verifyRequest must not be reached');
});

// The four variants from the adversarial retest that the first UNBINDABLE fix (checking only
// "did we find ZERO of the three fields") did not catch: each smuggles the real amount past a
// CORRECT decoy in one of the other fields, which made `out` non-empty and skipped the
// UNBINDABLE path entirely — only the fields that WERE found got compared, and amount, being
// merely absent rather than present-and-wrong, was never itself flagged. Fixed by requiring
// amount/merchant unconditionally (see DEFAULT_VALUE_FIELDS), not just checking whether the
// body offered nothing at all.
test('retest #1: correct merchant decoy + nested real amount is UNBINDABLE', async () => {
  const r = await call(mk(), { merchant: 'skyward-air', booking: { amount: 5000 } });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE'); assert.equal(forwarded, null);
});
test('retest #2: correct currency decoy + amount renamed to `total` is UNBINDABLE', async () => {
  const r = await call(mk(), { currency: 'USD', total: 5000 });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('retest #3: correct-looking top-level amount + an extra field the tool also reads is NOT something this generic binder can see BY DEFAULT', async () => {
  // Documented limitation of the DEFAULT (non-strict) binder, not a bug it can fix generically:
  // amount/merchant both check out clean here, so binding correctly ALLOWS the call — the risk
  // is an upstream that ALSO honors an arbitrary extra key (`surcharge`) the binder has no way
  // to know is meaningful. W4/route.allowedFields (below) is the opt-in mitigation.
  const r = await call(mk(), { amount: 250, merchant: 'skyward-air', extra: { surcharge: 4750 } });
  assert.equal(r.status, 200, 'amount/merchant genuinely match what was signed');
});
test('strict mode (route.allowedFields) refuses the SAME additive extra key retest #3 forwards by default', async () => {
  const r = await call(mk({}, { allowedFields: ['amount', 'currency', 'merchant'] }), { amount: 250, merchant: 'skyward-air', extra: { surcharge: 4750 } });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('strict mode still allows an honest body carrying only allowlisted fields', async () => {
  const r = await call(mk({}, { allowedFields: ['amount', 'currency', 'merchant'] }), { amount: 250, currency: 'USD', merchant: 'skyward-air' });
  assert.equal(r.status, 200);
});
test('strict mode refuses an array body outright, regardless of its contents', async () => {
  const r = await call(mk({}, { allowedFields: ['amount', 'merchant'] }), [{ amount: 250, merchant: 'skyward-air' }]);
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('a numeric-string amount matches VALUE under the default binder (documented, decimal-equal)', async () => {
  const r = await call(mk(), { amount: '250', merchant: 'skyward-air' });
  assert.equal(r.status, 200, 'still decimal-equal — not the hex/exponent divergence class');
});
test('strict mode refuses the SAME decimal-equal numeric-string amount as a type mismatch', async () => {
  const r = await call(mk({}, { allowedFields: ['amount', 'merchant'] }), { amount: '250', merchant: 'skyward-air' });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
// W5's second half: currency has always been comparable via `valueFields`, just not required
// by DEFAULT (see DEFAULT_VALUE_FIELDS) — a route whose governing mandate carries a unit-
// bearing constraint should require it explicitly, the same way it opts into anything else.
test('currency becomes required, not just compared, once a route explicitly lists it in valueFields', async () => {
  const r = await call(mk({}, { valueFields: ['amount', 'currency', 'merchant'] }), { amount: 250, merchant: 'skyward-air' }); // no currency key at all
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('a route requiring currency still allows an honest body that includes a matching one', async () => {
  const r = await call(mk({}, { valueFields: ['amount', 'currency', 'merchant'] }), { amount: 250, currency: 'USD', merchant: 'skyward-air' });
  assert.equal(r.status, 200);
});
test('retest #4: correct merchant + amount renamed to `total` (no nesting) is UNBINDABLE', async () => {
  const r = await call(mk(), { merchant: 'skyward-air', total: 5000 });
  assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
});
test('bind:false restores legacy behaviour (opt-out works)', async () => {
  const r = await call(mk({ bind: false }), { amount: 5000, merchant: 'evil-corp' });
  assert.equal(r.status, 200, 'opt-out must forward the tampered body');
});
test('a throwing binder fails CLOSED', async () => {
  const gw = mk({}, { bind: () => { throw new Error('boom'); } });
  const r = await call(gw, { amount: 250 });
  assert.equal(r.status, 502); assert.equal(r.body.reasonCode, 'BIND_ERROR'); assert.equal(forwarded, null);
});
test('unmatched route under denyByDefault is unchanged', async () => {
  const r = await call(mk(), { amount: 250 }, SIGNED, '/other');
  assert.equal(r.body.reasonCode, 'ROUTE_NOT_ALLOWED');
});
test('missing governance header is unchanged', async () => {
  const r = await mk()({ method: 'POST', path: '/book-flight', headers: {}, rawBody: Buffer.from('{}') });
  assert.equal(r.status, 401); assert.equal(r.body.reasonCode, 'MISSING_GOVERNANCE');
});

// W3 deprecation window: a value-bearing route (has an `action`) with no explicit binding
// decision should be LOUD about it at construction, naming the route, rather than silently
// installing the default heuristic — even though that default is itself safe (see above).
test('a route with an action but no explicit valueFields/bind warns at construction, naming the route', () => {
  const warnings = [];
  const realWarn = console.warn;
  console.warn = (msg) => warnings.push(msg);
  try {
    createHttpGateway({ guard, forward, routes: [{ method: 'POST', path: '/undeclared', action: 'flight-purchase' }] });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /POST \/undeclared/);
    assert.match(warnings[0], /action: "flight-purchase"/);
    assert.match(warnings[0], /valueFields/);
  } finally { console.warn = realWarn; }
});
test('a route with an explicit valueFields (even matching the default) does not warn', () => {
  const warnings = [];
  const realWarn = console.warn;
  console.warn = (msg) => warnings.push(msg);
  try {
    createHttpGateway({ guard, forward, routes: [{ method: 'POST', path: '/declared', action: 'flight-purchase', valueFields: ['amount', 'merchant'] }] });
    assert.equal(warnings.length, 0);
  } finally { console.warn = realWarn; }
});
test('a route with an explicit bind (including bind:false) does not warn', () => {
  const warnings = [];
  const realWarn = console.warn;
  console.warn = (msg) => warnings.push(msg);
  try {
    createHttpGateway({ guard, forward, routes: [{ method: 'POST', path: '/a', action: 'x', bind: false }, { method: 'POST', path: '/b', action: 'y', bind: () => null }] });
    assert.equal(warnings.length, 0);
  } finally { console.warn = realWarn; }
});
test('a route with no action at all (not governed) does not warn', () => {
  const warnings = [];
  const realWarn = console.warn;
  console.warn = (msg) => warnings.push(msg);
  try {
    createHttpGateway({ guard, forward, routes: [{ method: 'GET', path: '/health' }] });
    assert.equal(warnings.length, 0);
  } finally { console.warn = realWarn; }
});

let pass = 0, fail = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m ' + name); pass++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m ' + name + '\n       ' + e.message); fail++; }
}
console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

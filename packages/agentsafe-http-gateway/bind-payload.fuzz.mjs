// Property-based fuzzing for the payload binder, complementing bind-payload.smoke.mjs.
// That file encodes SPECIFIC known-attack shapes (a decoy top-level field, one renamed
// field, one hex string) — one example per historical bug. This file instead generates
// many random variations of "hide the real amount/merchant somewhere the binder won't
// see it" and asserts the INVARIANT that must hold for every one of them, not just the
// four shapes anyone has thought to hand-write so far (attack.mjs/attack2.mjs/attack3.mjs/
// attack4.mjs in agentsafe-cleanroom). No dependency (fast-check et al.) is added here —
// this package ships zero-dependency and its smoke tests run with no `npm install` step
// in CI, so the fuzzer is hand-rolled with only Math.random() and Node built-ins.
//
//   node bind-payload.fuzz.mjs [iterations-per-category]   (default 400)
//
// Exits non-zero (and prints every failing case) the moment a single generated body
// defeats the invariant — this is meant to be wired into `npm test` alongside the smoke
// suite, not run-and-eyeball.
import assert from 'node:assert/strict';
import { createHttpGateway } from './gateway.mjs';

const N = Number(process.argv[2]) || 400;
let seed = 0x1234567 ^ Date.now();
function rand() {
  // xorshift32 — deterministic-if-seeded, fast, no dependency. Date.now() above only
  // varies the seed run-to-run; a failure always prints the seed that produced it.
  seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; seed |= 0;
  return ((seed >>> 0) / 0xffffffff);
}
function randInt(min, max) { return min + Math.floor(rand() * (max - min + 1)); }
function pick(arr) { return arr[randInt(0, arr.length - 1)]; }

const guard = { verifyRequest: async () => ({ decision: 'allow', reasonCode: 'AUTHORIZED' }) };
let forwarded = null;
const forward = async (req) => { forwarded = req; return { status: 200, body: { ran: true } }; };
const gw = createHttpGateway({
  guard, forward, denyByDefault: true,
  routes: [{ method: 'POST', path: '/book-flight', action: 'flight-purchase', valueFields: ['amount', 'merchant'] }],
});
const strictGw = createHttpGateway({
  guard, forward, denyByDefault: true,
  routes: [{ method: 'POST', path: '/book-flight', action: 'flight-purchase', valueFields: ['amount', 'merchant'], allowedFields: ['amount', 'currency', 'merchant'] }],
});

async function call(target, body, amount, merchant) {
  forwarded = null;
  const signed = { agentDid: 'did:x', amount, currency: 'USD', merchant, nonce: 'n', issuedAt: 'now', signature: 's' };
  const res = await target({
    method: 'POST', path: '/book-flight', headers: { 'x-magp-request': JSON.stringify(signed) },
    rawBody: Buffer.from(JSON.stringify(body)),
  });
  return { res, forwarded };
}

// ---------------------------------------------------------------------------
// Random shape generators
// ---------------------------------------------------------------------------

/** A JSON-safe scalar unrelated to the two governed fields — filler for decoy structure. */
function randomScalar() {
  return pick([randInt(1, 999), `s${randInt(1, 999)}`, true, false, null]);
}

/** A plausible-but-wrong key name an attacker (or an honest but differently-shaped
 *  upstream) might use instead of the exact governed key. */
function decoyKeyFor(field) {
  return pick({
    amount: ['Amount', 'AMOUNT', 'amount_usd', 'amt', 'total', 'price', 'value', 'booking_amount'],
    merchant: ['Merchant', 'MERCHANT', 'merchant_id', 'vendor', 'seller', 'provider', 'merchantName'],
  }[field]);
}

/** Wrap `value` at random depth (1-4) under randomly-named container keys, so it is
 *  reachable but NOT at the body's top level under any key at all. */
function nestDeep(field, value) {
  const depth = randInt(1, 4);
  let node = { [field]: value };
  for (let i = 0; i < depth; i++) node = { [`${pick(['data', 'booking', 'details', 'meta', 'payload', 'inner'])}${i}`]: node };
  return node;
}

/** Build a body where `field`'s real value is hidden by one of several strategies, and
 *  the top level has no key that canonically carries it. Returns { body, hidden: true }. */
function hideField(field, value) {
  const strategy = pick(['nested', 'renamed-top-level', 'array-wrap', 'omitted', 'wrong-value-same-key']);
  switch (strategy) {
    case 'nested':
      return nestDeep(field, value);
    case 'renamed-top-level':
      return { [decoyKeyFor(field)]: value };
    case 'array-wrap':
      // Present at the real key, but as [value] instead of value — a different structural
      // type than what was signed, which boundValueMatches must not treat as equal.
      return { [field]: [value] };
    case 'omitted':
      return {};
    case 'wrong-value-same-key':
      return { [field]: field === 'amount' ? value + randInt(1, 9999) + 1 : `${value}-not-the-real-one` };
    default:
      throw new Error('unreachable');
  }
}

function merge(...objs) { return Object.assign({}, ...objs); }

/** N random extra top-level fields that are neither `amount` nor `merchant` — benign
 *  noise an honest upstream body might legitimately carry alongside the governed fields. */
function benignExtras() {
  const out = {};
  for (let i = 0; i < randInt(0, 3); i++) out[`extra_${pick(['risk', 'note', 'ref', 'tag', 'flag'])}_${i}`] = randomScalar();
  return out;
}

// Canonical-decimal strings that represent the SAME numeric value as `n` and MUST match
// (an independent oracle, not a copy of parseCanonicalAmount — this is what the README's
// contract promises, not a restatement of the implementation under test).
function canonicalStringVariantsOf(n) {
  const variants = [String(n), `${n}.0`, `${n}.00`];
  if (n >= 0) variants.push(`0${n}`); // leading zero — still `-?\d+(\.\d+)?`, still unambiguous
  return variants;
}

// Strings whose bytes are ambiguous or read differently by a strict downstream decimal
// parser than by JS's `Number()` coercion — MUST NOT match even though they represent the
// same value under `Number()`.
function nonCanonicalStringVariantsOf(n) {
  const hex = '0x' + Math.abs(Math.trunc(n)).toString(16);
  return [
    `${n}e0`, `${n}E0`,           // exponent notation
    ` ${n}`, `${n} `,             // whitespace
    `+${n}`,                      // explicit leading plus
    hex,                          // hex
    `${n},00`,                    // thousands/decimal-comma ambiguity
  ];
}

// ---------------------------------------------------------------------------
// Fuzz runs
// ---------------------------------------------------------------------------

const failures = [];
function record(label, cond, detail) {
  if (!cond) failures.push({ label, detail, seed });
}

async function fuzzHiddenAmount() {
  for (let i = 0; i < N; i++) {
    const amount = randInt(1, 100000);
    const merchant = pick(['skyward-air', 'acme', 'globex']);
    const body = merge(hideField('amount', amount), { merchant }, benignExtras());
    const { res } = await call(gw, body, amount, merchant);
    // The real amount is not verifiably at the top level -> must never forward as 200,
    // regardless of which of the five hiding strategies was chosen this iteration.
    record('hidden-amount must never forward', res.status !== 200, { body, amount, merchant, status: res.status });
  }
}

async function fuzzHiddenMerchant() {
  for (let i = 0; i < N; i++) {
    const amount = randInt(1, 100000);
    const merchant = pick(['skyward-air', 'acme', 'globex']);
    const body = merge({ amount }, hideField('merchant', merchant), benignExtras());
    const { res } = await call(gw, body, amount, merchant);
    record('hidden-merchant must never forward', res.status !== 200, { body, amount, merchant, status: res.status });
  }
}

async function fuzzHiddenBoth() {
  for (let i = 0; i < N; i++) {
    const amount = randInt(1, 100000);
    const merchant = pick(['skyward-air', 'acme', 'globex']);
    const body = merge(hideField('amount', amount), hideField('merchant', merchant), benignExtras());
    const { res } = await call(gw, body, amount, merchant);
    record('hidden-both must never forward', res.status !== 200, { body, amount, merchant, status: res.status });
  }
}

async function fuzzZeroAndSmallAmounts() {
  // The historical NEW-1 finding lived specifically at amount:0 / amount omitted — make
  // sure the general hiding fuzz above is exercised there too, not just at "normal" amounts.
  for (let i = 0; i < N; i++) {
    const amount = pick([0, 0, 1, 0.01]); // weight 0 heavily — that's the finding's exact edge
    const merchant = pick(['skyward-air', 'acme']);
    const body = merge(hideField('amount', amount), { merchant }, benignExtras());
    const { res } = await call(gw, body, amount, merchant);
    record('hidden zero/near-zero amount must never forward', res.status !== 200, { body, amount, merchant, status: res.status });
  }
}

async function fuzzHonestPathNeverFalselyBlocked() {
  for (let i = 0; i < N; i++) {
    const amount = randInt(0, 100000);
    const merchant = pick(['skyward-air', 'acme', 'globex']);
    const body = merge({ amount, currency: 'USD', merchant }, benignExtras());
    const { res, forwarded: fwd } = await call(gw, body, amount, merchant);
    record('honest top-level body must forward', res.status === 200 && fwd != null, { body, amount, merchant, status: res.status });
  }
}

async function fuzzCanonicalAmountStrings() {
  for (let i = 0; i < N; i++) {
    const amount = randInt(0, 100000);
    const merchant = pick(['skyward-air', 'acme']);
    const asString = pick(canonicalStringVariantsOf(amount));
    const { res } = await call(gw, { amount: asString, merchant }, amount, merchant);
    record('canonical-equivalent amount string must match', res.status === 200, { asString, amount, merchant, status: res.status });
  }
}

async function fuzzNonCanonicalAmountStrings() {
  for (let i = 0; i < N; i++) {
    const amount = randInt(1, 100000); // avoid 0 (hex/exponent of 0 degenerate to "0")
    const merchant = pick(['skyward-air', 'acme']);
    const asString = pick(nonCanonicalStringVariantsOf(amount));
    const { res } = await call(gw, { amount: asString, merchant }, amount, merchant);
    record('non-canonical amount string must NOT match', res.status !== 200, { asString, amount, merchant, status: res.status });
  }
}

async function fuzzAllowedFieldsStrictMode() {
  for (let i = 0; i < N; i++) {
    const amount = randInt(1, 100000);
    const merchant = pick(['skyward-air', 'acme']);
    const extraKey = pick(['surcharge', 'feeOverride', 'discount', 'note']);
    const body = { amount, currency: 'USD', merchant, [extraKey]: randomScalar() };
    const { res } = await call(strictGw, body, amount, merchant);
    record('allowedFields must reject any undeclared top-level key', res.status !== 200, { body, status: res.status });

    const cleanBody = { amount, currency: 'USD', merchant };
    const { res: cleanRes } = await call(strictGw, cleanBody, amount, merchant);
    record('allowedFields must still forward a body with only declared keys', cleanRes.status === 200, { cleanBody, status: cleanRes.status });
  }
}

const suites = [
  fuzzHiddenAmount, fuzzHiddenMerchant, fuzzHiddenBoth, fuzzZeroAndSmallAmounts,
  fuzzHonestPathNeverFalselyBlocked, fuzzCanonicalAmountStrings, fuzzNonCanonicalAmountStrings,
  fuzzAllowedFieldsStrictMode,
];

for (const suite of suites) await suite();

console.log(`bind-payload.fuzz: ${suites.length} properties x ~${N} random cases each, ${failures.length} failures`);
if (failures.length) {
  console.log('\nFirst 10 failures:');
  for (const f of failures.slice(0, 10)) console.log(JSON.stringify(f, null, 2));
}
// process.exitCode (not process.exit()) — a still-settling handle from the async gateway
// calls above can make process.exit() crash instead of exiting cleanly; see agentsafe-
// cleanroom's gate.mjs for the same fix and why.
process.exitCode = failures.length === 0 ? 0 : 1;

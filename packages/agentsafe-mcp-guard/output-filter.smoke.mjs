// output-filter.smoke.mjs — guardIncomingTool's `output` option: a tool runs only when the text the agent hands it has none
// of the operator's forbidden words, matched as whole words after folding. A refusal names where the word is, never the
// word; nothing runs and a hold this guard settles is released.
//
//   node output-filter.smoke.mjs   → PASS when every case matches.
import crypto from 'node:crypto';
import { buildAuthMessage } from './policy-core.mjs';
import { buildHederaDid } from './magp-did.mjs';
import { createMcpGuard } from './agentsafe-mcp-guard.mjs';
import { assertOutputPolicy, checkOutputValue, forbiddenSet, outputWords } from './output-filter.mjs';

function mint(topic) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const did = buildHederaDid('testnet', spki.subarray(spki.length - 32), topic);
  return { did, sign: (msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), privateKey).toString('hex') };
}

const agent = mint('0.0.930');
const service = mint('0.0.931');
const bundle = { subject: agent.did, mandates: [{ action: 'send-email', document: { permission: [{ target: 'send-email', constraint: [] }] } }] };

function signedRequest(extra = {}) {
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const signature = agent.sign(buildAuthMessage({ agentDid: agent.did, action: 'send-email', amount: 0, currency: 'USD', merchant: '', nonce, issuedAt }));
  return { agentDid: agent.did, action: 'send-email', amount: 0, currency: 'USD', merchant: '', nonce, issuedAt, signature, ...extra };
}

let failed = 0;
const ok = (cond, name, extra = '') => { if (!cond) failed++; console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${extra ? '  →  ' + extra : ''}`); };
const refusal = async (fn) => { try { await fn(); return null; } catch (e) { return e?.name === 'GovernanceBlocked' ? e.governance : { reasonCode: `THREW ${e?.message}` }; } };
const warn = console.warn; console.warn = () => {};

const OUTPUT = { forbidden: ['ssn', 'Falcon'] };
const guard = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => bundle });
let ran = 0;
let got;
const tool = (output) => guard.guardIncomingTool('send-email', (_signed, args) => { ran++; got = args; return 'sent'; }, { output });

console.log('— the words: folded, split at word boundaries, matched whole —');
{
  ok(JSON.stringify(outputWords('My SSN: ｓｓｎ, Straße')) === JSON.stringify(['my', 'ssn', 'ssn', 'strasse']), 'case, fullwidth and ß fold; punctuation and spaces drop', JSON.stringify(outputWords('My SSN: ｓｓｎ, Straße')));
  ok(JSON.stringify(outputWords('ΟΔΟΣ ﬁle ẞ')) === JSON.stringify(['οδοσ', 'file', 'ss']), 'final sigma, a ligature and capital sharp s fold');
  ok(JSON.stringify(forbiddenSet({ forbidden: ['SSN.', 'ssn', 'Falcon'] })) === JSON.stringify(['falcon', 'ssn']), 'the forbidden set is the words entries split into, deduplicated');
  const at = (v) => checkOutputValue(v, OUTPUT);
  ok(at('lessons on falconry') === null, 'a forbidden word inside another word is not a match');
  ok(at({ to: 'a@b', body: ['hi', 'your SSN is 1'] })?.path === '/body/1', 'a value deep in the body, named by its path');
  const key = at({ meta: { 'a/FALCON~': 1 } });
  ok(key?.path === '/meta' && key?.detail === 'an object key', 'an object key is checked too; the path names its object, never the key', JSON.stringify(key));
  for (const t of ['my_ssn', 'ssn123', '1ssn', 'user.ssn', "SSN's", 'ssn_number']) ok(at(t)?.reasonCode === 'OUTPUT_FORBIDDEN_WORD', `a word joined to others still counts: ${t}`);
  for (const t of ['s­sn', 'ss​n', 's‍sn', 'ssn⁠', 'ssn️']) ok(at(t)?.reasonCode === 'OUTPUT_FORBIDDEN_WORD', `an invisible character does not hide it: ${JSON.stringify(t)}`);
  ok(at({ n: 42 }) === null && checkOutputValue({ n: 4111 }, { forbidden: ['4111'] })?.path === '/n', 'numbers are checked as their text');
}

console.log('\n— a forbidden word stops the tool before it runs —');
{
  ran = 0;
  const r = await refusal(() => tool(OUTPUT)(signedRequest(), { to: 'x@y', body: 'Customer ssn attached' }));
  ok(ran === 0 && r?.reasonCode === 'OUTPUT_FORBIDDEN_WORD' && r?.path === '/body' && r?.executed === false && r?.decision === 'block', 'refused OUTPUT_FORBIDDEN_WORD at /body, nothing ran', JSON.stringify(r));
  ok(!JSON.stringify(r).toLowerCase().includes('ssn'), 'the word is not in the refusal');
  ok((await refusal(() => tool(OUTPUT)(signedRequest(), { body: 'ＦＡＬＣＯＮ launch' })))?.reasonCode === 'OUTPUT_FORBIDDEN_WORD', 'a fullwidth spelling is the same word');
}

console.log('\n— clean text runs, with the snapshot that was checked —');
{
  ran = 0;
  const out = await tool(OUTPUT)(signedRequest(), { to: 'x@y', body: 'lessons attached' });
  ok(out === 'sent' && ran === 1 && got?.body === 'lessons attached', 'the tool ran with the arguments');
  let reads = 0;
  const live = { get body() { reads++; return reads === 1 ? 'fine' : 'the ssn'; } };
  await tool(OUTPUT)(signedRequest(), live);
  ok(got?.body === 'fine' && reads === 1, 'a getter is read once; the handler gets what was checked', `${got?.body}, ${reads} read(s)`);
  const extra = { signal: new AbortController().signal };
  let second;
  await guard.guardIncomingTool('send-email', (_s, _a, x) => { second = x; }, { output: OUTPUT })(signedRequest(), { body: 'ok' }, extra);
  ok(second === extra, 'arguments after the first (an MCP SDK\'s `extra`) are passed through as they are');
  const big = await refusal(() => tool(OUTPUT)(signedRequest(), { n: 1n }));
  ok(big?.reasonCode === 'OUTPUT_UNCHECKABLE' && big?.executed === false, 'arguments JSON cannot carry are refused as uncheckable', JSON.stringify(big));
}

console.log('\n— a hold this guard settles is released when the output is refused —');
{
  const realFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url).replace(/^.*\/authorize\/[^/]+\//, ''));
    return { ok: true, status: 200, json: async () => ({ success: true, data: { ok: true, effectState: 'dispatching', agentDid: agent.did, action: 'send-email', amount: 0, currency: 'USD', merchant: '', claimToken: 'tok-1' } }) };
  };
  try {
    const claiming = createMcpGuard({ allowedAgents: 'any', serviceDid: service.did, fetchBundle: async () => bundle, issuerApi: 'https://issuer.example/api/v1', requireAuthorization: true });
    const settled = claiming.guardIncomingTool('send-email', () => 'sent', { settle: true, output: OUTPUT });
    calls.length = 0;
    const r = await refusal(() => settled({ ...signedRequest(), authorizationId: 'auth-1' }, { body: 'the SSN' }));
    ok(r?.reasonCode === 'OUTPUT_FORBIDDEN_WORD' && calls.includes('void') && !calls.includes('capture'), 'refused: the hold is released (void), never captured', calls.join(','));
  } finally { globalThis.fetch = realFetch; }
}

console.log('\n— a misconfigured tool fails when it is wrapped; a request that fails verification is never checked —');
{
  for (const bad of [null, [], {}, { forbidden: [] }, { forbidden: ['credit card'] }, { forbidden: ['e-mail'] }, { forbidden: [' '] }, { forbidden: [7] }, { forbidden: ['ssn'], fields: ['/x'] }]) {
    let threw = false;
    try { guard.guardIncomingTool('send-email', () => {}, { output: bad }); } catch { threw = true; }
    ok(threw, `refused at wrap time: ${JSON.stringify(bad)}`);
  }
  ok((() => { try { assertOutputPolicy({ output: { forbidden: ['credit_card', 'SSN.'] } }); return true; } catch { return false; } })(), 'an underscore joins a word; trailing punctuation drops');
  const unverified = await refusal(() => tool(OUTPUT)({ ...signedRequest(), signature: '00' }, { body: 'ssn' }));
  ok(unverified && !String(unverified.reasonCode).startsWith('OUTPUT_'), 'an unverified request is refused for that, not for its text', unverified?.reasonCode);
  const plain = guard.guardIncomingTool('send-email', (_s, a) => a);
  const args = { body: 'ssn' };
  ok((await plain(signedRequest(), args)) === args, 'no `output`: the arguments reach the handler as they are');
}

console.warn = warn;
console.log(failed === 0 ? '\nPASS' : `\nFAIL (${failed})`);
process.exit(failed === 0 ? 0 : 1);

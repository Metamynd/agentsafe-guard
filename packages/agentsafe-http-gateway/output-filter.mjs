// output-filter.mjs — the output check on what an agent sends out through a tool or a route (`output`).
//
// An agent can be talked into writing what it must not release: a customer's SSN into an email, an internal codename
// into a public post, a secret into a ticket. The operator names, per tool or route, a set of forbidden words. The text
// the agent sends is then released only when none of its words is one of them.
//
// Words are matched the way ZKBC's output family states its relation, made stricter where that is safe: the text is
// folded (NFKC, then case folding, with invisible format characters removed) and split into words (Unicode word
// boundaries, UAX #29, with whitespace and punctuation dropped), and each word, and each run of letters or digits inside
// it, is compared with each forbidden word folded the same way. `SSN`, fullwidth `ｓｓｎ`, `my_ssn` and `ssn123` all hold
// `ssn`; `lessons` does not, and neither does `s s n`. This is a guard against a mistake, not against an agent that is
// trying to evade it. Scripts written without spaces (Chinese, Japanese, Thai, Korean) are split by dictionary or not
// at all, so a forbidden word in them may not be found inside a longer run of text.
//
// It fails closed: a forbidden word that is not one word after folding is refused when the policy is loaded (it could
// never match), and text that cannot be read as written (not UTF-8, JSON that is not strict, a value JSON cannot carry,
// more fields than the cap) is refused as uncheckable. Every string in the body is checked, object keys included. The
// refusal names where the word is, never the word.
//
// Used by guardIncomingTool's `output` option here, by agentsafe-http-gateway's `route.output`, and by the OpenShell
// adapter's request stage. Zero dependencies. The two packages ship identical copies (the gateway imports nothing from
// the guard at runtime); agentsafe-http-gateway/output-filter.smoke.mjs fails if they differ.

const KEYS = new Set(['forbidden']);
const MAX_NODES = 100_000;
const SEPARATOR_ONLY = /^[\p{White_Space}\p{P}]+$/u;
// Format characters (soft hyphen, zero-width space and joiners, word joiner, BOM, tags) and variation selectors draw
// nothing, so a word with one inside reads the same as one without.
const INVISIBLE = /[\p{Cf}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/gu;
const RUNS = /[\p{L}\p{M}]+|\p{N}+/gu;
let segmenter;

/**
 * `fold`: NFKC, invisible characters removed, then case folding. JavaScript has no full case fold, so it is lower, upper,
 * lower again (which also folds `ẞ` and `ß` to `ss`), a final sigma folded to `σ`, and NFKC once more. It collapses at
 * least what default case folding does, so it can only match more words, never fewer.
 */
export function foldText(text) {
  return String(text).normalize('NFKC').replace(INVISIBLE, '').toLowerCase().toUpperCase().toLowerCase().replace(/ς/g, 'σ').normalize('NFKC');
}

/** The words of `text` after folding: UAX #29 word segments, those that are only whitespace or punctuation dropped. */
export function outputWords(text) {
  segmenter ??= new Intl.Segmenter('und', { granularity: 'word' });
  const words = [];
  for (const { segment } of segmenter.segment(foldText(text))) if (!SEPARATOR_ONLY.test(segment)) words.push(segment);
  return words;
}

/** What a text is matched on: each word, and each run of letters or of digits inside it (`my_ssn` gives `my`, `ssn`). */
function matchForms(text) {
  const forms = new Set();
  for (const word of outputWords(text)) {
    forms.add(word);
    for (const run of word.match(RUNS) ?? []) forms.add(run);
  }
  return forms;
}

/**
 * The forbidden set as the check uses it: each entry as the one word it splits into (so `SSN.` is `ssn`, the same word a
 * text's `SSN.` gives), sorted and deduplicated. Call it on a policy assertOutputPolicy accepted.
 */
export function forbiddenSet(output) {
  return [...new Set(output.forbidden.map((w) => outputWords(w)[0]))].sort();
}

/**
 * An `output` policy (a route's or a tool's), checked at startup: throws on anything that could not be enforced as
 * written. `holder` carries it as `holder.output`; `where` names the holder in the error (a route by method and path).
 */
export function assertOutputPolicy(holder, where = `route "${holder?.method ?? '*'} ${holder?.path}"`) {
  const output = holder?.output;
  if (output === undefined) return;
  if (output === null || typeof output !== 'object' || Array.isArray(output)) throw new Error(`output for ${where} must be an object`);
  for (const k of Object.keys(output)) if (!KEYS.has(k)) throw new Error(`output for ${where} has an unknown key "${k}" (forbidden)`);
  const list = output.forbidden;
  if (!Array.isArray(list) || list.length === 0) throw new Error(`output.forbidden for ${where} must be a non-empty array of words`);
  for (const word of list) {
    if (typeof word !== 'string') throw new Error(`output.forbidden for ${where} has a value that is not a string`);
    // A phrase, or a word that folds to more or less than one word, would never equal a single word of the text.
    if (outputWords(word).length !== 1) throw new Error(`output.forbidden for ${where} has ${JSON.stringify(word)}, which is not exactly one word`);
  }
}

/** The reason codes an output check can give. */
export const OUTPUT_REASON_CODES = Object.freeze(['OUTPUT_FORBIDDEN_WORD', 'OUTPUT_UNCHECKABLE']);

const escape = (seg) => String(seg).replace(/~/g, '~0').replace(/\//g, '~1');
const plain = (o) => { const p = Object.getPrototypeOf(o); return p === Object.prototype || p === null; };

/**
 * Whether `value` (a parsed JSON body, or a tool's arguments) may be released. Null when no string in it, value or object
 * key, has a forbidden word; otherwise { reasonCode, path, detail? }:
 *   OUTPUT_FORBIDDEN_WORD  a string has one; `path` is the JSON Pointer of the string, or of the object whose key has it
 *                          (with detail 'an object key'), so the path never carries the word
 *   OUTPUT_UNCHECKABLE     a value that is not JSON (a Map, a class instance), or more than the cap of fields to check
 * Numbers (and BigInts) are checked as their text; booleans and null carry no words.
 */
export function checkOutputValue(value, output) {
  const forbidden = new Set(forbiddenSet(output));
  const hit = (text) => { for (const f of matchForms(text)) if (forbidden.has(f)) return true; return false; };
  const stack = [{ node: value, path: '' }];
  let visited = 0;
  while (stack.length) {
    const { node, path } = stack.pop();
    if (++visited > MAX_NODES) return { reasonCode: 'OUTPUT_UNCHECKABLE', path: '', detail: `more than ${MAX_NODES} fields to check` };
    if (typeof node === 'string' || typeof node === 'number' || typeof node === 'bigint') {
      if (hit(String(node))) return { reasonCode: 'OUTPUT_FORBIDDEN_WORD', path };
    } else if (Array.isArray(node)) {
      for (let i = node.length - 1; i >= 0; i--) stack.push({ node: node[i], path: `${path}/${i}` });
    } else if (node !== null && typeof node === 'object') {
      if (!plain(node)) return { reasonCode: 'OUTPUT_UNCHECKABLE', path, detail: 'a value that is not plain JSON' };
      const entries = Object.entries(node);
      for (const [k] of entries) if (hit(k)) return { reasonCode: 'OUTPUT_FORBIDDEN_WORD', path, detail: 'an object key' };
      for (let i = entries.length - 1; i >= 0; i--) stack.push({ node: entries[i][1], path: `${path}/${escape(entries[i][0])}` });
    } else if (node !== undefined && node !== null && typeof node !== 'boolean') {
      return { reasonCode: 'OUTPUT_UNCHECKABLE', path, detail: 'a value that is not plain JSON' };
    }
  }
  return null;
}

/** The names and values of a query string or a form body, decoded; throws when one does not decode. */
function formParts(text) {
  const parts = [];
  for (const pair of text.split('&')) for (const part of pair.split('=')) parts.push(decodeURIComponent(part.replace(/\+/g, ' ')));
  return parts;
}

/**
 * The output refusal for a query string (raw, without the `?`), or null. Its names and values are decoded and checked;
 * one that does not decode is uncheckable. The refusal's path is `?`.
 */
export function checkOutputQuery(query, output) {
  if (!query) return null;
  let parts;
  try {
    parts = formParts(query);
  } catch {
    return { reasonCode: 'OUTPUT_UNCHECKABLE', path: '?', detail: 'the query string does not decode' };
  }
  const found = checkOutputValue(parts, output);
  return found ? { ...found, path: '?' } : null;
}

/**
 * The output refusal for a request body as text, or null. `contentType` is the request's Content-Type (or undefined).
 * `parseJson` is the strict JSON reader the caller trusts (one that refuses duplicate keys).
 *   - A form body (application/x-www-form-urlencoded) is decoded and checked like a query string.
 *   - A JSON body (a JSON content type, or text that starts like JSON) must parse strictly, then every string in it is
 *     checked; one that does not parse is uncheckable, since what the upstream reads from it cannot be known.
 *   - Anything else is checked as one text.
 */
export function checkOutputBody(text, contentType, output, parseJson) {
  if (!text) return null;
  const type = String(contentType ?? '').toLowerCase();
  if (type.includes('application/x-www-form-urlencoded')) {
    let parts;
    try {
      parts = formParts(text);
    } catch {
      return { reasonCode: 'OUTPUT_UNCHECKABLE', path: '', detail: 'the form body does not decode' };
    }
    return checkOutputValue(parts, output);
  }
  const trimmed = text.trim();
  if (type.includes('json') || /^[[{"]/.test(trimmed)) {
    let body;
    try {
      body = parseJson(trimmed);
    } catch {
      return { reasonCode: 'OUTPUT_UNCHECKABLE', path: '', detail: 'the body is not strict JSON' };
    }
    return checkOutputValue(body, output);
  }
  return checkOutputValue(text, output);
}

// output-filter.mjs — the output check on what an agent sends out through a tool or a route (`output`).
//
// An agent can be talked into writing what it must not release: a customer's SSN into an email, an internal codename
// into a public post, a secret into a ticket. The operator names, per tool or route, a set of forbidden words. The text
// the agent sends is then released only when none of its words is one of them.
//
// Words are matched by ZKBC's output relation exactly, and then more strictly where that is safe:
//   - ZKBC's canonical form (canonicalOutputTokens): `fold` = NFKC then Unicode default case folding (the C and F
//     mappings of CaseFolding.txt, generated into casefold-data.mjs and pinned to that Unicode version), then UAX #29
//     words with whitespace- and punctuation-only tokens dropped. A text is refused when one of its tokens is a forbidden
//     word folded the same way. OUTPUT_CANONICALIZATION is the descriptor ZKBC commits to.
//   - Stricter (never looser): invisible format characters are also removed before folding, and each word is also split
//     into its runs of letters and of digits. `SSN`, fullwidth `ｓｓｎ`, `my_ssn`, `ssn123` and `s<zero-width space>sn`
//     all hold `ssn`; `lessons` does not, and neither does `s s n`.
//   - A forbidden word in a script written without spaces between words (Chinese, Japanese, Thai, Lao, Khmer, Myanmar,
//     Tibetan, Yi, Bopomofo, Javanese, Balinese; Korean attaches particles to words) is matched as a substring of the
//     folded text with its whitespace removed, since word boundaries there come from a dictionary, if at all. A short entry
//     therefore also matches inside longer words (`死` inside `死亡`): choose such entries with that in mind. That part is
//     outside ZKBC's token relation (canonicalForbiddenSet says so).
// This is a guard against a mistake, not against an agent that is trying to evade it.
//
// It fails closed: a forbidden word that is not one word after folding (outside the scripts above) is refused when the
// policy is loaded (it could never match), and text that cannot be read as written (not UTF-8, JSON that is not strict, a
// value JSON cannot carry, more fields than the cap, a path or query that does not decode) is refused as uncheckable.
// Every string in the body is checked, object keys included; a request's path too (unless `path: false`), and the headers
// it names (`headers`). The refusal names where the word is, never the word.
//
// Used by guardIncomingTool's `output` option here, by agentsafe-http-gateway's `route.output`, and by the OpenShell
// adapter's request stage. Zero dependencies. The two packages ship identical copies of this file and casefold-data.mjs
// (the gateway imports nothing from the guard at runtime); agentsafe-http-gateway/output-filter.smoke.mjs fails if they differ.

import { CASEFOLD_DATA, CASEFOLD_UNICODE } from './casefold-data.mjs';

const KEYS = new Set(['forbidden']);
const REQUEST_KEYS = new Set(['forbidden', 'path', 'headers']);
const MAX_NODES = 100_000;
const SEPARATOR_ONLY = /^[\p{White_Space}\p{P}]+$/u;
// Format characters (soft hyphen, zero-width space and joiners, word joiner, BOM, tags) and variation selectors draw
// nothing, so a word with one inside reads the same as one without.
const INVISIBLE = /[\p{Cf}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/gu;
const RUNS = /[\p{L}\p{M}]+|\p{N}+/gu;
// Scripts written without spaces between words (or, for Hangul, with particles attached to them).
const NO_SPACE = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}\p{Script=Lao}\p{Script=Khmer}\p{Script=Myanmar}\p{Script=Tibetan}\p{Script=Yi}\p{Script=Bopomofo}\p{Script=Javanese}\p{Script=Balinese}]/u;
let segmenter;
let FOLD;

/** Unicode default case folding (CaseFolding.txt C + F) of a string, code point by code point. */
function caseFold(text) {
  if (!FOLD) {
    FOLD = new Map();
    for (const entry of CASEFOLD_DATA.split(',')) {
      const [from, to] = entry.split(':');
      FOLD.set(parseInt(from, 16), String.fromCodePoint(...to.split(' ').map((h) => parseInt(h, 16))));
    }
  }
  let out = '';
  for (const ch of text) out += FOLD.get(ch.codePointAt(0)) ?? ch;
  return out;
}

/**
 * ZKBC's canonicalization descriptor for the output family (RFC 8785 canonical JSON of this object is what
 * `output.canonicalization` commits to). `unicode` is the version casefold-data.mjs was generated from.
 */
export const OUTPUT_CANONICALIZATION = Object.freeze({ unicode: CASEFOLD_UNICODE, identifier_form: 'nfc', matching_form: 'nfkc+casefold', tokenizer: 'uax29-words' });

/**
 * Whether this runtime's NFKC and UAX #29 segmentation (its ICU) are the Unicode version the descriptor pins. Matching
 * works either way; a ZKBC receipt over canonicalOutputTokens is only faithful when this is true.
 */
export function outputCanonicalizationMatchesRuntime() {
  const v = globalThis.process?.versions?.unicode;
  return typeof v === 'string' && (v === CASEFOLD_UNICODE || CASEFOLD_UNICODE.startsWith(`${v}.`));
}

/** ZKBC's `fold`, exactly: NFKC, then Unicode default case folding (the result is encoded as UTF-8 where it is hashed). */
export function zkbcFold(text) {
  return caseFold(String(text).normalize('NFKC'));
}

function words(folded) {
  segmenter ??= new Intl.Segmenter('und', { granularity: 'word' });
  const out = [];
  for (const { segment } of segmenter.segment(folded)) if (!SEPARATOR_ONLY.test(segment)) out.push(segment);
  return out;
}

/** ZKBC's canonical form of an output text: the multiset (as a list) of UAX #29 word tokens of zkbcFold(text). */
export function canonicalOutputTokens(text) {
  return words(zkbcFold(text));
}

/**
 * The stricter fold this check also matches on: NFKC, invisible characters removed, case folded, then upper- and
 * lower-cased once more (which also merges what default case folding keeps apart, such as dotless `ı` with `i`), folded
 * again (JavaScript's lower case turns a word-final σ back into ς), and NFKC again. Applied to the text and the forbidden
 * words alike, so it can only match more than zkbcFold, never less.
 */
export function foldText(text) {
  return caseFold(caseFold(String(text).normalize('NFKC').replace(INVISIBLE, '')).toUpperCase().toLowerCase()).normalize('NFKC');
}

/** The words of `text` after the stricter fold: UAX #29 word segments, those only whitespace or punctuation dropped. */
export function outputWords(text) {
  return words(foldText(text));
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

const noSpaceEntry = (word) => NO_SPACE.test(word);

/**
 * The forbidden set as the stricter check uses it: each word entry as the one word it splits into (so `SSN.` is `ssn`,
 * the same word a text's `SSN.` gives), and each entry in a script written without spaces as its folded text (matched as a
 * substring), sorted and deduplicated. Call it on a policy assertOutputPolicy accepted.
 */
export function forbiddenSet(output) {
  return [...new Set(output.forbidden.map((w) => (noSpaceEntry(w) ? foldText(w).replace(/\s+/gu, '') : outputWords(w)[0])))].sort();
}

/**
 * The forbidden set in ZKBC's canonical form, for a receipt: `tokens` are the entries that fold to exactly one canonical
 * token (sorted, deduplicated); `outsideTokenRelation` lists the entries ZKBC's token relation cannot express (a word in
 * a script without spaces that its segmenter splits, matched here as a substring), so a receipt can say it does not
 * cover them rather than claim it does.
 */
export function canonicalForbiddenSet(output) {
  const tokens = new Set();
  const outside = [];
  for (const w of output.forbidden) {
    const t = canonicalOutputTokens(w);
    if (t.length === 1) tokens.add(t[0]);
    else outside.push(w);
  }
  return { tokens: [...tokens].sort(), outsideTokenRelation: outside };
}

/**
 * An `output` policy (a route's or a tool's), checked at startup: throws on anything that could not be enforced as
 * written. `holder` carries it as `holder.output`; `where` names the holder in the error (a route by method and path).
 * `request: false` (a tool's arguments) refuses the request-only keys `path` and `headers`, which have nothing to apply to.
 */
export function assertOutputPolicy(holder, where = `route "${holder?.method ?? '*'} ${holder?.path}"`, { request = true } = {}) {
  const output = holder?.output;
  if (output === undefined) return;
  if (output === null || typeof output !== 'object' || Array.isArray(output)) throw new Error(`output for ${where} must be an object`);
  const keys = request ? REQUEST_KEYS : KEYS;
  for (const k of Object.keys(output)) if (!keys.has(k)) throw new Error(`output for ${where} has an unknown key "${k}" (${[...keys].join(', ')})`);
  const list = output.forbidden;
  if (!Array.isArray(list) || list.length === 0) throw new Error(`output.forbidden for ${where} must be a non-empty array of words`);
  for (const word of list) {
    if (typeof word !== 'string') throw new Error(`output.forbidden for ${where} has a value that is not a string`);
    if (noSpaceEntry(word)) {
      // Matched as a substring: it must be one run of text, without spaces, that folds to something.
      if (!foldText(word).trim() || /\s/u.test(word.trim())) throw new Error(`output.forbidden for ${where} has ${JSON.stringify(word)}, which is not one word`);
      continue;
    }
    // A phrase, or a word that folds to more or less than one word, would never equal a single word of the text.
    if (outputWords(word).length !== 1) throw new Error(`output.forbidden for ${where} has ${JSON.stringify(word)}, which is not exactly one word`);
  }
  if (output.path !== undefined && typeof output.path !== 'boolean') throw new Error(`output.path for ${where} must be true or false`);
  if (output.headers !== undefined) {
    if (!Array.isArray(output.headers) || output.headers.some((h) => typeof h !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(h))) {
      throw new Error(`output.headers for ${where} must be a list of header names`);
    }
  }
}

/** The reason codes an output check can give. */
export const OUTPUT_REASON_CODES = Object.freeze(['OUTPUT_FORBIDDEN_WORD', 'OUTPUT_UNCHECKABLE']);

/**
 * Whether a text holds a forbidden word, by any of the three checks (module header): ZKBC's canonical tokens, the stricter
 * words and runs, or a no-space-script entry as a substring. Any one refuses, so this can only refuse more than ZKBC's
 * relation, never less.
 */
function matcher(output) {
  const strict = new Set();
  const substrings = [];
  for (const w of output.forbidden) {
    if (noSpaceEntry(w)) substrings.push(foldText(w).replace(/\s+/gu, ''));
    else strict.add(outputWords(w)[0]);
  }
  const canonical = new Set(canonicalForbiddenSet(output).tokens);
  return (text) => {
    for (const f of matchForms(text)) if (strict.has(f)) return true;
    for (const t of canonicalOutputTokens(text)) if (canonical.has(t)) return true;
    if (substrings.length) {
      const folded = foldText(text).replace(/\s+/gu, '');
      for (const s of substrings) if (folded.includes(s)) return true;
    }
    return false;
  };
}

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
  const hit = matcher(output);
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

/**
 * The output refusal for a request's path (without its query string), or null. Each segment is percent-decoded and
 * checked; one that does not decode is uncheckable. Checked unless the policy says `path: false` (a route whose own fixed
 * path holds a forbidden word, say). The refusal's path is `@path`.
 */
export function checkOutputPath(path, output) {
  if (output.path === false || !path) return null;
  // Decoded repeatedly, to a fixed point (at most 4 rounds), as the gateway's route matcher decodes it: an upstream that
  // decodes twice would otherwise read `ss%256E` as `ssn` after this check saw `ss%6E`. A backslash counts as `/`. As in
  // the matcher, a malformed escape (`/discount/100%`) stops the decoding and the text is checked as far as it decoded:
  // nothing can decode it further, the upstream included. Everything after the first raw `?` is the query string, checked
  // on its own; a `#` or `;params` is checked with the path, which only checks more text.
  let decoded = String(path).split('?')[0];
  for (let round = 0; round < 4; round++) {
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      break;
    }
    if (next === decoded) break;
    decoded = next;
  }
  const segments = decoded.replace(/\\/g, '/').split('/').filter(Boolean);
  const found = checkOutputValue(segments, output);
  return found ? { ...found, path: '@path' } : null;
}

/**
 * The output refusal for the request headers the policy names (`headers`, matched without regard to case), or null.
 * `headers` is a plain object of name to a string or an array of strings. The refusal's path is `@headers/<name>`, the
 * name as the policy gives it.
 */
export function checkOutputHeaders(headers, output) {
  if (!Array.isArray(output.headers) || output.headers.length === 0) return null;
  const byName = new Map();
  for (const [k, v] of Object.entries(headers ?? {})) {
    const list = byName.get(k.toLowerCase()) ?? [];
    for (const one of Array.isArray(v) ? v : [v]) if (one !== undefined && one !== null) list.push(String(one));
    byName.set(k.toLowerCase(), list);
  }
  for (const name of output.headers) {
    const values = byName.get(name.toLowerCase());
    if (!values?.length) continue;
    const found = checkOutputValue(values, output);
    if (found) return { ...found, path: `@headers/${name}` };
  }
  return null;
}

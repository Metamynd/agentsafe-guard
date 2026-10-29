// Types for output-filter.mjs (identical in agentsafe-mcp-guard and agentsafe-http-gateway).

export interface OutputPolicy {
  /**
   * Words the text the agent sends must not contain, each exactly one word (a word in a script written without spaces,
   * such as Chinese or Thai, is matched as a substring instead). Matched after folding (NFKC + Unicode case folding).
   */
  forbidden: string[];
  /** A request's path is checked too, segment by segment, unless this is false. Routes only (not a tool's arguments). */
  path?: boolean;
  /** Request headers whose values are checked too (names, any case). Routes only. */
  headers?: string[];
}

export interface OutputRefusal {
  reasonCode: 'OUTPUT_FORBIDDEN_WORD' | 'OUTPUT_UNCHECKABLE';
  /**
   * The JSON Pointer of the string in the agent's own body ('' for the whole body), '?' for the query string, '@path' for
   * the request path, '@headers/<name>' for a header, or the object whose key has the word (detail 'an object key').
   * Never the word.
   */
  path: string;
  detail?: string;
}

/** ZKBC's canonicalization descriptor for the output family; `unicode` is the pinned case-folding version. */
export const OUTPUT_CANONICALIZATION: Readonly<{ unicode: string; identifier_form: 'nfc'; matching_form: 'nfkc+casefold'; tokenizer: 'uax29-words' }>;
/** Whether this runtime's NFKC and segmentation are the pinned Unicode version (a receipt is faithful only then). */
export function outputCanonicalizationMatchesRuntime(): boolean;
/** ZKBC's fold exactly: NFKC, then Unicode default case folding. */
export function zkbcFold(text: unknown): string;
/** ZKBC's canonical output tokens: UAX #29 words of zkbcFold(text), whitespace- and punctuation-only ones dropped. */
export function canonicalOutputTokens(text: unknown): string[];
/** The forbidden set in ZKBC's canonical form, and the entries its token relation cannot express. */
export function canonicalForbiddenSet(output: OutputPolicy): { tokens: string[]; outsideTokenRelation: string[] };
/** The stricter fold this check also matches on (invisible characters removed). */
export function foldText(text: unknown): string;
export function outputWords(text: unknown): string[];
export function forbiddenSet(output: OutputPolicy): string[];
/** Throws on a policy that could not be enforced as written; `request: false` refuses `path` and `headers`. */
export function assertOutputPolicy(holder: { output?: OutputPolicy; method?: string; path?: string } | null | undefined, where?: string, options?: { request?: boolean }): void;
export const OUTPUT_REASON_CODES: readonly ['OUTPUT_FORBIDDEN_WORD', 'OUTPUT_UNCHECKABLE'];
/** Null when no string in `value`, value or key, has a forbidden word. `value` is parsed JSON. */
export function checkOutputValue(value: unknown, output: OutputPolicy): OutputRefusal | null;
/** A raw query string (no `?`): its names and values decoded and checked. */
export function checkOutputQuery(query: string, output: OutputPolicy): OutputRefusal | null;
/** A request body as text, read by its Content-Type: a form decoded, JSON by `parseJson` (strict), else one text. */
export function checkOutputBody(text: string, contentType: string | undefined, output: OutputPolicy, parseJson: (text: string) => unknown): OutputRefusal | null;
/** A request path (its query string ignored): each segment decoded and checked, unless `output.path` is false. */
export function checkOutputPath(path: string, output: OutputPolicy): OutputRefusal | null;
/** The request headers `output.headers` names. */
export function checkOutputHeaders(headers: Record<string, string | string[] | undefined> | null | undefined, output: OutputPolicy): OutputRefusal | null;

// Types for output-filter.mjs (identical in agentsafe-mcp-guard and agentsafe-http-gateway).

export interface OutputPolicy {
  /** Words the text the agent sends must not contain, each exactly one word. Matched after folding (NFKC + case). */
  forbidden: string[];
}

export interface OutputRefusal {
  reasonCode: 'OUTPUT_FORBIDDEN_WORD' | 'OUTPUT_UNCHECKABLE';
  /**
   * The JSON Pointer of the string in the agent's own body ('' for the whole body, '?' for the query string), or of the
   * object whose key has the word (detail 'an object key'). Never the word.
   */
  path: string;
  detail?: string;
}

export function foldText(text: unknown): string;
export function outputWords(text: unknown): string[];
export function forbiddenSet(output: OutputPolicy): string[];
export function assertOutputPolicy(holder: { output?: OutputPolicy; method?: string; path?: string } | null | undefined, where?: string): void;
export const OUTPUT_REASON_CODES: readonly ['OUTPUT_FORBIDDEN_WORD', 'OUTPUT_UNCHECKABLE'];
/** Null when no string in `value`, value or key, has a forbidden word. `value` is parsed JSON. */
export function checkOutputValue(value: unknown, output: OutputPolicy): OutputRefusal | null;
/** A raw query string (no `?`): its names and values decoded and checked. */
export function checkOutputQuery(query: string, output: OutputPolicy): OutputRefusal | null;
/** A request body as text, read by its Content-Type: a form decoded, JSON by `parseJson` (strict), else one text. */
export function checkOutputBody(text: string, contentType: string | undefined, output: OutputPolicy, parseJson: (text: string) => unknown): OutputRefusal | null;

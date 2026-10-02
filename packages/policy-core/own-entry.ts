/**
 * Look a key up in a fixed table by OWN property only. Mandate operators, atom predicates and the like arrive in
 * documents, and indexing a plain object with them reaches Object.prototype: `constructor`, `toString` or `valueOf`
 * resolve to built-in functions that return something truthy, so an operator named `constructor` "satisfied" any
 * constraint — failing OPEN where an unknown operator must fail closed. Found by the mandate-eval fuzz test
 * (2026-10-02). Every lookup keyed by document content goes through here.
 */
export function ownEntry<T>(table: Readonly<Record<string, T>>, key: unknown): T | undefined {
  return typeof key === 'string' && Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

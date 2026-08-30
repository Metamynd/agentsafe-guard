import { defineConfig } from 'vitest/config';

// `test:core` only ever meant to run the real vitest specs under packages/policy-core —
// vitest's own default include glob (**/*.test.*) also picked up magp-hcs2.test.mjs and
// magp-evidence.test.mjs, two standalone zero-framework scripts (they call process.exit()
// directly) that vitest cannot host as a spec file. Scoping include to what test:core was
// actually meant to run fixes that without touching how those two packages test themselves
// (see their own package.json `test` scripts, run via plain `node`).
export default defineConfig({
  test: {
    include: ['packages/policy-core/**/*.test.ts'],
  },
});

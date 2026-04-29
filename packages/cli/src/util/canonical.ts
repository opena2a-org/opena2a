/**
 * Canonical ecosystem constants used in user-facing copy.
 *
 * IMPORTANT: every value here mirrors `data/canonical-numbers.json` in
 * the `opena2a-website` repo, which is the cross-repo source of truth.
 * When a number changes there, update it here and bump
 * `CANONICAL_NUMBERS_REVISION` so the regression test in
 * `__tests__/util/canonical.test.ts` flags any source files that still
 * embed an outdated literal.
 *
 * Adding a new canonical number?
 * 1. Add the constant here with a JSDoc citing its `_source` path.
 * 2. Replace every literal in `src/` and the test will block re-introductions.
 */

/**
 * HackMyAgent check count. Mirrors `hmaChecks.value` in
 * `opena2a-website/data/canonical-numbers.json`. Bumped on each HMA
 * release that adds checks.
 */
export const HMA_CHECK_COUNT = 209;

/** Bump when any constant in this file changes. */
export const CANONICAL_NUMBERS_REVISION = 1;

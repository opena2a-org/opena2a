// Flat config for the `sast` job in .github/workflows/security.yml.
//
// Deliberately narrow: this is not a style linter. It carries only rules that
// catch a dynamic-evaluation primitive reaching the tree, which is the one
// thing an automated check can assert about a contribution without a human.
// Style and correctness linting is `npm run lint` (turbo, per package).
//
// Scope covers __tests__ as well as src. Test code executes under `npm test`
// on CI runners and on maintainer machines, so excluding it from the only
// dynamic-evaluation check would leave the larger of the two surfaces unread.
//
// The parser is @typescript-eslint/parser because espree cannot parse type
// annotations; without it eslint exits non-zero on the first `: string` and
// the job reports a parse failure rather than a rule result.

import tsParser from '@typescript-eslint/parser';

export default [
  {
    files: ['packages/*/src/**/*.ts', 'packages/*/__tests__/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2023,
      sourceType: 'module',
      // Required for no-implied-eval to fire at all. The rule only reports
      // when its callee resolves to a GLOBAL variable; with no globals
      // declared, `setTimeout` is an unresolved reference, the resolution
      // check fails, and the rule silently never fires. Verified: with this
      // block absent, `setTimeout("danger()", 1)` lints clean.
      //
      // An enabled rule that cannot fire is the same defect as the `|| true`
      // this config replaces — a green check that measured nothing. Keep the
      // calibration probes in the workflow so the next person finds out
      // immediately rather than at review time.
      globals: {
        setTimeout: 'readonly',
        setInterval: 'readonly',
        setImmediate: 'readonly',
        execScript: 'readonly',
        window: 'readonly',
        globalThis: 'readonly',
      },
    },
    // noInlineConfig is a security property, not a style choice. Without it a
    // contributor can neutralise the only automated dynamic-evaluation check
    // in the repo with `// eslint-disable-next-line no-eval` in the same diff
    // that introduces the eval — and the job still reports green. Inline
    // comments cannot switch these rules off.
    //
    // It also makes the job independent of disable directives written for the
    // per-package `npm run lint` configs, which enable rules this config does
    // not. Honouring those directives makes eslint fail on an unknown rule
    // name, which fails the job for a reason that has nothing to do with the
    // code being checked.
    linterOptions: {
      noInlineConfig: true,
      reportUnusedDisableDirectives: 'off',
    },
    rules: {
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
    },
  },

  // The one exception in the tree, stated here rather than as an inline
  // comment, so that it appears in a diff and has to be re-approved if the
  // file's use of it changes.
  //
  // review.test.ts renders the HTML report and then executes the script the
  // report embeds, in order to assert that the nav handler it registers
  // actually works. There is no way to test emitted script behaviour without
  // evaluating it. The evaluated string is the report our own code just
  // generated, not input, and it runs against a stub document inside the test.
  //
  // Scoped to no-new-func only: no-eval and no-implied-eval stay ERROR in this
  // file. Verified maintainer-authored (`git blame -w -L 105,106 d3fc6de --
  // packages/cli/__tests__/commands/review.test.ts` -> 454bd9a8), not part of
  // the externally contributed surface.
  //
  // Reopen if: this file evaluates anything that is not output of our own
  // report generator, or a second file needs the same exemption — two sites
  // means the pattern needs a test helper, not a second waiver.
  {
    files: ['packages/cli/__tests__/commands/review.test.ts'],
    rules: {
      'no-new-func': 'off',
    },
  },
];

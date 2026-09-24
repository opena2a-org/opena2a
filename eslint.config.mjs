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
];

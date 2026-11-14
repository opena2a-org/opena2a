# Changelog

All notable changes to `@opena2a/shared` will be documented in this file.

## 0.1.3 — 2026-11-14

- `zod` moves to `^4.6.6`, where 0.1.2 declared `^3.24.0`. zod 4.6.6 is the
  first version outside GHSA-mrhx-c7xc-m3w5 (high, zod `< 4.6.6`), so a project
  that installs `@opena2a/shared` no longer carries that advisory through it.
- `loadProjectConfig(dir)` parses `.opena2a.yaml` and `.opena2a.yml` as YAML,
  with js-yaml's core schema (strings, numbers, booleans, nulls, lists and
  mappings only; a tag that would build anything else fails the parse). 0.1.2
  passed both files to `JSON.parse`, so a YAML config that was not also valid
  JSON returned `null`. `opena2a.config.json` is a fourth file name, tried
  after `.opena2a.yaml`, `.opena2a.yml` and `.opena2a.json`; `findProjectRoot()`
  treats it as a root marker too. `js-yaml` (`^4.1.0`) is a new dependency.
- `getUserConfigDir()` returns `$OPENA2A_HOME`, resolved, when that variable is
  set to a non-blank value, and `~/.opena2a` otherwise. 0.1.2 built `~/.opena2a`
  from the home directory and did not read the variable.
- `getProjectStoreKey(project)` and `getProjectStoreDir(project)` are new
  exports: the per-project user store `<user home>/projects/<key>`, where the
  key is the first 16 hex characters of the SHA-256 of the project's
  `realpathSync.native` path, so every spelling of one directory yields one
  key; a path that is not on disk is keyed on its absolute form.
  `getProjectStoreKey('/srv/example-project')` is `2550ea6e13e5f88a`.
  `getProjectStoreDir` resolves the path and does not create it.
- The package ships its `LICENSE` (Apache-2.0), and the four compiled test
  files (`dist/user-config.test.*`) that 0.1.2 shipped are no longer in the
  tarball.
- The README and the `isContributeEnabled()` docblock describe contributed
  scan summaries without calling them anonymous.

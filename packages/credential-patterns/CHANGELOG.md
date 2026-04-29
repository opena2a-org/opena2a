# Changelog

All notable changes to `@opena2a/credential-patterns` will be documented in this file.

## 0.1.0 — 2026-04-29

Initial release. Pure relocation of the credential pattern catalog from `secretless-ai` (`src/patterns.ts` and `findRealMatch` / `isKnownExample` from `src/scan.ts`). No regex changes, no semantic changes — every input that matched in `secretless-ai 0.16.2` continues to match here.

### Exports

- `CREDENTIAL_PATTERNS` — 56 patterns across ai-ml, cloud, communication, developer, payment, database, auth, and monitoring categories.
- `CREDENTIAL_PREFIX_QUICK_CHECK` — auto-generated prefilter regex.
- `KNOWN_EXAMPLE_KEYS`, `PLACEHOLDER_INDICATORS` — allowlist data.
- `SECRET_FILE_PATTERNS`, `CONFIG_FILES`, `SOURCE_FILE_EXTENSIONS`, `SOURCE_SKIP_DIRS` — file-system scan rules.
- `findRealMatch`, `isKnownExample` — match-with-allowlist helpers.
- `CredentialPattern` — pattern interface type.

### Provenance

`0.1.0` is a manual one-shot bootstrap publish (`npm publish --access public`). From `0.1.1` onward the package publishes via npm Trusted Publishing through `.github/workflows/release.yml`, which attaches SLSA v1 attestations.

### Consumers (planned)

- `secretless-ai 0.17.0` (PR 2) — replaces local `src/patterns.ts` with this package.
- `hackmyagent` (PR 3) — replaces `src/plugins/credvault.ts`'s parallel pattern copy and switches `src/plugins/secretless.ts` from runtime `import('secretless-ai')` to a compile-time dep on this package.

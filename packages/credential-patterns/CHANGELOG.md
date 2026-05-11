# Changelog

All notable changes to `@opena2a/credential-patterns` will be documented in this file.

## 0.1.1 — 2026-04-30

False-positive suppression release driven by `secretless-ai status` dogfooding inside the `hackmyagent` repo (4/4 reported findings were tutorial fixtures, JSDoc comments, or block-comment context that the 0.1.0 allowlist branches did not cover).

### Allowlist additions in `isKnownExample`

- **Block-comment marker recognition.** The comment-marker example branch now also fires on `/*`, `<!--`, `-->`, `'''`, `"""`, and JSDoc-continuation lines (regex `^\s*\*`). The original `//` and `#` markers continue to fire. The `example`-token gate is preserved — a comment without an explicit `example` keyword still flags real credentials.
- **Localhost + demo-password DB connection strings.** `<protocol>://user:password@host` URLs whose host is `localhost` or `127.0.0.1` AND whose password is one of `{password, password123, secret, admin, root, demo, test, changeme}` are now treated as known examples. Anchored host check defeats `localhost.evil.com` bypass attempts; production hostnames with weak passwords still fire (the finding is preserved, not silenced).
- **Bare `'fake'` placeholder.** `PLACEHOLDER_INDICATORS` now contains a bare `'fake'` substring (replacing the previous `'fake_'` and `'fake-'`). Catches `sk-proj-fake1234567890abcdefghij` style values where no underscore or dash followed `fake`.

### Code hygiene (issue #127)

- `isKnownExample` comment-marker branch reduced — the inner re-check of `lineLC.includes('example')` was redundant under the outer `&&` and unreachable for `placeholder` / `fake`. Replaced with a single `isExampleInComment` helper.
- ReDoS test expanded from one shape to ten (empty, single char, 1k/10k repeated `a`, 10k `/`, 10k after each common prefix `sk-`/`AKIA`/`ghp_`, 10k newlines, mixed long). Every pattern stays under 50ms on every input.
- Multi-real per-category test added (`findRealMatch`) — one fixture per pattern category (ai-ml / cloud / communication / developer / payment / database / auth / monitoring) asserts the `/g` promotion iterates past an allowlisted match to find a real one. A future regex edit that breaks `/g` is caught with a precise per-category diagnostic.

### Phase 4.5 adversarial review fixes (caught pre-merge)

- **Demo-password match is case-insensitive.** `Password123` (capitalized) in a tutorial fixture now allowlists; the case-sensitive Set lookup that shipped in the first draft would have missed it.
- **IPv6 loopback `[::1]` allowlists alongside `localhost` and `127.0.0.1`.** Tutorial fixtures using IPv6 loopback are no longer flagged as real credentials. `[::2]` and other non-loopback IPv6 addresses still fire.

### Test count

165 → 227 (+62).

### Known limitation (carried over from 0.1.0)

The comment-marker example branch fires on substring presence anywhere on the line, not on actual comment context. A real credential whose value or surrounding text contains `//`, `/*`, `<!--`, `-->`, `'''`, `"""`, or a JSDoc-continuation glyph AND the word `example` somewhere on the same line will be allowlisted. This was already true in 0.1.0 (via `://` matching `//` plus `example` in hostnames). 0.1.1 expanded the marker set; the substring-match model is unchanged. A future release will replace the substring check with structural comment-context detection.

### Deferred

- The `~6 verified-against-official-docs allowlist additions` from issue #127 are deferred. Each candidate requires verification against AWS / OpenAI / GitHub doc pages and a per-pattern test; that scope did not fit this release window. Tracking continues in #127.

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

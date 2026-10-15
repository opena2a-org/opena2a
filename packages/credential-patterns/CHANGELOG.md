# Changelog

All notable changes to `@opena2a/credential-patterns` will be documented in this file.

## Unreleased

### Patterns match the token formats vendors issue today (opena2a-org/secretless-ai#135)

Four patterns had a fixed length or shape that tokens issued today do not
have, so a file holding a live token was read and reported clean. Each pattern
below matches more than before. Nothing that matched before stops matching,
and no pattern was removed. `CREDENTIAL_PATTERNS` grows from 57 to 59 entries.

- **`azure` matches the 88-character Storage account key.** Azure Storage
  account keys are 512-bit; base64 of 64 bytes is 88 characters ending in
  `==`. The pattern expected `=` at character 44, so a real Storage key never
  matched. The 44-character shape (Service Bus and Event Hubs
  `SharedAccessKey`) still matches. Both still need the `AccountKey` /
  `SharedAccessKey` / `azure_*` key name in front, so an
  `"integrity": "sha512-…=="` value of the same shape stays clean.
- **`slack` matches user tokens (`xoxp-`) and secrets longer than 24
  characters.** A third numeric group is accepted, and the secret has a
  24-character floor and no maximum, so the match covers the whole token.
- **New `github-user-to-server` pattern for `ghu_` GitHub App user access
  tokens**, which nothing matched before.
- **`github-pat`, `github-oauth`, `github-app` and `github-user-to-server`
  take bodies of 36 characters or more.** GitHub says tokens will likely grow
  and to plan for up to 255 characters; a body pinned at 36 left a longer
  token's tail outside the match. `github-refresh` already had no maximum.
- **New `square-access-token` pattern for Square `EAAA` access tokens**
  (64 characters, the length of Square's documented example). `EAAA` is also
  four ordinary base64 characters, so the token must stand alone: no base64 or
  base64url character, `=` included, directly before or after it. Image data
  in a `data:` URI and `sha512-` integrity strings stay clean. A token written
  directly after `=` (`SQUARE_ACCESS_TOKEN=EAAA…`, unquoted) is not matched;
  quoted, after `:` or a space, or after `Bearer ` it is.
- `CREDENTIAL_PREFIX_QUICK_CHECK` now includes `ghu_` and `EAAA`.
- Each pattern's comment cites the vendor page its format comes from.
- Unchanged: `newrelic` (no vendor-documented body length), `telegram-bot`
  (its 35-character segment is correct) and `github-refresh`.
- **`isKnownExample(line, match, pattern?)` takes the pattern as an optional
  third argument, and `findRealMatch` passes it.** A body written as a floor
  takes a placeholder word that directly follows the token into the match
  (`xoxb-…-<24 characters>sample` is one `slack` match; with the pinned
  length it was the token, and the word stayed outside), and the
  whole-value placeholder test then dropped the token. With the pattern given,
  a placeholder word that follows a value which is a complete match on its own
  no longer marks that value as a placeholder; the part in front of the word
  still has to pass the other allowlist rules (known example, low entropy,
  comment marker). A placeholder word inside a token's fixed-length part, or
  at its start, suppresses the match as before. Without the third argument the
  result is unchanged.

Tests sweep every changed pattern at its minimum length, one over, and well
over, check that the match reaches the end of the value, and check that a
base64 blob holding the prefix, the pattern's own source, a `${VAR}` reference
and a placeholder-marked value produce no finding. The source-literal guard
covers the `ghu_`, `EAAA` and three-group `xoxp-` shapes.

## 0.1.3 — 2026-07-22

### `CONFIG_FILES`

- **Added `.mcp.json`** — the Claude Code project-scope MCP config. It sits at the
  project root and is committed to repos, making it a high-risk home for plaintext
  `env` credentials, yet no consumer scanned it (found by the secretless-ai 0.20.0
  release test: a planted Anthropic key in `.mcp.json` survived `scan`, `mcp-status`,
  `status`, and a PASS from `verify`).
- **Fixed the `.curse/mcp.json` typo to `.cursor/mcp.json`** — Cursor's project MCP
  config was unreachable since the entry was introduced; `.curse/` matches nothing.
- **Added `.mcp/config.json`, `.claude/settings.local.json`, and
  `.windsurf/mcp.json`** — MCP/agent config locations the org's tools already
  enumerate elsewhere (opena2a-cli `ai-config`/`detect`, secretless MCP discovery)
  but the shared scan list lacked.

### Database connection-string precision

- **`mongodb`, `postgres`, `mysql`, and `redis` now flag only URIs that embed a
  secret.** Previously any URI ≥ 10 chars matched, so the canonical
  credential-free MCP server layout (`"args":
  ["postgresql://localhost:5432/mydb"]`) produced a CRITICAL "PostgreSQL
  Connection String" finding with nothing secret in it. A URI now matches when
  it carries a userinfo password (`user:pass@`, `:pass@`), a
  `password=`/`pwd=`/`sslpassword=` query param (case-insensitive), or — redis
  only — any single userinfo token (`redis://your-password@host`): pre-ACL Redis has
  no usernames, so a lone token there is a password, not topology. For
  `postgres`/`mysql`/`mongodb`, username-only URIs (`postgres://user@host`) are
  a deliberate non-match: no password, no secret.
- **Plain `mongodb://` URIs are now covered** — the old pattern only matched
  `mongodb+srv://`, so `mongodb://root:pass@host/admin` was never detected.
- **Matches cannot cross JSON string boundaries** — the character classes
  exclude quotes and commas, so minified content like
  `{"cache":"redis://localhost:6379","owner":"ops@corp.io"}` neither
  false-positives nor gets destructively over-masked by `replace()`-based
  redaction consumers.
- **Env-var-interpolated passwords are not secrets** — the user/password
  classes exclude `$ { } | ;`, so `postgres://app:${POSTGRES_PASSWORD}@db`
  (the recommended secure shape), `$VAR` forms, markdown-table cells, and
  compound `;`-joined env lines no longer read as literal credentials. Hosts
  deliberately keep `$ { }`: a real password next to an interpolated host
  (`redis://:realpass@${REDIS_HOST}:6379`) still flags. The redis single-token
  rule carves out the literal `default@` (the standard Redis 6+ ACL username);
  other username-only redis URIs still flag on the safe side, since a lone
  userinfo token is indistinguishable from a pre-ACL password.
- **`CREDENTIAL_PREFIX_QUICK_CHECK` derives `redis` from `rediss?`, not
  `rediss`** — the prefix extractor kept the char an optional quantifier
  applies to, so consumers' `${VAR}`-line skip dropped plain `redis://` lines
  before the pattern ever ran: `redis://:realpass@${REDIS_HOST}:6379` was a
  silent miss. The extractor now trims a trailing `X?` char, with a regression
  test pinning `redis://` recognition.
- **Every run is length-bounded** (user ≤ 64, password ≤ 256, host/query ≤ 512
  chars), keeping scan time linear on scheme-stuffed one-line files
  (adversarially measured: 220 KB of repeated `postgres://` dropped from
  multi-second quadratic scans to ~30 ms); the ReDoS perf suite gains
  scheme-literal-prefixed inputs, which the previous inputs never exercised.
  Known edges, accepted: a password containing a raw unencoded `&`, `,`,
  quote, `$`, `{`, `}`, `|`, or `;` is missed or masked only partially
  (percent-encoded forms are caught), format-string templates
  (`postgres://%s:%s@%s`) still match, and secrets placed beyond ~512 chars
  into a single URI's query string are not matched.

## 0.1.2 — 2026-06-08

Name-gated AWS secret-access-key detection (ports hackmyagent's scanner rule to the shared catalog).

### New pattern

- **`aws-secret` (AWS Secret Access Key).** AWS secret keys are 40-char `[A-Za-z0-9/+]` values with no distinctive prefix, so a value-only regex would flood on every base64 blob/hash. This pattern is **name-gated**: it matches the 40-char value only when `aws … secret|private … key` or the AWS-specific full phrase `secret[_ ]access[_ ]key` precedes it (the latter catches JS-SDK `secretAccessKey` and Terraform `secret_access_key` with no nearby `aws`). The value is captured in group 1; `match[0]` includes the name token, so `.replace`-based maskers over-mask the name (fail-safe). A forward capture group is used rather than a lookbehind because a variable-width lookbehind exceeded the package's 50 ms ReDoS perf budget.

### `isKnownExample`

- **Value-aware.** Now reads the captured value (`match[1] ?? match[0]`) so the example/placeholder checks apply to the secret value of a name-gated match, not the `name = value` whole. Value-only patterns (no group 1) are unchanged.
- **Low-entropy floor.** A name-gated value of ≥20 chars with ≤6 distinct characters (e.g. `0000…`, `DEADBEEF…`) is treated as a placeholder. A real ≥20-char secret never has so few distinct characters, so genuine keys are unaffected. The `wJalr…EXAMPLEKEY` docs secret remains covered by `KNOWN_EXAMPLE_KEYS`, and `xxx`/`example`/… by `PLACEHOLDER_INDICATORS`.

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

### Adversarial review fixes (caught pre-merge)

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

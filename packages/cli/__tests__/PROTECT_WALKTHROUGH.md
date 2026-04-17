# `opena2a protect` real-world walkthrough — testing playbook

Run this playbook before every `opena2a-cli` publish that touches the `protect`
command, the credential-pattern library, or the MCP/source scanners.

The playbook exists because automated tests pass while real-world usage on
common fixtures still surfaces functional gaps that no synthetic test will
catch. Each scenario below is paired with the exact command, the expected
behavior, and what to grade in the output.

## Setup

Fixtures live at `/tmp/hma-real-world/` (one directory per scenario). They are
intentionally vulnerable. **Never run protect against the canonical fixtures
directly — copy first, otherwise protect will rewrite the source-of-truth and
the next session inherits a polluted fixture.**

```bash
rm -rf /tmp/walk-X && cp -r /tmp/hma-real-world/<fixture> /tmp/walk-X
node packages/cli/dist/index.js protect /tmp/walk-X --ci --skip-verify --skip-sign --skip-liveness
```

`--skip-verify --skip-sign --skip-liveness` removes friction for repeatable
runs; drop them when you are testing those specific features.

## Scenarios and what to grade

### S1 — `ibm-mcp` (vendor-prefixed key in JSON env value)

Original `mcp.json` contains
`"WATSONX_API_KEY": "ibm-api-FAKE-key-for-testing-1234567890"`.

Grade:
- Detection MUST fire. The key is `vendor-prefix` style (`ibm-api-...`) and the
  surrounding JSON key is `WATSONX_API_KEY`. CRED-004 should match the source
  line because the key name contains `API_KEY`. If protect prints
  "No hardcoded credentials detected", the JSON-quoted-key form of CRED-004 is
  broken — see Finding #1 in `briefs/protect-walkthrough-findings.md`.
- Replacement MUST yield a working JSON `${WATSONX_API_KEY}` placeholder, not
  bare `process.env.X`.
- Env var name SHOULD be vendor-specific (`WATSONX_API_KEY`), not generic
  `API_KEY`. Generic names confuse the user about which secret to set.

### S2 — `composio-skill` (Python `client.X(api_key="...")` in markdown code block)

Original `SKILL.md` contains `api_key="comp_fake_key_testing_only_..."` inside
a Python snippet inside a markdown file.

Grade:
- Detection MUST fire (CRED-004).
- Replacement is the trap: `.md` falls through the language switch and emits
  `${API_KEY}` — a literal Python string at runtime, NOT env interpolation.
  Either: (a) detect Python code blocks inside markdown and use `os.environ`,
  or (b) refuse to autopatch markdown and emit a manual-fix instruction.
  Silent broken-Python output is the worst of both worlds.
- Env var name (currently `API_KEY`) should be `COMPOSIO_API_KEY` based on
  call-site context.

### S3 — `mega-mcp` (already-secured project, env vars used)

`mcp.json` references `${SLACK_TOKEN}` etc. — no hardcoded values.

Grade:
- Detection MUST report zero credentials.
- The output MUST tell the user what protect actually did: it created
  `.gitignore`, `.env.example`, `CLAUDE.md` (secretless section),
  `.opena2a/guard/signatures.json`, `.opena2a/backup/`. The two-line
  "No hardcoded credentials detected. protect also applies git hygiene…" is
  too thin and looks like a no-op. List the artifacts created, the score, and
  next-step commands. No dead ends.
- A stale `.opena2a/protect-rollback.json` from a prior run MUST be cleaned up
  or re-written with empty `credentials`. Leaving the old manifest is a trust
  bug — the user reads it and thinks creds are still in vault when they are
  not.

### S4 — `ssh-mcp` (path that looks credential-shaped, false-positive check)

`mcp.json` env contains `"SSH_KEY_PATH": "/home/user/.ssh/id_rsa"`.

Grade:
- MUST report zero credentials (a path is not the key itself). If a future
  pattern flags filesystem paths as credentials, that is a regression.

### S5 — JSON output is valid and includes all manifest fields

```bash
node dist/index.js protect /tmp/walk-X --ci --format=json --skip-verify --skip-sign --skip-liveness | jq .
```

Grade:
- Output parses as JSON.
- Top-level keys must include: `totalFound`, `migrated`, `failed`, `skipped`,
  `results`, `verificationPassed`, `durationMs`, `targetDir`, `scoreBefore`,
  `scoreAfter`, `additionalFixes`, `aiToolsUpdated`, `rollbackManifestPath`,
  `vaultStoredEnvVars`. Missing fields break downstream consumers.
- `rollbackManifestPath` and `vaultStoredEnvVars` only appear when migration
  actually moved at least one credential. If they appear with empty arrays on
  a no-credentials run, that is bug #6 surfacing in JSON form.

### S6 — Error paths

```bash
node dist/index.js protect /nonexistent       # expect exit 1, clean message
node dist/index.js protect /tmp                # expect "not a project root" message + exit
```

Grade:
- No raw stack traces. No ENOENT spilled to stderr.
- Non-zero exit codes for failure.
- Helpful next step (e.g. "run `opena2a init` to set up a project here").

### S7 — Rollback works for never-committed files

```bash
mkdir -p /tmp/walk7 && echo '{"name":"t"}' > /tmp/walk7/package.json
echo 'const k = "AIza...35char...";' > /tmp/walk7/app.ts
cp /tmp/walk7/app.ts /tmp/walk7/.original-snapshot
node dist/index.js protect /tmp/walk7 --ci --skip-verify --skip-sign --skip-liveness
cmp /tmp/walk7/.opena2a/backup/app.ts /tmp/walk7/.original-snapshot
```

Grade:
- The backup at `.opena2a/backup/app.ts` MUST be byte-equal to the pre-protect
  snapshot. If `cmp` exits non-zero, rollback is broken.
- The printed rollback section MUST list both `cp` (file restore) AND
  `secretless-ai secret rm` (vault cleanup) commands. A rollback that only
  cleans source while leaving the secret in vault is incomplete.

### S8 — Idempotency: re-running protect on a clean source

After S7, run protect again on the same directory.

Grade:
- Reports zero credentials.
- Does NOT leave a stale `protect-rollback.json` from the prior run (bug #6 in
  the findings brief).

### S9 — Masked secret preview

When a credential is found, the dry-run output should show a masked preview
(`AIzaB****` style — first 5 + `****`) so the user can visually verify the
match against what they expect. Currently absent.

### S10 — Multiple same-type credentials

Two AIza keys in one file should produce `GOOGLE_API_KEY` and
`GOOGLE_API_KEY_2`, both replaced correctly. This works today; document so it
stays working.

## What to do with findings

Each scenario above maps to an entry in
`briefs/protect-walkthrough-findings.md` (created 2026-04-17). When you run
this playbook and a scenario degrades, add a regression test in
`__tests__/commands/protect.test.ts` (or a sibling file) before the fix lands.
The playbook is the human eye; the regression suite is the long-term memory.

## Why the playbook exists

Prior to 2026-04-17, the protect command shipped 12 fixed bugs but the
real-world walkthrough on `/tmp/hma-real-world/ibm-mcp` immediately surfaced
two more shippers (CRED-004 misses JSON-quoted keys; stale rollback manifest
not cleaned). All 12 prior bugs had unit-test coverage; none of the unit tests
modeled the actual fixtures users hit. That is the gap this playbook closes.

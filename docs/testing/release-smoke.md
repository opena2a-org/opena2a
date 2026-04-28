# opena2a-cli release smoke test

**Run before every tag push to `v*`. ~25 minutes by hand.**

Every item came from a real bug or user-visible regression. Don't skip without
writing down why.

Run every command from a clean clone. Use `node packages/cli/dist/index.js`
not the global install. Capture exact output for the `USER_VISIBLE_IMPACT:`
marker.

---

## 0. Build + tests (3 min)

```bash
cd opena2a
git status                          # clean, or only the branch you intend to ship
npm ci                              # lockfile valid (workspace root)
npm run build --workspace=packages/cli
npm test --workspace=packages/cli   # all green
```

Fail the release if any step is red.

---

## 1. Help and version (1 min)

```bash
CLI=node\ packages/cli/dist/index.js   # alias

$CLI --version      # prints: 0.x.x
$CLI -v             # same
$CLI --help         # full command list; no stack traces
```

The `--help` output must list at minimum: `scan`, `check`, `protect`, `detect`,
`review`, `init`, `shield`, `guard`, `mcp`, `skill`, `trust`, `scan-soul`,
`harden-soul`, `benchmark`, `verify`. If a top-level command vanishes from
help, the router registration dropped it.

---

## 2. Scan and check commands (5 min)

These are the commands most likely to break on a cli-ui or check-core bump.

```bash
CLI=node\ packages/cli/dist/index.js

# check — delegates to HMA; rich-block renders via @opena2a/cli-ui
$CLI check express                           # npm package, Tier 3 graceful degrade
$CLI check pip:requests                      # PyPI package
$CLI check skill:opena2a/code-review-skill   # skill — rich-block render
$CLI check mcp:@modelcontextprotocol/server-filesystem  # MCP — rich-block render
$CLI check nonexistent-xyz-999 --json        # not-found, JSON shape, exit 2
$CLI check express --json                    # JSON output on stdout

# scan — wraps HMA secure
$CLI scan packages/cli/               # scan the CLI package itself
$CLI scan packages/cli/ --json | head -5
```

For `check skill:` and `check mcp:`: verify the rich-context block renders with
all sections present — header with trust tier + score, `── Hardcoded secrets ──`,
`── What is this skill? ──` (or MCP equivalent), `── What we observed ──`,
`── Why ... ──`, `── Next ──`. If any section is missing, the rich-block render
path broke.

For `check express` (npm Tier 3): verify the graceful-degrade footer renders:
`Rich-context view available for skills and MCPs in v1`.

---

## 3. Core user-facing commands (6 min)

```bash
CLI=node\ packages/cli/dist/index.js

# Detect — shadow AI audit
$CLI detect .                          # current directory
$CLI detect . --json | head -10        # JSON shape

# Protect — credential migration
$CLI protect --help                    # verify subcommands listed
# Do NOT run protect against a live directory unless testing protect specifically.
# See packages/cli/__tests__/PROTECT_WALKTHROUGH.md for the protect scenario matrix.

# Review — unified HTML dashboard
$CLI review --help

# Governance
$CLI scan-soul .                       # SOUL.md scan (expect missing-file message)
$CLI harden-soul --help

# Identity and trust
$CLI mcp audit --help                  # mcp-audit: MCP server identity management
$CLI trust --help

# Security setup
$CLI init --help
$CLI shield --help
$CLI guard --help

# Skill management
$CLI skill --help
$CLI harden-skill --help

# Benchmark
$CLI benchmark --help

# Verification
$CLI verify --help
```

For each command: output produced, no hang, no stack trace. The `--help` flag
must be honored on every subcommand.

---

## 4. install / path commands (2 min)

```bash
CLI=node\ packages/cli/dist/index.js

# install — skill or MCP installation
$CLI install --help     # lists install options

# path — installed skill/MCP path lookup
# (only testable if a skill is installed; --help verification is sufficient here)
```

---

## 5. protect walkthrough (when protect is in the diff) (8 min)

When the diff modifies `packages/cli/src/commands/protect.ts`,
`packages/cli/src/util/credential-patterns.ts`, or
`packages/cli/src/util/ai-config.ts`, run the full protect scenario matrix
documented at `packages/cli/__tests__/PROTECT_WALKTHROUGH.md`.

The matrix covers 10 scenarios (S1–S10) graded on:
- Detection accuracy (is the right credential found?)
- Replacement correctness (is the env-var name sensible?)
- Masked preview (is the live value hidden in output?)
- Rollback completeness (does rollback fully restore the original?)
- No dead ends (every finding has a next-step command)

Fail the release if any scenario produces a CRITICAL or HIGH finding in the
walkthrough grading rubric that is not already in the known-issues list.

---

## 6. `--ci` and `--json` exit-code matrix (1 min)

After any release touching exit codes, the router, or JSON output:

```bash
CLI=node\ packages/cli/dist/index.js

# scan of vulnerable target → exit 1
$CLI scan packages/cli/ --json; echo "exit: $?"
# Expected: JSON object on stdout, exit varies by findings

# check not-found → exit 2
$CLI check nonexistent-xyz-999 --json; echo "exit: $?"
# Expected: JSON with found:false or error shape, exit 2

# --ci flag accepted without error
$CLI check express --ci --json; echo "exit: $?"
```

---

## 7. Rich-block parity gate (after cli-ui bump)

After any `@opena2a/cli-ui` version bump, run the parity harness to confirm the
rich-block output is byte-identical to the locked golden fixtures across HMA,
ai-trust, and opena2a-cli:

```bash
cd ../opena2a-parity
HMA_BIN="OPENA2A_TELEMETRY=off node ${HOME}/workspace/opena2a-org/hackmyagent/dist/cli.js" \
AI_TRUST_BIN="OPENA2A_TELEMETRY=off node ${HOME}/workspace/opena2a-org/ai-trust/dist/index.js" \
OPENA2A_BIN="OPENA2A_TELEMETRY=off node ${HOME}/workspace/opena2a-org/opena2a/packages/cli/dist/index.js" \
node --experimental-strip-types src/run-parity.ts
# Expected: 5 fixture(s) run, 0 fixture failure(s)
```

Fail the release if any parity fixture fails. The parity harness is the
source of truth for byte-identical rendering across CLIs.

---

## 8. Telemetry (1 min)

**Do NOT point at the production endpoint while smoking.**

```bash
export OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never
unset OPENA2A_TELEMETRY

# Version disclosure present
node packages/cli/dist/index.js --version
# Expected: version line + Telemetry disclosure

# Opt-out
node packages/cli/dist/index.js telemetry off
node packages/cli/dist/index.js telemetry on

# Command completes when telemetry endpoint unreachable (≤ 2 s tolerance)
time node packages/cli/dist/index.js check express --json 2>/dev/null
# Expected: real time < 10 s total (telemetry timeout must not dominate)

unset OPENA2A_TELEMETRY_URL
```

---

## 9. Cleanup

```bash
# Restore telemetry config if overwritten:
# rm ~/.config/opena2a/telemetry.json
```

---

## When this checklist isn't enough

- If the diff touches the `check` command or the spawn delegation path to HMA:
  run the cross-CLI parity gate (§7) even if cli-ui didn't bump — the spawn
  can introduce double-render or banner injection.
- If the diff touches `protect`: run the full protect walkthrough (§5). The
  walkthrough found two ship-blockers that 906 unit tests missed.
- If the diff touches the router (`packages/cli/src/router.ts`): run every
  command in §3 with the `--ci` flag and verify exit codes are stable.
- If a regression ships that would have been caught by an item NOT on this list:
  add the item here as part of the fix.

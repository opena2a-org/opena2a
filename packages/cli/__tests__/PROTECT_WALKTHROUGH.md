# protect — manual walkthrough playbook

> The CLAUDE.md trigger ("Release testing — protect command") points here.
> Run every scenario below before any publish that modifies
> `packages/cli/src/commands/protect.ts`,
> `packages/cli/src/util/credential-patterns.ts`, or
> `packages/cli/src/util/ai-config.ts`.

Unit tests certify code shape. This playbook certifies user outcomes — the
masked preview, env-var naming, replacement correctness, and rollback
completeness. Both layers are required.

## Setup

```bash
cd ~/workspace/opena2a-org/opena2a/packages/cli
npm run build
```

All scenarios use `mktemp -d` so they don't depend on
workspace-local fixture paths. Each scenario is self-contained — copy the
heredoc, run, observe.

## Grading rubric (5 axes per scenario)

For every finding produced by `opena2a protect`:

1. **Detection accuracy** — Does it find the credential? Does it find only the credential (no FPs)?
2. **Replacement correctness** — After protect runs, does the source still compile / parse / pass the language linter?
3. **Env-var naming** — Is the suggested env-var name reasonable (matches the credential type, no collisions for multi-key files)?
4. **Masked preview** — Does the user see enough of the credential to recognize it (`sk-ant…abcd`) without the full value being printed?
5. **Rollback completeness** — Does `--undo` (or the rollback manifest) restore the file byte-for-byte? Is the manifest cleaned up after a clean rollback?

A scenario passes only when all 5 axes are clean. Any failure → entry in
the workspace-local `briefs/protect-walkthrough-findings.md` (severity,
root cause, why it matters, fix sketch). Ship-blockers (CRITICAL/HIGH on
protect's stated purpose) MUST land in the same branch BEFORE pre-push;
add the regression test FIRST, then the fix.

## Scenarios

### S1 — Anthropic key in JS source (CRED-001, critical)

```bash
DIR=$(mktemp -d) && cat > "$DIR/app.js" <<'EOF'
const client = new Anthropic({
  apiKey: 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
});
EOF
opena2a protect "$DIR"
```

Expected: 1 finding CRED-001 critical · masked preview `sk-ant…AAAAA` · suggests `ANTHROPIC_API_KEY` · replacement uses `process.env.ANTHROPIC_API_KEY` · `.env.example` updated · rollback manifest written.

### S2 — Multi-key file with collision

```bash
DIR=$(mktemp -d) && cat > "$DIR/config.js" <<'EOF'
const a = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const b = 'sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
EOF
opena2a protect "$DIR"
```

Expected: 2 findings CRED-001 critical · env-var names `ANTHROPIC_API_KEY` and `ANTHROPIC_API_KEY_2` (not two `_KEY`s). Replacement preserves order.

### S3 — JSON-quoted credential (regression for CRED-004 ship-blocker)

```bash
DIR=$(mktemp -d) && cat > "$DIR/secrets.json" <<'EOF'
{"apiKey": "abcd1234567890abcdef1234567890abcdef"}
EOF
opena2a protect "$DIR"
```

Expected: 1 finding CRED-004 medium. Earlier versions missed JSON-quoted keys — that ship-blocker is what motivated this scenario. If protect fires zero findings here, you have a regression.

### S4 — Already-protected file (no false fire)

```bash
DIR=$(mktemp -d) && cat > "$DIR/app.js" <<'EOF'
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
EOF
opena2a protect "$DIR"
```

Expected: 0 findings. The `process.env.X` skip in `quickCredentialScan` must hold.

### S5 — Placeholder value (should not fire)

```bash
DIR=$(mktemp -d) && cat > "$DIR/.env.example" <<'EOF'
ANTHROPIC_API_KEY=your-key-here
OPENAI_API_KEY=sk-replace-me
EOF
opena2a protect "$DIR"
```

Expected: 0 findings (placeholders in `.env.example` are documentation, not credentials).

### S6 — Documentation with key-shaped example

```bash
DIR=$(mktemp -d) && cat > "$DIR/README.md" <<'EOF'
Set `ANTHROPIC_API_KEY` to a value like `sk-ant-api03-...`.
EOF
opena2a protect "$DIR"
```

Expected: 0 findings (README mention without an 80+ char body).

### S7 — Skip dirs honored

```bash
DIR=$(mktemp -d) && mkdir -p "$DIR/node_modules/anthropic" && cat > "$DIR/node_modules/anthropic/index.js" <<'EOF'
const apiKey = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
EOF
opena2a protect "$DIR"
```

Expected: 0 findings (`node_modules` is in `SKIP_DIRS`).

### S8 — Rollback round-trip

```bash
DIR=$(mktemp -d) && cat > "$DIR/app.js" <<'EOF'
const client = new Anthropic({
  apiKey: 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
});
EOF
sha256sum "$DIR/app.js" > "$DIR/before.sha"
opena2a protect "$DIR"
opena2a protect "$DIR" --undo
sha256sum -c "$DIR/before.sha"
```

Expected: `OK` from sha256sum. Rollback manifest is removed after a clean undo (regression: stale manifest was a prior ship-blocker).

### S9 — AWS Access Key + Secret pair (CRED-005)

```bash
DIR=$(mktemp -d) && cat > "$DIR/aws.js" <<'EOF'
const accessKeyId = 'AKIAIOSFODNN7EXAMPLE';
const secretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
EOF
opena2a protect "$DIR"
```

Expected: 2 findings (DRIFT-002 + CRED-005). DRIFT-002 high · CRED-005 critical. Both suggest distinct env-var names.

### S10 — Empty file / empty dir (no dead end)

```bash
DIR=$(mktemp -d) && touch "$DIR/empty.js" && opena2a protect "$DIR"
```

Expected: 0 findings · clear "no credentials detected" message · Next Steps shown · exit 0. No dead end.

## Reporting

After running all 10 scenarios, summarize per the per-finding review
protocol in `opena2a/CLAUDE.md`. Findings → workspace-local
`briefs/protect-walkthrough-findings.md`. UX-only findings →
workspace-local `briefs/protect-ux-roundtwo.md`. Both files are
workspace-local (not in git) by design — `briefs/` is a thinking surface,
not a shipped artifact.

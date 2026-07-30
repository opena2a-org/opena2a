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

### S8 — Rollback round-trip (git work tree)

The migration MUST be proven to have happened before the restore is checked.
The previous version of this scenario ran `opena2a protect "$DIR"` with no
`--ci`, so protect skipped the migration entirely, and `sha256sum -c` then
reported `OK` because the file had never changed — a gate that passed because
nothing happened (#256). It also invoked `opena2a protect --undo`, which is not
a registered option (`error: unknown option '--undo'`).

```bash
DIR=$(mktemp -d) && git -C "$DIR" init -q && cat > "$DIR/app.js" <<'EOF'
const client = new Anthropic({
  apiKey: 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
});
EOF
git -C "$DIR" add app.js && git -C "$DIR" -c user.email=t@t -c user.name=t commit -qm base
sha256sum "$DIR/app.js" > "$DIR/before.sha"

opena2a protect "$DIR" --ci

# GATE 1 — protect must actually have rewritten the file. If this reports OK,
# the migration did not run and the rest of the scenario is meaningless.
sha256sum -c "$DIR/before.sha" && echo "S8 FAIL: protect changed nothing" || echo "S8 ok: file was rewritten"
grep -q 'process.env.ANTHROPIC_API_KEY' "$DIR/app.js" && echo "S8 ok: env reference written"

# GATE 2 — the offered rollback must restore the original byte-for-byte.
git -C "$DIR" checkout -- app.js
sha256sum -c "$DIR/before.sha"
```

Expected: gate 1 prints `S8 ok:` twice (file rewritten, env reference present);
gate 2 prints `OK` from sha256sum.

### S8b — Rollback guidance outside a git repo (#257)

```bash
DIR=$(mktemp -d) && cat > "$DIR/app.js" <<'EOF'
const client = new Anthropic({
  apiKey: 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
});
EOF
opena2a protect "$DIR" --ci | sed -n '/Rollback:/,/Continue hardening/p'
```

Expected: no `git checkout` line (there is no repository, so it could not run).
The block states the source edit is not reversible from disk and names
`npx secretless-ai secret get <NAME>`, which is a real subcommand of the vault
protect stores into.

### S8c — Non-interactive run must not claim success (#256)

```bash
DIR=$(mktemp -d) && cat > "$DIR/app.js" <<'EOF'
const client = new Anthropic({
  apiKey: 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
});
EOF
opena2a protect "$DIR" < /dev/null ; echo "exit=$?"
grep -c 'sk-ant-api03' "$DIR/app.js"
```

Expected: `exit=2` (not 0 — exit 0 would tell CI the credentials were migrated),
stderr names `--ci` and `--dry-run`, and the grep still reports `1` because the
refusal is a genuine no-op.

### S9 — AWS Access Key + Secret pair (CRED-005)

Two fixtures, because one cannot tell placeholder suppression from a pattern
miss. Both halves must be judged by the SAME rule (#258): before the fix,
DRIFT-002 fired on the documentation id while CRED-005 suppressed the
documentation secret, so the pair reported exactly one finding — the harmless
identifier — and a user acting on it migrated the wrong half.

**S9a — AWS's published documentation pair. Neither half is a secret.**

```bash
DIR=$(mktemp -d) && cat > "$DIR/aws.js" <<'EOF'
const accessKeyId = 'AKIAIOSFODNN7EXAMPLE';
const secretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
EOF
opena2a protect "$DIR" --dry-run
```

Expected: 0 findings. Both values are in the canonical `KNOWN_EXAMPLE_KEYS`
(source-verified against the AWS IAM User Guide). The zero-finding state must
still print an observation line, not an empty screen.

**S9b — non-example, high-entropy pair. Both halves are real exposures.**

Both values are assembled at runtime. A literal 20-char `AKIA…` id or a 40-char
secret in an `aws_secret_access_key` context is exactly what GitHub push
protection rejects, so this file must never contain one.

```bash
DIR=$(mktemp -d)
ID="AKIA""2X7QNVBTKLMZ4RCD"
SECRET="Kp7QzR2mNvT4""bXwL9sYc1JhG""sixdFa8UeZ0i""OnPr"
printf "const accessKeyId = '%s';\nconst secretAccessKey = '%s';\n" "$ID" "$SECRET" > "$DIR/aws.js"
[ ${#SECRET} -eq 40 ] || echo "S9b FAIL: secret must be exactly 40 chars, got ${#SECRET}"
opena2a protect "$DIR" --dry-run
```

The secret must be exactly 40 base64 characters — CRED-005 requires it. A
39- or 41-char fixture reports only DRIFT-002 and reads as a pattern miss,
which is why the length is asserted inline rather than trusted.

Expected: 2 findings (DRIFT-002 high + CRED-005 critical), distinct env-var
names (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`). If S9b reports fewer than
2, the pattern is genuinely broken — that is the case S9a alone could not
distinguish.

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

# New-user CLI walkthrough

> Run before every opena2a-cli publish. Every command via `node dist/index.js`,
> not the global install — we want to test the artifact we're about to ship.

```bash
cd ~/workspace/opena2a-org/opena2a/packages/cli
npm run build
```

For each command verify:

1. Output is produced (not silent).
2. Every finding has a fix command or path forward (no dead ends).
3. Exit code is correct (0 for success, 1 for critical/high findings or hard errors).
4. No credentials printed (any masked preview shows ≤8 chars of head + tail).
5. No stack traces.
6. Observations + Verdict block present (CISO Rule 11) — required from 0.10.0 onward.

## Help and version

```bash
node dist/index.js --help
node dist/index.js -v
node dist/index.js --version
```

`--version` should be a two-line disclosure (version + telemetry status, brand-model split per 0.9.0 telemetry canary). `--help` lists every registered command and the global flags.

## Composite review

```bash
node dist/index.js review .
node dist/index.js review --json . | head -30
node dist/index.js review --no-contribute .
```

Expected: HMA + Shield phases run; composite score; per-tab findings; Observations + Verdict block on the composite tab. `--no-contribute` propagates through the spawned scanners (regression for #107 / 0.9.1).

## Trust query

```bash
node dist/index.js trust express
node dist/index.js trust @opena2a/cli-ui
node dist/index.js trust some-not-yet-scanned-package
```

Expected: trust level + score + scan age. The "not scanned" branch must NOT show "NaN months ago" (pre-existing P3, deferred).

## Scan-soul / harden-soul

```bash
DIR=$(mktemp -d) && cat > "$DIR/SOUL.md" <<'EOF'
# Agent Identity
This agent helps with security review.
EOF
node dist/index.js scan-soul "$DIR"
node dist/index.js harden-soul --dry-run "$DIR"
```

Expected: governance score, domain breakdown, conformance level, missing controls by ID. Harden in dry-run shows the diff without writing.

## Protect (full playbook = `__tests__/PROTECT_WALKTHROUGH.md`)

Sanity check only — full grading rubric in the playbook:

```bash
DIR=$(mktemp -d) && cat > "$DIR/app.js" <<'EOF'
const apiKey = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
EOF
node dist/index.js protect "$DIR"
```

Expected: 1 finding CRED-001, masked preview, env-var suggestion, replacement, rollback manifest.

## Check (cross-surface)

```bash
node dist/index.js check express
node dist/index.js check getsentry/sentry-mcp
DIR=$(mktemp -d) && cp ~/.opena2a/corpus/skill/benign/tiny-clean-skill/* "$DIR/" 2>/dev/null
node dist/index.js check skill:"$DIR"
```

Expected: appropriate score per surface; `check skill:` is labeled "Quick scan" with "Run `opena2a review` for full audit" follow-up (HMA #136 precedent at 1c30957).

## Shield / Guard (Shield context for ARP)

```bash
node dist/index.js shield status
node dist/index.js shield selfcheck
node dist/index.js guard hooks --status
```

Expected: status output, selfcheck passes on a clean install. Guard hooks list installed pre-tool-use guards.

## Telemetry

```bash
node dist/index.js telemetry status
```

Expected: opt-in/opt-out state, retention notes, brand/model split (0.9.0 canary). NEVER prompts for opt-in mid-walkthrough.

## Detect (AI infrastructure inventory)

```bash
DIR=$(mktemp -d) && cat > "$DIR/openai.py" <<'EOF'
import openai
client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
EOF
node dist/index.js detect "$DIR"
```

Expected: lists detected SDK/provider; no false fire on the env-var reference.

## Edge cases (must not crash, must not silent-pass)

```bash
node dist/index.js review /nonexistent/path
node dist/index.js trust ""
node dist/index.js review --json /tmp 2>&1 | head -3
node dist/index.js unknown-subcommand 2>&1
```

Expected: each errors cleanly to stderr with exit 1, never a stack trace. Unknown subcommands print a hint, never silent exit 0 (regression for daemon 0.2.0 fix at nanomind#16, applied to opena2a-cli at 0.9.0).

## Score sanity check

| Target | Expected score range | Why |
|---|---|---|
| `~/.opena2a/corpus/repo/benign/tiny-clean-repo` | 80-100 | Known-good, intentionally clean |
| `~/.opena2a/corpus/repo/malicious/kitchen-sink` | 0-30 | Known-bad, intentionally vulnerable |
| Empty dir (`mktemp -d`) | 95-98 | Events emitted, ~0 findings post-#109 sub-item 1 |

A score below 30 for known-good or above 70 for known-bad means scoring is broken. Halt the publish and investigate.

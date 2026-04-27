# opena2a (monorepo) release smoke

**Covers `opena2a-cli` + library packages (`@opena2a/cli-ui`, `@opena2a/check-core`, `@opena2a/registry-client`, `@opena2a/telemetry`, `@opena2a/contribute`, `@opena2a/aim-core`).**

Catalog index: [opena2a-org/docs/testing/release-smoke-catalog.md](../../../docs/testing/release-smoke-catalog.md).

The opena2a monorepo publishes one CLI (`opena2a-cli`) and several libraries. Library bumps are smoke-tested via their downstream consumers — the only **standalone** CLI walkthrough lives here.

## 0. Pre-flight (Tier A — always)

```bash
cd ~/workspace/opena2a-org/opena2a
git status
npm ci
npx turbo run build test typecheck      # 26 tasks, all green
```

Fail the release if turbo reports any task red.

## 1. `opena2a-cli` walkthrough (Tier A on cli-touching diffs)

`opena2a-cli` delegates `check` to `hackmyagent` via subprocess spawn (router.ts). Its own commands are `protect`, `review`, `detect`, `mcp-audit`, `install`, `path`, plus the delegated `check`.

```bash
cd packages/cli
node dist/index.js --version           # 2 lines, version + telemetry disclosure
node dist/index.js --help              # lists every subcommand
```

### `check` (delegated to HMA)

Same matrix as [hackmyagent/docs/testing/release-smoke.md §2](../../../hackmyagent/docs/testing/release-smoke.md). When this monorepo bumps `@opena2a/registry-client` / `@opena2a/check-core` / `@opena2a/cli-ui`, run that section here too.

### `protect` (per packages/cli/__tests__/PROTECT_WALKTHROUGH.md)

```bash
node dist/index.js protect /tmp/protect-fixture/   # see PROTECT_WALKTHROUGH.md S1-S10 scenarios
```

The protect walkthrough is governed by `opena2a/CLAUDE.md` "Release testing — protect command (MANDATORY before any opena2a-cli publish that touches scanners)" — that block is the source of truth.

### `review`

```bash
node dist/index.js review ~/workspace/opena2a-org/test/hma/  # in-repo fixture
node dist/index.js review $(mktemp -d)                       # empty dir
```

### `detect` (Tier A on detect diffs)

```bash
node dist/index.js detect ~/workspace/opena2a-org/test/hma/
node dist/index.js detect ~/workspace/opena2a-org/test/hma/ --json | jq .
```

### `mcp-audit` (Tier A on mcp-audit diffs)

```bash
node dist/index.js mcp-audit verify ~/workspace/opena2a-org/test/hma/
```

### `install` / `path` (Tier B unless touched)

```bash
node dist/index.js path opena2a/code-review-skill   # echo install path; no side effect
# install requires a real registered skill; gate to staging if exercising
```

## 2. Library packages — downstream-consumer smoke

When a library bumps, the user-visible improvement / regression lives in its consumer. Run the consumer's smoke, not the library's tests.

| Library bump | Required downstream smoke |
|---|---|
| `@opena2a/cli-ui` | hackmyagent §2 (check) + ai-trust §1 + opena2a-cli §1 (check) |
| `@opena2a/check-core` | hackmyagent §2 + ai-trust §1 + opena2a-cli §1 |
| `@opena2a/registry-client` | hackmyagent §2 + ai-trust §1 + opena2a-cli §1 + opena2a-registry §1-3 |
| `@opena2a/telemetry` | every CLI's telemetry section + `--version` line |
| `@opena2a/contribute` | hackmyagent §1 (`secure --publish`) + opena2a-cli `path` |
| `@opena2a/aim-core` | aim-cli (separate repo) — out of monorepo smoke |

A library publish without a downstream smoke is treated as a data-only release per `~/.claude/projects/-Users-ecolibria-workspace-opena2a-org/memory/feedback_no_invisible_releases.md` — get explicit user opt-in or hold the publish until consumers wire it.

## 3. Cross-CLI parity (Tier A — every release that ships `check`)

Run the parity matrix from [ai-trust/docs/testing/release-smoke.md §5](../../../ai-trust/docs/testing/release-smoke.md). Must_match fields agree across HMA + ai-trust + opena2a-cli on identical inputs. The `opena2a-parity` repo's CI gate enforces this; the manual run is the sanity check before tagging.

## 4. Telemetry (Tier A on telemetry diffs across the workspace)

```bash
node dist/index.js telemetry status
node dist/index.js --version | grep "Telemetry:"
```

## 5. Full-sweep checklist (Tier B — monthly + minor / major)

Run §1-§4 against every fixture in §1 plus the full HMA + ai-trust matrices. The monorepo bundles a lot of surfaces; the goal of the monthly sweep is to catch cross-package drift (e.g. a `cli-ui` change that compiles but breaks one of three downstream renders).

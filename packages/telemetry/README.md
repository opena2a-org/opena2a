# @opena2a/telemetry

Tier-1 anonymous usage telemetry SDK for OpenA2A CLIs and tools.

Fires anonymous events (tool name, version, command name, success, duration, platform, node major) to the OpenA2A Registry. **No content collection** — no file paths, no scanned content, no prompts, no responses, no env vars, no IP storage. Schema and rationale: [`opena2a.org/telemetry`](https://opena2a.org/telemetry) (canonical disclosure) + `opena2a-registry/docs/telemetry-spec.md` (engineering spec).

## Install

```bash
npm install @opena2a/telemetry
```

## Usage

```ts
import * as tele from "@opena2a/telemetry";

await tele.init({ tool: "dvaa", version: "0.8.1" });
tele.start();
await tele.track("scan", { success: true, durationMs: 312 });
tele.error("scan", "HMA_TIMEOUT");
```

- `init()` loads opt-out config from `~/.config/opena2a/telemetry.json` and `OPENA2A_TELEMETRY` env var, and suppresses telemetry entirely in CI or under `DO_NOT_TRACK` (see [automatic suppression](#automatic-suppression)). **No first-run banner is emitted** (deliberate — see disclosure surfaces below).
- `start()` fires a `start` event.
- `track(name, fields?)` fires a `command` event with the command name and optional `success` / `durationMs`.
- `error(name, code)` fires an `error` event with the failure code.
- `status()` returns `{ enabled, configPath, policyURL, installId }` for tools to build their own `--version` line and `telemetry` subcommand (see `@opena2a/cli-ui` helpers).
- `successFromExitCode(exitCode, semanticSuccessCodes?)` translates `process.exitCode` to the `success` boolean. Default behavior follows POSIX security-tool convention (exit 0 and 1 = success; ≥ 2 = failure). The optional second argument lets dispatchers declare exit codes ≥ 2 that represent semantic outcomes (not crashes). See [crash-rate semantics](#crash-rate-semantics-for-success) below.

All methods are fire-and-forget. Network failures, rate-limiting (429), and timeouts are swallowed. Telemetry never blocks the calling tool.

## Crash-rate semantics for `success`

Per [CHIEF-CSR-018] + [CHIEF-CPO-022], the `success` field in invocation telemetry follows **crash-rate semantics**: `success: false` means the command itself failed to execute (config error, network failure, exception, integrity violation) — NOT "the user got a result they didn't want."

Some CLIs use exit codes ≥ 2 for semantic outcomes the command achieved correctly. Example: `ai-trust check <not-found-pkg>` exits 2 to signal "I checked, the package isn't in the registry." That's the command doing its job, not a crash. Pass those codes as the optional second argument so the dashboard signal reflects actual crash rate:

```ts
// POSIX default — exit 2 is a failure
success: tele.successFromExitCode(process.exitCode),

// ai-trust — exit 2 is a not-found outcome, not a crash
success: tele.successFromExitCode(process.exitCode, [2]),

// Multiple semantic codes are supported
success: tele.successFromExitCode(process.exitCode, [2, 3]),
```

Validation always wins. Out-of-range values (< 0 or > 255), non-finite numbers, and unparseable strings continue to return `false` even when listed in `semanticSuccessCodes`. A programming-bug-tier value (e.g. `[256]`) is treated as a programming bug, not a semantic override.

## Disclosure surfaces

Per the spec, this SDK does not emit a per-run CLI banner. Disclosure is discoverable via four other surfaces:

1. **Policy page** — [`opena2a.org/telemetry`](https://opena2a.org/telemetry).
2. **README section** — every consuming tool's README has a `## Telemetry` section.
3. **`<tool> --version` line** — appended by `@opena2a/cli-ui`'s `versionLine()` helper.
4. **`<tool> telemetry [on|off|status]`** — added by `@opena2a/cli-ui`'s `registerTelemetryCommand()` helper.

## Opt-out

Three ways to disable, in precedence order:

1. **Per-invocation** — `OPENA2A_TELEMETRY=off` (also `0`, `false`, `no`).
2. **Persistent** — `<tool> telemetry off` (writes to `~/.config/opena2a/telemetry.json`).
3. **Direct edit** — `~/.config/opena2a/telemetry.json` → `{"enabled": false}`.

## Automatic suppression

Telemetry is **off by default** in two cases, with no configuration:

- **CI / build environments** — detected via `CI`, `CONTINUOUS_INTEGRATION`, or a
  vendor marker (`GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `BUILDKITE`, `JENKINS_URL`,
  `TF_BUILD`, `VERCEL`, `NETLIFY`, and others). `CI=false` / `CI=0` is honored as
  "not CI".
- **`DO_NOT_TRACK`** — the [cross-vendor convention](https://consoledonottrack.com/).
  Any value other than `0` / `false` / `no` opts out.

Why: `install_id` is derived from the OS machine-id, falling back to a hash of the
hostname when that probe fails. CI runners are provisioned fresh for each job, so
the machine-id (or the hostname fallback) differs on every run — **a CI run
typically minted a new `install_id` and was counted as a distinct install and
active user**. Left unsuppressed, adoption metrics grow with build frequency rather
than with real usage. Bots are not users.

Two honest caveats. Self-hosted or reused runners have a *stable* machine-id, so
they collapse onto one persistent identity rather than inflating — a different
distortion, not this one. And `CI` is a proxy for ephemerality, not a synonym: a
throwaway `docker run`, a devcontainer rebuild, or a sandboxed `npx` hits the same
fallback path while setting none of these variables. This suppression covers the
CI-labeled population, which is the bulk of it, not the whole class.

The two reasons are **not peers**:

- `DO_NOT_TRACK` is a deliberate user intent, in the same tier as `telemetry off`.
  **Nothing overrides it** — see below.
- CI-ness is a fact about the machine, not a choice, so an explicit opt-in may
  override it.

Suppression is computed per-invocation and is **never written to the config file**:
the file records what the user chose, not where the process happened to run.

To exercise the real ingest path from your own CI, set an explicit
`OPENA2A_TELEMETRY=on` (also `1`, `true`, `yes`). That overrides **CI detection
only**. It can not re-enable a deliberate `telemetry off`, and it can not override
`DO_NOT_TRACK` — otherwise any Makefile, Dockerfile `ENV`, or org-wide CI config
exporting it would silently defeat a privacy signal the user set once in their
shell profile and never revisited.

`status()` reports which suppression is in force via the optional
`suppressedBy: "ci" | "do-not-track"` field, so a CLI can explain the state
rather than implying the user turned telemetry off:

```
  state:       off (CI environment detected)
  ...
  Telemetry is suppressed automatically in CI — you did not turn it off.
  override: OPENA2A_TELEMETRY=on opena2a <cmd>
```

Under `DO_NOT_TRACK` the remedy differs, because the opt-in does not override it:

```
  state:       off (DO_NOT_TRACK is set)
  ...
  DO_NOT_TRACK is set in this environment, so telemetry stays off.
  to re-enable: unset DO_NOT_TRACK
```

The field is absent when nothing suppressed, and is never set when the user
opted out themselves. Note that `setOptOut(true)` under suppression returns
`enabled: false` — it reports the effective state, not the flag it wrote,
because a config flip does not survive automatic suppression.

## Audit

Runtime audit of every payload:

```bash
OPENA2A_TELEMETRY_DEBUG=print dvaa scan ./agent
```

Each event is echoed to stderr in JSON before sending.

## What's collected

Only these fields, exactly:

| Field        | Example                     | Purpose                          |
|--------------|-----------------------------|----------------------------------|
| `tool`       | `"dvaa"`                    | Which tool fired the event       |
| `version`    | `"0.8.1"`                   | Version distribution             |
| `installId`  | `<random UUID>`             | Unique-installs aggregate (DAU)  |
| `event`      | `"install" \| "start" \| "command" \| "error"` | Event class |
| `name`       | `"scan"` (command events)   | Command-use heatmap              |
| `success`    | `true` (command events)     | Success rate per command         |
| `durationMs` | `312` (command events)      | Latency aggregate per command    |
| `platform`   | `"darwin"`                  | Platform distribution            |
| `nodeMajor`  | `24`                        | Node-version-support planning    |
| `countryCode` | derived server-side from CF-IPCountry | Country distribution (no IP stored) |

**Never collected:** file paths, scanned content, attack payloads, prompts, responses, env vars, argv beyond command name, user identifiers, raw IP.

## License

Apache-2.0

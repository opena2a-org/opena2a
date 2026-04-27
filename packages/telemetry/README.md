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

- `init()` loads opt-out config from `~/.config/opena2a/telemetry.json` and `OPENA2A_TELEMETRY` env var. **No first-run banner is emitted** (deliberate — see disclosure surfaces below).
- `start()` fires a `start` event.
- `track(name, fields?)` fires a `command` event with the command name and optional `success` / `durationMs`.
- `error(name, code)` fires an `error` event with the failure code.
- `status()` returns `{ enabled, configPath, policyURL, installId }` for tools to build their own `--version` line and `telemetry` subcommand (see `@opena2a/cli-ui` helpers).

All methods are fire-and-forget. Network failures, rate-limiting (429), and timeouts are swallowed. Telemetry never blocks the calling tool.

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

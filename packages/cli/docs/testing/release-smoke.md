# opena2a-cli release smoke test

**Run before every tag push to `cli-v*`. ~5 minutes by hand.**

The monorepo's existing CI (turbo build + test, lint, audit) covers the standard release gates. This file documents the **per-release manual checks** that CI can't catch — specifically the telemetry surfaces, since the user only sees them at runtime.

## 0. Pre-flight (1 min)

```bash
cd opena2a/packages/cli
npm run build              # zero output, zero errors
npm test                   # all green
node dist/index.js --help  # banner + commands list, no panics
```

## 1. Help and version

```bash
node dist/index.js --version
```

Expected output (exactly two lines for the `--version` invocation):
```
opena2a 0.10.0
Telemetry: on (opt-out: OPENA2A_TELEMETRY=off  •  details: opena2a.org/telemetry)
```

If the second line is missing, `versionLine()` isn't wired or the SDK init failed silently.

## 2. Telemetry — disclosure surfaces and opt-out (3 min)

**Do NOT point at the production endpoint while smoking** — set `OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never` so events go to a port that refuses connections (proves fire-and-forget tolerance) instead of polluting prod aggregates.

```bash
export OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never
unset OPENA2A_TELEMETRY
rm -f ~/.config/opena2a/telemetry.json
```

| # | Command | Expected |
|---|---------|----------|
| 2.1 | `opena2a --version` | `opena2a 0.10.0` then `Telemetry: on (opt-out: OPENA2A_TELEMETRY=off  •  details: opena2a.org/telemetry)` |
| 2.2 | `opena2a telemetry status` | `opena2a telemetry`, then `state: on`, install_id, config path, policy URL, toggle hint |
| 2.3 | `opena2a telemetry off` | `Telemetry disabled for opena2a.` Then `--version` shows `Telemetry: off`. `~/.config/opena2a/telemetry.json` has `"enabled": false`. |
| 2.4 | `opena2a telemetry on` | Re-enables persistently. |
| 2.5 | `OPENA2A_TELEMETRY=off opena2a telemetry status` | `state: off` (env wins over file). |
| 2.6 | `OPENA2A_TELEMETRY_DEBUG=print opena2a status` | Stderr contains a `[opena2a:telemetry]` line with the JSON payload (`tool: "opena2a-cli"`, `event: "command"`, `name: "status"`, `success: true`, `duration_ms: <int>`, no PII). The wire-format `tool` is `opena2a-cli` (npm name), not the brand `opena2a` — that's deliberate so tool_usage_events keys correlate with npm download counts. |
| 2.7 | `opena2a status` (with the unreachable URL) | Command completes normally. Telemetry endpoint unreachable must not slow it perceptibly (≤2s timeout). |

Fail the release if:
- any disclosure line is omitted or malformed
- `~/.config/opena2a/telemetry.json` leaks anything beyond `enabled` and `installId`
- the debug-print payload contains scanned package names, finding details, file paths, env-var values, or any field outside the locked schema (`tool, version, install_id, event, name, success, duration_ms, platform, node_major`)
- a command blocks more than 2 seconds when the telemetry endpoint is unreachable

## 3. Cleanup

```bash
unset OPENA2A_TELEMETRY_URL
# Restore your real telemetry config if you had one — the tests above
# overwrite ~/.config/opena2a/telemetry.json.
```

## 4. Setup-flow URLs — frontend host invariant (1 min)

`opena2a setup` prints links the user is expected to click. Backend host
(`oa2a.org`) serves the API; frontend host (`opena2a.org`) renders the UI.
Printing the backend host as a "Dashboard:" link sends users to a JSON health
endpoint, not the dashboard. This invariant is unit-tested in
`__tests__/util/server-url.test.ts` (`resolveDashboardUrl`); the smoke checks
the wire output every release because URL drift is invisible to scoring tests.

Run setup with the JSON flag against a fresh auth file pointed at `cloud`. If
you don't have a live AIM Cloud auth on this machine, skip 4.2 and run the
helper-output check (4.3) by itself — it covers the regression.

```bash
# 4.1 - inspect the cloud-auth path (real flow; needs a valid login first)
opena2a login --server cloud   # one-time
opena2a setup --json | jq '.dashboard, .mcpDashboard, .serverUrl'
```

| # | Assertion |
|---|-----------|
| 4.1.a | `dashboard` and `mcpDashboard` start with `https://aim.opena2a.org/` (NEVER `aim.oa2a.org`, NEVER `api.aim.opena2a.org`). |
| 4.1.b | `dashboard` ends with `/dashboard/agents/<agentId>` — deep link to the agent we just created, not the generic `/dashboard`. |
| 4.1.c | `serverUrl` is the API host (`https://aim.oa2a.org` for cloud) — that field is for downstream tooling, kept distinct from `dashboard`. |

Text-mode output should include a "Self-hosted instead?" hint that names a
`--server` example (e.g. `localhost:8080`). If that line is missing, the
self-hosted disclosure regressed — release-blocker.

```bash
# 4.2 - self-hosted shape (no live server needed; reads cached config)
node -e "
  const { resolveDashboardUrl } = require('./dist/util/server-url.js');
  const cases = {
    cloudBackend:    'https://aim.oa2a.org',
    communityApi:    'https://api.aim.opena2a.org',
    selfHostedLocal: 'http://localhost:8080',
    selfHostedCorp:  'https://aim.example.internal',
  };
  for (const [k, v] of Object.entries(cases)) console.log(k, '->', resolveDashboardUrl(v));
"
```

Expected (line for line):

```
cloudBackend -> https://aim.opena2a.org
communityApi -> https://aim.opena2a.org
selfHostedLocal -> http://localhost:8080
selfHostedCorp -> https://aim.example.internal
```

Fail the release if any line drifts. The two `*.opena2a.org` lines must NOT
contain `oa2a.org` (no `n`-drop) and the two self-hosted lines must echo the
input host exactly — same protocol, same port.

## When this checklist isn't enough

- If the diff touches `src/router.ts` or any subcommand action — also run the relevant subcommand against a real target (`opena2a check express`, `opena2a status`, etc.) — telemetry hooks fire on the postAction phase, so a broken hook only surfaces with a real action.
- If any `npm publish` is planned — the monorepo's release.yml + per-package `cli-v*` tag pattern handles publish via OIDC. No manual `npm publish` ever — first-publish bootstrap for new `@opena2a/*` packages is documented in the global memory `opena2a_npm_first_publish_bootstrap.md`.

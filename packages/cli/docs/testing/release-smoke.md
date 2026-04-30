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
you don't have a live AIM Cloud auth on this machine, skip 4.1 and run the
helper-output check (4.2) by itself — it covers the regression.

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

## 5. Auth token storage — keychain primary, file fallback (2 min)

`opena2a login` writes OAuth tokens to the OS keychain on macOS / Linux. The
metadata file at `~/.opena2a/auth.json` (mode `0600`) stays, but it must NOT
contain the token strings when keychain is available. Plaintext-on-disk
regression is invisible to scoring tests; the smoke checks the file shape
every release.

Run on a host with a working keychain (your laptop, NOT a Docker container):

```bash
# 5.1 - login + verify file shape
opena2a logout
opena2a login --server cloud      # device-flow login
ls -l ~/.opena2a/auth.json        # mode -rw------- (0600)
jq 'keys' ~/.opena2a/auth.json    # MUST contain "tokenStorage"; MUST NOT contain "accessToken" or "refreshToken"
jq -r .tokenStorage ~/.opena2a/auth.json  # "keychain" on macOS/Linux laptop, "file" on headless
```

| # | Assertion |
|---|-----------|
| 5.1.a | `tokenStorage` is present and equals `"keychain"`. If it's `"file"` on a known-good keychain box, keychain detection is broken. |
| 5.1.b | `accessToken` and `refreshToken` are NOT in the file's keys. Their presence is a P0 plaintext-on-disk regression. |
| 5.1.c | File mode is `-rw-------` (0600). Should be unchanged from prior releases. |

```bash
# 5.2 - keychain entries exist (macOS only)
security find-generic-password -s opena2a-cli -a 'https://aim.oa2a.org:access' -w | head -c 20 ; echo "..."
security find-generic-password -s opena2a-cli -a 'https://aim.oa2a.org:refresh' -w | head -c 20 ; echo "..."
```

Both MUST print a JWT prefix (`eyJhbGciOi...`) followed by `...`. If
`security` returns "item could not be found", login wrote nothing to the
keychain.

```bash
# 5.3 - logout clears keychain AND file (and orphans from prior server-switches)
opena2a logout
ls ~/.opena2a/auth.json 2>&1 | grep -q 'No such file' && echo "file gone OK"
security find-generic-password -s opena2a-cli -a 'https://aim.oa2a.org:access' -w 2>&1 | grep -q 'could not be found' && echo "keychain gone OK"
```

Both lines must print `OK`. Logout that leaves the keychain populated is a
P1 — the user thinks they're logged out but a stolen device still has the
refresh token. `removeAuth()` enumerates every `opena2a-cli` keychain entry
(via `listAccounts()`) so server-switch orphans (cloud → self-hosted without
intervening logout) are cleared too.

```bash
# 5.4 - file-fallback path (forced)
OPENA2A_AUTH_FORCE_FILE=1 opena2a login --server cloud
jq -r .tokenStorage ~/.opena2a/auth.json  # MUST be "file"
jq 'has("accessToken")' ~/.opena2a/auth.json  # MUST be true under file fallback
```

The forced-fallback path is what runs in Docker / CI / Windows today. It
must work AND print one line of stderr at login: `Warning: ... unavailable.
Storing tokens in ~/.opena2a/auth.json (mode 0600).`

```bash
# 5.5 - migration from legacy plaintext (one-time)
# Simulates a pre-0.10.2 user upgrading. Skip if 5.1 already migrated this host.
opena2a logout
cat > ~/.opena2a/auth.json <<'EOF'
{"serverUrl":"https://aim.oa2a.org","accessToken":"FAKE-LEGACY-ACCESS","refreshToken":"FAKE-LEGACY-REFRESH","expiresAt":"2099-01-01T00:00:00Z","tokenType":"Bearer","authenticatedAt":"2026-04-30T00:00:00Z"}
EOF
chmod 600 ~/.opena2a/auth.json
opena2a whoami 2>&1 | head -1
# MUST print: "Note: tokens migrated to OS keychain. ~/.opena2a/auth.json now holds metadata only."
jq 'has("accessToken")' ~/.opena2a/auth.json  # MUST now be false
opena2a logout                                 # cleanup the fake-token state
```

Fail the release if any of the assertions in this section regress. Plaintext
tokens leaking back into `~/.opena2a/auth.json` after a clean keychain login
is a P0 release-blocker.

## When this checklist isn't enough

- If the diff touches `src/router.ts` or any subcommand action — also run the relevant subcommand against a real target (`opena2a check express`, `opena2a status`, etc.) — telemetry hooks fire on the postAction phase, so a broken hook only surfaces with a real action.
- If any `npm publish` is planned — the monorepo's release.yml + per-package `cli-v*` tag pattern handles publish via OIDC. No manual `npm publish` ever — first-publish bootstrap for new `@opena2a/*` packages is documented in the global memory `opena2a_npm_first_publish_bootstrap.md`.

# Changelog

## Unreleased

### Added

- **Telemetry is now suppressed automatically in CI and under `DO_NOT_TRACK`.**
  New `isCI()`, `doNotTrack()` and `autoSuppressionReason()` helpers;
  `loadConfig()` returns `enabled: false` when either fires. Suppression is
  computed per-invocation and is never persisted — the config file records the
  user's choice, not where the process ran.

  The two reasons are deliberately **not peers**. `DO_NOT_TRACK` is a
  deliberate user intent and sits in the same tier as `telemetry off`:
  **nothing overrides it**. CI-ness is a fact about the machine rather than a
  choice, so an explicit `OPENA2A_TELEMETRY=on` overrides *CI detection only*
  — letting our own e2e exercise the real ingest path without allowing a
  Makefile, Dockerfile `ENV`, or org-wide CI config to silently defeat a
  privacy signal a user set once in their shell profile.

  `OPENA2A_TELEMETRY` opt-out values are now trimmed before comparison, so
  `OPENA2A_TELEMETRY="off "` (routine in `.env` files, compose YAML and `$(cmd)`
  substitution) disables rather than silently failing open.

  **Why this is a data-integrity fix, not a privacy nicety.** `install_id` is
  derived from the OS machine-id and falls back to a hash of the hostname when
  that probe fails. CI runners are provisioned fresh per job, so the machine-id
  (or hostname fallback) differs on every run — a CI run typically minted a
  brand-new `install_id` and was counted as a distinct install and a distinct
  active user. Adoption metrics tracked our own build frequency rather than
  real usage, and the error compounded with every added workflow.

  Scope, stated honestly: `CI` is a proxy for ephemerality, not a synonym. A
  throwaway `docker run`, a devcontainer rebuild or a sandboxed `npx` hits the
  same fallback path while setting none of the detected variables, and
  self-hosted/reused runners have a stable machine-id so they collapse onto one
  identity instead (a different distortion, not inflation). This covers the
  CI-labeled population — the bulk of it, not the whole class.

- **`status()` now reports *why* telemetry is off.** New optional
  `suppressedBy: "ci" | "do-not-track"` on `Status`, set only when the
  environment (not the user) is the cause — a user who ran `telemetry off`
  is never told CI did it. The field is omitted entirely when nothing
  suppressed, so existing consumers are unaffected.

  `setOptOut()` now returns the **effective** state rather than the flag it
  just wrote. Previously `telemetry on` inside CI persisted `enabled: true`,
  printed "Telemetry enabled", and then the very next `telemetry status`
  printed "off" — a dead end with nothing explaining the flip, since
  automatic suppression re-applies on every load.

  Registry context: per-tool installs are counted as
  `COUNT(DISTINCT install_id) FILTER (WHERE event = 'install')`, and no
  `install` event has ever been emitted by this SDK (`buildEvent` is only
  called with `start`, `command`, `error`), so the dashboard's Installs column
  reads a permanent 0. Simply dropping that filter would have counted CI
  runners and ephemeral containers as installs — replacing a visible zero with
  a plausible, wrong number. This change removes the CI-labeled share of that
  inflation; the non-CI ephemeral-container share (see Scope above) remains and
  must be addressed before a per-tool install count can be published as
  measured.

### Fixed

- **`DEFAULT_ENDPOINT` now points at the canonical ingest path** —
  `https://api.oa2a.org/api/v1/telemetry/v1/event` (was
  `.../api/v1/registry/telemetry/v1/event`). Registry PR #283 (2026-06-26) moved
  the ingest mount off the `/registry/`-prefixed path, which every published SDK
  (0.1.2 + 0.3.0) still posted to — so first-party telemetry silently 404'd for
  ~7 days until registry PR #299 added a back-compat alias mounting the old path
  to the same handler. All **deployed** installs recover via that alias with no
  client release; this fix ensures **future** installs post to the canonical path
  directly and lets the alias eventually be retired. Ships whenever the package is
  next published — no consumer action required (the alias covers the gap).

## 0.3.0 — 2026-05-24

### Added

- **`successFromExitCode(exitCode, semanticSuccessCodes?)`** — optional second argument lets each dispatcher declare exit codes ≥ 2 that represent semantic outcomes rather than crashes. Per [CHIEF-CSR-018] + [CHIEF-CPO-022] (`briefs/cli-telemetry-success-semantics.md`), invocation telemetry's `success` field follows **crash-rate semantics**: a `success: false` event means the command itself failed to execute (config error, network failure, exception, integrity violation), not "the user got a result they didn't want." Tools whose exit codes ≥ 2 represent working outcomes — `ai-trust check <not-found-pkg>` exits 2 to signal "I checked, the package isn't in the registry" — pass those codes via the new argument so the dashboard signal reflects actual crash rate.

  Surfaced by the first 60-day rollup query on `/admin/cli-usage`: `ai-trust audit` showed a 50% "failure" rate driven almost entirely by exit-2 not-found events in `requirements.txt` audits. Real crash rate was ~0%.

  Validation still wins. Out-of-range values (< 0 or > 255), non-finite numbers, and unparseable strings continue to return `false` even when listed in `semanticSuccessCodes` — a programming-bug-tier value is treated as a programming bug, not a semantic override.

### Migration for consumer CLIs

- **ai-trust** ships `tele.successFromExitCode(process.exitCode, [2])` consuming 0.3.0 on its next pin bump.
- **hackmyagent** ships unchanged dispatcher (no `semanticSuccessCodes` — partial-scan exit 2 IS a degraded outcome per [CHIEF-CSR-018]; surface it). HMA's integrity-failure exit-3 path at `src/cli.ts:9494` migrates to `tele.error('startup', 'INTEGRITY_FAIL')` so integrity violations get their own dashboard event row.
- **damn-vulnerable-ai-agent** — `browse.js:349` exit-2 site needs case-by-case classification before assigning a `semanticSuccessCodes` value. Default is no override.
- **opena2a-cli**, **secretless-ai** — no production exit-≥2 sites; no migration needed.

### Tests

- 11 new tests in `index.test.ts` covering `semanticSuccessCodes` behavior, validation precedence, backward compatibility with the no-arg form, and the "empty array = no override" semantic.

### Guardrails (set by [CHIEF-CPO-022])

- New CLIs joining the OpenA2A fleet MUST declare `semanticSuccessCodes` at telemetry-wiring time or accept the default `[]` (treat exit ≥ 2 as failure).
- Exit-code contract toward end-users is unchanged — no shipping CLI changes its `process.exit(...)` codes as part of this rollout. Splitting an existing exit code (e.g. HMA exit 2 → 2-or-4) is a breaking CLI contract change that requires Abdel escalation.
- Third-party SDK consumers: 0.3.0 is backward-compatible with 0.2.0 call sites — the second argument is optional. Existing dispatchers compile and behave identically without changes.

## 0.2.0 — 2026-05-11

### Changed (behavioural)

- **`install_id` is now stable across container restarts and beyond the 30-day boundary.** The previous implementation derived `install_id` from `hash(platform + node-major + npm-cache-dir + floor(mtime/30days))`. That had two production bugs surfaced by the first `/admin/cli-usage` Registry dashboard query (Apr 27 – May 11): (a) `install_id` rotated every 30 days even on stable developer machines because the mtime bucket advanced; (b) ephemeral container envs (CI, dvaa's primary deploy surface) had no persistent npm cache, so the fallback `randomUUID()` fired on every invocation, producing `47 unique installs from 67 events` for dvaa.
  - New derivation, in priority order:
    1. **OS machine-id** — `/etc/machine-id` (Linux/systemd) or `/var/lib/dbus/machine-id` (older Linux); `IOPlatformUUID` via `ioreg` (macOS); `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (Windows). Purpose-built per-machine identifier. High entropy, not predictable from hostnames, designed for this exact use case.
    2. **Hash of hostname + platform + node-major** — fallback when the machine-id probe fails (sandboxed environments, BSD/uncommon platforms, missing `ioreg` / `reg` binaries).
    3. **`randomUUID()`** — last resort when neither source is available.
  - Same machine produces the same `install_id` indefinitely, across container restarts, npm cache rebuilds, and beyond 30 days.
  - **One-time `install_id` change for every existing installation.** Persisted IDs from `~/.config/opena2a/telemetry.json` continue to be honoured; only first-run derivation changes. But machines that have never run a 0.1.x build (or whose config file was deleted) will derive a new ID from the new algorithm. Registry dashboards will show a small spike of "new installs" on the next consumer-tool release window. This is correct — the prior IDs were unstable.
  - **Privacy.** The raw machine-id / hostname is never transmitted. SHA-256 is applied locally and only the hash is sent to the Registry; the hash is irreversible. Rainbow-table resistance is strong for the machine-id path (random 128-bit Linux machine-ids, per-device macOS UUIDs) and weaker for the hostname fallback (predictable patterns like `runner-12345` in CI environments are theoretically guessable). Users in privacy-sensitive environments should prefer path (1) by ensuring `/etc/machine-id` exists, or run `<tool> telemetry reset` to opt into a random ID.

### Added

- **`successFromExitCode(exitCode: number | string | undefined | null): boolean`** — new public export. Translates a CLI's `process.exitCode` into the `success` boolean for `track()` using the security-tool convention (exits 0 and 1 = success; exit ≥ 2 = failure). Replaces the buggy `exitCode === 0` check that every consumer dispatcher was independently using, which recorded `exit 1 = findings detected` as failure and produced misleading 29% / 20% success rates on the dominant security commands (`hackmyagent secure`, `opena2a-cli scan`) in production. Helper widens to accept `string` for Node 22+'s widened `process.exitCode` type; unparseable strings return `false`. POSIX 0-255 bounds enforced: out-of-range values return `false`.

### Tests

- 12 new tests in `index.test.ts` (`successFromExitCode` matrix + bounds + Infinity + hostname-irreversibility + `install_id` stability across processes for the same machine).
- All SDK tests pass.

### Migration for consumer CLIs

Consumer CLIs (opena2a-cli, hackmyagent, secretless-ai, ai-trust, damn-vulnerable-ai-agent) ship companion PRs that fix the success-heuristic inline. On their next telemetry pin bump, they can replace the inline check with `tele.successFromExitCode(process.exitCode)` for centralised semantics.

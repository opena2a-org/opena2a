# Changelog

## 0.2.0 — 2026-05-11

### Changed (behavioural)

- **`install_id` is now stable across container restarts and beyond the 30-day boundary.** The previous implementation derived `install_id` from `hash(platform + node-major + npm-cache-dir + floor(mtime/30days))`. That had two production bugs surfaced by the first `/admin/cli-usage` Registry dashboard query (Apr 27 – May 11): (a) `install_id` rotated every 30 days even on stable developer machines because the mtime bucket advanced; (b) ephemeral container envs (CI, dvaa's primary deploy surface) had no persistent npm cache, so the fallback `randomUUID()` fired on every invocation, producing `47 unique installs from 67 events` for dvaa.
  - New derivation: `hash(hostname + platform + node-major)`. Same machine produces the same `install_id` indefinitely, across container restarts, npm cache rebuilds, and beyond 30 days. Falls back to `randomUUID()` only if `hostname()` returns `"localhost"` or empty (vanishingly rare).
  - **One-time `install_id` change for every existing installation.** Persisted IDs from `~/.config/opena2a/telemetry.json` continue to be honoured; only first-run derivation changes. But machines that have never run a 0.1.x build (or whose config file was deleted) will derive a new ID from the new algorithm. Registry dashboards will show a small spike of "new installs" on the next consumer-tool release window. This is correct — the prior IDs were unstable.
  - Privacy: hostname is SHA-256'd into UUID shape before transmission. The Registry never sees plaintext hostname; the hash is irreversible. `install_id` remains user-rotatable via `<tool> telemetry reset`.

### Added

- **`successFromExitCode(exitCode: number | string | undefined | null): boolean`** — new public export. Translates a CLI's `process.exitCode` into the `success` boolean for `track()` using the security-tool convention (exits 0 and 1 = success; exit ≥ 2 = failure). Replaces the buggy `exitCode === 0` check that every consumer dispatcher was independently using, which recorded `exit 1 = findings detected` as failure and produced misleading 29% / 20% success rates on the dominant security commands (`hackmyagent secure`, `opena2a-cli scan`) in production. Helper widens to accept `string` for Node 22+'s widened `process.exitCode` type; unparseable strings return `false`.

### Tests

- 8 new tests in `index.test.ts` (`successFromExitCode` matrix + `install_id` stability across processes for the same machine).
- All 43 SDK tests pass (was 35).
- 992 `opena2a-cli` tests pass.

### Migration for consumer CLIs

Consumer CLIs (opena2a-cli, hackmyagent, secretless-ai, ai-trust, damn-vulnerable-ai-agent) ship companion PRs that fix the success-heuristic inline. On their next telemetry pin bump, they can replace the inline check with `tele.successFromExitCode(process.exitCode)` for centralised semantics.

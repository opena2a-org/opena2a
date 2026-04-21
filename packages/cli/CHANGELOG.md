# Changelog

## Unreleased

### New Features
- `create skill [name]` command: secure skill scaffolding with 3 templates (basic, mcp-tool, data-processor), auto-signing, heartbeat, tests, and GitHub Action template
- `guard harden` subcommand: scan skills for security issues via HackMyAgent, with `--fix` and `--dry-run` flags
- Docker adapter configurable port mapping for `train` command (full DVAA port range)

## 0.8.24

### Bug Fixes
- Scoring: removed redundant 8-point deduction for missing `.gitignore` in the configuration category. HackMyAgent already covers this at LOW severity; the overlay was double-counting and caused `opena2a scan` to disagree with `hackmyagent secure` on the same target (95 MEDIUM vs 98 LOW). Users will see the same score climb from 95 to 98 on the reference fixture. The `.gitignore` hygiene check itself still reports `warn` when missing, so the item remains visible in the checks list.

### Notes
- First opena2a-cli release published via tag-triggered GitHub Actions workflow with npm provenance attestations (SLSA). Verify: `npm view opena2a-cli dist.attestations --json`.

## 0.8.23

### Bug Fixes
- `--server cloud` now resolves to `https://aim.oa2a.org` (AIM Cloud backend). Previously pointed to `api.aim.opena2a.org`, which serves a different product (community). Bare `aim.opena2a.org` still routes to `api.aim.opena2a.org` for community users.

## 0.6.3

### Breaking Changes
- `scanIdentity()` now checks for `.opena2a/aim/identity.json` instead of just the `.opena2a/` directory existing. Projects with a bare `.opena2a/` directory (no identity file inside) will now correctly report "no identity" instead of "identity initialized."

### New Features
- Shadow AI detection (`opena2a detect`) with governance scoring
- HTML executive report (`--report`)
- CSV asset inventory export (`--export-csv`)
- Shadow AI phase added to `opena2a review`
- Community contribution flow for detect scans and trust scores

### Bug Fixes
- `identity create` no longer crashes with "getOrCreateIdentity is not a function"
- `identity list` no longer auto-creates an identity when none exists
- `identity policy load` correctly parses YAML with `effect` field
- `identity check` correctly evaluates policy rules
- SOUL.md no longer flagged as "grants broad permissions" in AI config scan

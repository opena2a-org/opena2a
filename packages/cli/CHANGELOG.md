# Changelog

## Unreleased

### New Features
- `create skill [name]` command: secure skill scaffolding with 3 templates (basic, mcp-tool, data-processor), auto-signing, heartbeat, tests, and GitHub Action template
- `guard harden` subcommand: scan skills for security issues via HackMyAgent, with `--fix` and `--dry-run` flags
- Docker adapter configurable port mapping for `train` command (full DVAA port range)

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

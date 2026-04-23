# Changelog

All notable changes to `@opena2a/check-core`.

## 0.1.0 — 2026-04-24

Initial release. Extracted from `hackmyagent/src/check-render.ts` and
`ai-trust/src/output/formatter.ts` to provide one implementation of the
`check` flow's data layer across OpenA2A CLIs.

### Added
- `parseCheckInput(raw)` — ecosystem classifier (npm / pypi / github / local / url).
- `translateDownloadError(name, message)` — `code 128` + not-found hint builder.
- `mapScanStatusForMeter(status)` — maps registry scanStatus to the cli-ui meter gate.
- `buildCheckOutput(input)` — canonical `CheckOutput` JSON shape. Emission order matches hackmyagent@0.18.3 for byte-equality parity.
- `buildNotFoundOutput(input)` — canonical `NotFoundOutput` JSON shape.
- `checkPackage(input)` — registry-first, scan-on-miss orchestrator with pluggable `registry` / `scan` / `skillFallback` adapters.
- Types: `CheckInput`, `CheckOutput`, `NotFoundOutput`, `ScanResult`, `SkillResult`, `TrustData`, `ParsedCheckInput`, `ScanAdapter`, `SkillAdapter`, `RegistryAdapter`, `TranslatedError`.

### Unblocks
- F2, F3, F4 of `briefs/check-command-divergence.md` (not-found shape, git exit code leak, skill fallback).
- `[CA-034]` M3 milestone in `todo/2026-04-22-cli-consolidation-sequenced.md`.

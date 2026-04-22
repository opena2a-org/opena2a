# Changelog — @opena2a/cli-ui

## 0.3.0

### Added
- `renderCheckBlock(input)` — canonical `check <pkg>` output block. Emits header (name + meta), verdict line, Trust meter (gated on `scanStatus`), trust-level legend, and optional Publisher / Permissions / Revocation / Community scans / Last scan rows. Missing optional fields are hidden, never faked (closes brief `check-command-divergence.md` §F5).
- `renderNotFoundBlock(input)` — unified package-not-found output: ecosystem-aware header, optional error hint (for translated git-style misses, §F3), Did-you-mean suggestions list, optional skill-fallback CTA. Closes §F5 shape divergence across HMA / opena2a-cli / ai-trust.
- `renderNextSteps(input)` — Next-Steps CTAs with primary-vs-default bullet styling and tone signals. Each CLI passes its own commands; labels stay consistent across CLIs (closes §F7).

### Behaviour
- Trust meter is suppressed when `scanStatus !== 'completed' | 'warnings'` (closes §F6 — "a number implies measurement").
- Registry-canonical `trustScore` on the 0-1 scale is accepted and scaled to 0-100 for the meter; callers passing 0-100 work unchanged.
- No new runtime dependencies; primitives return structured `{ label, value, tone }` data so CLIs apply their own chalk palette.

## 0.2.0

### Added
- `renderObservationsBlock` + `buildCategorySummaries` + `buildVerdict` — Surfaces / Checks / Categories / Verdict block for scan output, consumed by HMA / opena2a-cli / ai-trust after CA-030.
- `analyst-render` helpers for description / threat-level / confidence normalization.

## 0.1.0

### Added
- Initial release: `scoreMeter`, `miniMeter`, `divider`, `normalizeVerdict`, `verdictColor`, `trustLevelLabel`, `trustLevelColor`, `trustLevelLegend`, `scoreColor`, `formatScanAge`.

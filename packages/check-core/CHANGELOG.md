# Changelog

All notable changes to `@opena2a/check-core`.

## 0.2.0 — 2026-04-27

Adds the rich-context narrative wire types, the static secret-rotation
lookup table, and the deterministic rule engine for verdict reasoning +
action gradient. Drives the `check` skill+mcp v1 view rendered by
`renderCheckRichBlock` in `@opena2a/cli-ui` 0.4.0 (session 3).

Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§4-§7).

### Added
- `PackageNarrative` + `SkillNarrative` + `McpNarrative` + supporting
  types (`HardcodedSecret`, `HardcodedSecretsBlock`, `McpTool`,
  `PermissionStatus`, `ToolCallCount`, `VerdictReasoningStatement`,
  `NextStep`, `ArtifactType`, `SecretSeverity`,
  `PermissionDeltaStatus`). Mirrors the `package_narratives` row stored
  by `opena2a-registry` migration 223.
- `SECRET_ROTATION_TABLE` + `lookupSecretRotation(type)` +
  `enrichSecretRotation(secret)` — credential-type → rotation
  URL/command lookup. Covers the brief baseline (anthropic, openai, aws,
  github, generic_bearer, private_key, database_url) plus three
  high-frequency types from HMA's existing corpus (slack_bot_token,
  gcp_service_account_key, stripe_secret_key) and the unknown fallback.
- `runRuleEngine(input)` — pure, deterministic
  `(RuleEngineInput) -> { verdictReasoning, nextSteps,
  enrichedSecrets, hardcodedSecretsBlock }`. Verdict reasoning rules
  per brief §5.1 (positive / gap / critical statements per tier).
  Action-gradient rules per brief §5.2 (verdict × scanStatus ×
  artifactType). No NanoMind, no I/O — same input always produces the
  same output.
- `CheckOutput.narrative?: PackageNarrative` — optional rich-context
  payload, emitted as the LAST key by `buildCheckOutput` so existing
  byte-equality parity (F1) holds when narrative is absent.

### Unblocks
- Brief acceptance criteria 4, 5, 6, 8, 10 (verdict reasoning + action
  gradient + hardcoded-secrets block determinism).
- Session 3 (cli-ui 0.4.0 rendering) — consumes `runRuleEngine` output
  via `PackageNarrative.verdictReasoning` + `nextSteps`.
- Session 2c (HMA semantic-compiler emission) — uses the wire types to
  build the `PackageNarrative` payload that `secure --publish` sends to
  the registry.

### Deferred to v2
- Rich-context rendering for npm/PyPI/A2A artifacts (graceful-degrade
  footer in v1).
- Per-package threat-model questions (static templates in cli-ui 0.4.0
  for v1).

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

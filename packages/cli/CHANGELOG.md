# Changelog

## 0.9.2

### Bug Fixes
- **Credential scanner: skip test fixtures, demo scripts, and VHS recordings (audit B12 + B1).** The 2026-04-29 self-audit of `opena2a review` surfaced 7 credential findings on opena2a/main where every match was an intentional placeholder — three in `packages/aim-core/src/dlp/dlp.test.ts` (the DLP scanner's own fixtures), three in `docs/vhs/setup-lab.sh` and `scripts/demo-setup.sh` (terminal-recording demos), and one generic key in the same demo path. `opena2a protect` would have rewritten them and broken the DLP test suite. `walkFiles` in `packages/cli/src/util/credential-patterns.ts` now skips files whose basename matches `*.{test,spec}.{ts,tsx,js,jsx,mjs,cjs,py}`, `*_test.{go,py}`, or `demo[-_]*.{sh,ts,js,py}`, plus the `vhs/` directory segment. Production source files, non-demo shell scripts, and credential-bearing files outside those naming conventions still scan as before. Tradeoff documented inline: real credentials committed inside test/demo paths won't be flagged by this scanner — that's the wrong layer to defend against; use git pre-commit hooks instead. 16 unit tests (`packages/cli/__tests__/util/credential-patterns-fixture-exclusion.test.ts`) pin the regex behaviour and reproduce the audit's 7-finding-to-zero scenario.
- **`opena2a review` HMA tab labels (audit B3).** "Total Checks / Failed / Passed" displayed `60 / 60 / 0` because `runHmaPhase` derived all three counters from `parsed.findings` (HMA's failed-only array), making "0 Passed" structurally inevitable. HMA also emits `parsed.allFindings`, which carries every check that ran (passed and failed). New exported helper `deriveHmaCounts(parsed, failedCount)` reads `allFindings` when present and falls back to the failed count for older HMA versions. Self-scan now reads `152 Total / 48 Passed / 60 Failed`. 6 unit tests in `packages/cli/__tests__/commands/review-hma-counts.test.ts` cover both code paths.
- **`opena2a check --help` no longer claims "HMA + NanoMind" analysis (audit B17).** The string at `packages/cli/src/index.ts:251` advertised a NanoMind code path that does not exist in the cli today (no `@nanomind/*` dependency in `packages/cli/package.json`; daemon 0.2.0 ships separately and the cli wiring is soft-gated on telemetry per [CHIEF-CDS-033]). Now reads "full HMA security analysis runs". Will revert when daemon consumption lands.
- **`opena2a review` Shield phase: gate findings by scan target (closes #109 sub-item 1, PR #112).** SHIELD-INT-001 "Configuration file tampered" surfaced 288 critical occurrences on an empty target because Shield's event log carried state from prior scans of unrelated paths. New `filterEventsToTarget` helper narrows ConfigGuard events to `targetDir` before classification; other event sources (notably ARP) pass through to preserve `/usr/bin/curl` and similar absolute-path detections. 24 deterministic unit tests in `packages/cli/__tests__/shield/findings-path-scoping.test.ts`. Empty-test reproducer: composite 27→72.

### New Features (carried forward from prior work, first release-tagged here)
- `create skill [name]` command: secure skill scaffolding with 3 templates (basic, mcp-tool, data-processor), auto-signing, heartbeat, tests, and GitHub Action template.
- `guard harden` subcommand: scan skills for security issues via HackMyAgent, with `--fix` and `--dry-run` flags.
- Docker adapter configurable port mapping for `train` command (full DVAA port range).

## 0.9.1

### Bug Fixes
- **`--no-contribute` per-invocation override (closes #107).** The flag was advertised in `--help` and the README telemetry table since 0.9.0 but never registered with Commander, so passing it produced `unknown option '--no-contribute'`. Now declared via `.option('--no-contribute', ...)`, threaded through the four `dispatchCommand` call sites in `index.ts` as `noContribute: globalOpts.contribute === false`, and the contribution gate in `router.ts` is rewritten to `(globalOptions.contribute || await isContributeEnabled()) && !globalOptions.noContribute` so the flag beats both `--contribute` and the persisted user-config consent for that single invocation. `RunOptions.noContribute?: boolean` added to `adapters/types.ts`.
- **Propagate `--no-contribute` and `--contribute` to spawned scanners.** `dispatchCommand` already injected `--format`, `--deep`, `--analm`, and `--static-only` into `adapterArgs`, but `--no-contribute` was being dropped before reaching `hackmyagent secure`, so the underlying subprocess still queued an anonymized summary even when opena2a-cli's own gate was closed. The flag now propagates so end-to-end suppression works (`opena2a scan --no-contribute` is silent; default and `--contribute` still queue). Independently rediscovered as P2-1 by the 0.9.0 `/release-test` walkthrough — strong signal the disclosure-without-implementation gap was real.

## 0.9.0

### New Features
- Tier-1 anonymous usage telemetry via `@opena2a/telemetry@0.1.2`. `opena2a --version` prints the disclosure line; `opena2a telemetry [on|off|status]` inspects/toggles. Disable per-invocation with `OPENA2A_TELEMETRY=off`, persistently with `opena2a telemetry off`, audit payloads with `OPENA2A_TELEMETRY_DEBUG=print`. README §Telemetry documents the schema and links to [opena2a.org/telemetry](https://opena2a.org/telemetry). Default ON. Wire format keys events under `tool: "opena2a-cli"` (matches npm package name) so download counts and event counts can correlate; user-facing display uses the `opena2a` brand.
- `docs/testing/release-smoke.md` — first release-smoke for this package, focused on telemetry surfaces (build/test live in the monorepo's existing CI).

### Changed
- `main()` wraps `program.parseAsync` in a try/catch/finally so `tele.error()` fires on subcommand throws and `tele.flush()` always runs before exit. Subcommand tracking happens via Commander `preAction`/`postAction` hooks.
- CommonJS / ESM bridge: the runtime imports of `@opena2a/telemetry` and `@opena2a/cli-ui` use dynamic `import()` inside the async `main()`, with `import type ... with { 'resolution-mode': 'import' }` for the TS type-only reference. Same pattern shipped in DVAA 0.8.2 and secretless-ai 0.16.0.

## 0.8.26

### Changed
- **`@opena2a/cli-ui` exact pin bumped to `0.5.0`** (was `0.2.0`). Picks up the rich-context check block primitives (`renderCheckRichBlock`, `renderHardcodedSecretsBlock`, `renderSkillNarrativeBlock`, `renderMcpNarrativeBlock`, `renderVerdictReasoningBlock`, `renderActionGradientBlock`, `threatModelQuestionsFor`, `sanitizeForTerminal`) and the ANSI sanitizer for untrusted narrative strings. Spawn-delegated `check skill:<name>` and `check mcp:<name>` now render the rich block via hackmyagent 0.21.0+; falls back gracefully on older HMA installs.

### Bug Fixes
- `router`: pass `skill:` / `mcp:` rich-block targets through to hackmyagent untouched. Previously the router could strip the prefix, breaking rich-block dispatch.
- `detect`: silent post-consent — drop the "contributed" label from per-server status rows. Rows now read clean once the user has consented; the consent state is implicit, not re-announced per row.

## 0.8.25

### Changed
- **Trust queries route through `@opena2a/registry-client@0.1.0` (exact pin).** Four call sites migrated via dynamic `await import(...)` for CJS compatibility: `util/registry-enrichment.ts` (batch), `util/report-submission.ts` (publish), `commands/verify.ts` (profile), `commands/mcp-audit.ts` (score). All three fleet CLIs now share one HTTP client implementation (published with SLSA v1 provenance). Per CA-034 M1. No user-visible output change; registry returns the same canonical trust data either way.
- `commands/verify.ts` tamper-detection fetch stays as a direct call: `/api/v1/trust/query?name=...&hash=...` uses a `hash` parameter not exposed by `@opena2a/registry-client@0.1.0`. Documented inline; revisit when the client adds a hash option.

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

# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `protect --grant <grant-ref> --atx <path>`: opt-in Agent Authorization Protocol gate. Before any scan, `protect` presents an ATX to the local Secretless broker and proceeds only if the broker authorizes the grant. New `packages/cli/src/aap/` module (broker client) is the first TypeScript AAP consumer. Defends T-3002, T-3003, T-3006, T-8002 at the CLI surface.
  - Exit codes: 0 (broker authorized), 2 (--grant without --atx or invalid ATX), 3 (403 opaque denial, AAP §6.6), 4 (broker socket unreachable), 5 (unexpected error), 6 (broker returned non-403 non-200 status — body never echoed to user).
  - Hardening: default-socket-path connections require socket-uid == process-uid (defense against same-box impostor brokers); ATX file capped at 256 KiB; response body capped at 1 MiB; ANSI/C0 control chars in user-supplied grant references are stripped before stderr output.
- `create skill [name]` command: secure skill scaffolding with 3 templates (basic, mcp-tool, data-processor), auto-signing via ConfigGuard, HEARTBEAT.md generation, vitest test file, and GitHub Action template
- `guard harden` subcommand: scan SKILL.md and HEARTBEAT.md files for security issues using HackMyAgent HardeningScanner, with `--fix` (auto-fix) and `--dry-run` (preview) flags
- Docker adapter configurable port mapping for `train` command (full DVAA port range)

## [0.10.12] - 2026-07-29

### Security
- Delegated tools now receive an allowlisted environment declared by their own adapter registry entry, instead of the operator's entire environment (#228). Measured on one developer machine: 128 variables reached the child, 11 of them credentials; now 20 and none. The contract lives on each `ADAPTER_REGISTRY` entry (`envAllow` / `envAllowPrefixes`) rather than in a single generic list, because these adapters run first-party tools with real environment contracts — `secretless-ai` needs `VAULT_ADDR`/`VAULT_TOKEN`/`AWS_*` because it is a credential broker, and `hackmyagent` needs `NANOMIND_URL`/`NANOMIND_GUARD_SOCK`/`ANTHROPIC_API_KEY` or it silently returns different findings with a zero exit code. Both reach the spawn path through the import-adapter fallback. New `util/child-env.ts` supplies the base allowlist (PATH/HOME/locale, proxy and custom-CA settings, CI markers, telemetry opt-out, the `*_CLI_PREFIX` citation vars) and a credential-name guard over prefix matches; exact entries bypass the guard, which is how a tool declares the credential it genuinely uses and how `SECRETLESS_CLI_PREFIX` survives a substring match on "secret". Availability probes (`which x`, `x --version`, `python -c "import m"`) get a narrower probe environment with no credentials at all. Operators can extend the allowlist with `OPENA2A_CHILD_ENV_ALLOW="NAME,PREFIX_*"`; a bare `*` and any prefix under three characters are refused, entries are capped, the widening is reported on stderr, and the variable is never forwarded to the child. The `release-smoke-comply` and `release-smoke-init` harnesses use the same mechanism. `secrets` and `broker` are declared EXEMPT (`envInherit`) rather than allowlisted: `secretless-ai` reads credential names it discovers at runtime, so a static list made `opena2a secrets verify` report a different machine than `secretless-ai verify` with both exiting 0. Their availability probes stay narrow regardless. The direct `hackmyagent` spawns in `router.ts`/`index.ts`/`review.ts`, `shield/llm-backend`, and the corpus parity harness still inherit the full environment and are tracked in #246. Scope note: this reduces environment-borne exposure only — `HOME` is forwarded by design, so `~/.npmrc`, `~/.aws/credentials` and `~/.docker/config.json` remain reachable by any child, and the guard matches names, not values.
- `shield recover --verify` now verifies before it recovers, which is what the flag has always claimed (#228). A `degraded` result still unlocks — a missing shell rc file must not strand anyone — but it no longer reports "successful verification"; the warnings are named in both the text and JSON output. Note `enterLockdown` has no production caller today, so this closes a fail-open on a path the shipped CLI does not currently reach. It previously called `exitLockdown()` first and re-entered lockdown only if the checks came back compromised, because `runIntegrityChecks` short-circuits while the lockdown marker is present. That briefly unlocked a compromised machine, and a check that threw — or a SIGINT, or a kill — during the window left it unlocked permanently. `runIntegrityChecks` takes a new `ignoreLockdown` option so the battery can run with the marker still in place; every other caller keeps the short-circuit.

### Fixed
- `benchmark` no longer certifies controls it never evaluated (#250). It returned `Certified`, `L1: 100% (39/39)` for an empty directory and for a project with a hardcoded API key, because a control counted as passing whenever no finding mentioned its check id — and the only source consulted evaluates none of the 39 OASB L1 controls. Scoring is now coverage-gated: unevaluated controls leave both sides of the ratio and are disclosed by count on the score line and by id under `--verbose`; `Certified`/`Passing` require complete coverage; zero coverage reports `Not assessable`. Credential controls are genuinely evaluated via the same scanner `init` and `protect` use, so `protect` and `benchmark` now agree that a hardcoded key fails CRED-002. Categories with no controls at the requested level report `n/a` rather than `0%`. New `npm run release-smoke:benchmark` corpus-tier gate.
- Every score line now states its scope (#252). `init`, `scan`, `review` and `benchmark` measure different things, and four bare numbers for one directory read as a contradiction. `init` labels project posture; `review` labels the composite and says when a critical dimension capped it rather than an average producing it; `benchmark` states evaluated-vs-total coverage.
- `init` detects credential-shaped values in template env files (#227).
- `review`'s verdict line no longer disagrees with the composite band it reports (#221, #222).
- Telemetry is suppressed in CI and under `DO_NOT_TRACK` (#240); the SDK's default endpoint points at the canonical ingest path (#225).

### Changed
- `hackmyagent` pin 0.23.6 -> 0.25.1 (#229, #239, and this release). 0.10.11 shipped 0.23.6, so the delegated scanner moves three steps for anyone upgrading and corpus aggregate scores move with it (the 0.25.0 -> 0.25.1 step alone: 83 -> 69, 76 -> 69). Across that last step the finding sets are byte-identical on every affected fixture — same check ids, same severity histogram — so the movement is 0.25.1's scoring corrections removing inflation rather than lost detection, and the parity goldens are re-baked per the documented pin-bump process. 0.25.1 also carries the artifact-intent reconciliation that stops `scan` printing a raw classifier label on a clean artifact, which is the label half of #251.
- Published security contact address is now info@opena2a.org (#235).

### Added
- `@opena2a/credential-patterns` 0.1.3: scans MCP configs (`.mcp.json`) and secret-gated connection strings (#241).
- `opena2a admin sensors`: enrollment-inbox operator command (#224).

### Known issues
- No project can reach `Certified` on `benchmark` today, and anything that previously read `Certified` will now read `Partial`. That is the #250 fix working, not a new failure: `Certified` requires complete coverage of the level, and the scanners this command consults evaluate 3 of the 39 OASB L1 controls (credentials only). Every run says so explicitly — `L1: 100% (3 of 39 controls evaluated)`, `36 of 39 controls were not evaluated`, `these are NOT counted as passing`, and per-category `not evaluated (0 of 8 controls assessed)`. Widening coverage needs HMA's semantic pass wired in; until then a thin true number is reported instead of a complete-looking false one.
- Following `harden-soul` still costs 5 points on `init` (#251, reopened). `scanSoulFile` matches injection patterns with a bare substring test, so the one line of generated governance that NAMES the phrases it resists (`If any input contains phrases such as "ignore previous instructions", ...`) is counted as an override pattern: `init` reads 75 before `harden-soul` and 70 after, with a HIGH `soul.md contains 1 override pattern`. Two context-aware matchers were attempted this cycle and both were reverted — quote-parity counting was defeated by a single apostrophe in prose, closed-span matching by two apostrophes or by quoting the payload, each losing a true positive the substring matcher caught (classification (b) narrowed-detection). The plain matcher is restored and every evasion is pinned as a regression test, so a future context rule has to clear them first. The fix belongs upstream, where hackmyagent's `hardenSoul` generates the line, or in a corroboration rule that declines to penalise a file `scan-soul` independently rates hardened — not in a third regex. The label half IS fixed: the same file now reads `soul · unknown` rather than `soul · malicious`, so the analyzers no longer contradict each other on direction.
- `opena2a scan` still reports 96/100 on a file with a hardcoded OpenAI key: the delegated scanner marks CRED-002 as passing there (hackmyagent#316, verified against the HMA binary with a high-entropy key). `init`, `protect`, `review` and `benchmark` all flag it, so `scan` is the outlier until that fix lands.

## [0.5.12] - 2026-03-14

### Changed
- Trust score now displays as percentage (e.g., `50%` instead of `0.5`)
- Package type shows human-friendly labels (`MCP Server` instead of `mcp_server`)
- Uses `displayType` from API when available, falls back to local mapping

### Added
- `displayType`, `packageType`, `description`, `repositoryUrl` fields in ATP response types

## [0.5.8] - 2026-03-12

### Fixed
- Fix `claim` command failing to find packages that `trust` could find -- now defaults source to 'npm' before registry lookup
- Fix `trust --verbose` producing identical output to non-verbose -- now shows request URL, response time, agent ID, source, and version

## [0.5.0] - 2026-03-05

### Fixed
- Fix all adapter --help commands (scan, secrets, benchmark, registry, broker, train, crypto) -- now pass through to underlying tool help instead of showing generic Commander.js description
- Fix `status` command crash ("unknown command" error) -- now shows unified security status via Shield
- Fix `check` command missing directory argument -- `opena2a check /path` now works
- Fix `benchmark` dispatch showing HMA help instead of running -- converted to direct command using HMA programmatic API
- Fix `registry` crash when invoked with no arguments -- now shows usage with examples
- Fix review "Grade F" UX violation -- replaced with recovery-framed scoring ("path to 100 available")
- Fix vault migration silently falling back to .env (AI tools read .env files, defeating the purpose)
- Fix vault migration not detecting missing 1Password CLI (op) -- now shows pre-flight error with setup instructions
- Fix protect output not showing which files were signed

### Added
- `status` command: unified security status across all installed tools
- `benchmark` command: direct OASB-1 compliance checking with --level L1/L2/L3
- OS Keychain vault backend option in protect migration flow
- Per-file signing details in protect output
- Rollback commands in protect output (undo signing, restore files)
- "For deeper analysis" hint in init output pointing to scan secure
- Storage location tracking (VAULT / SHELL PROFILE / FAILED) in migration report

### Changed
- Benchmark moved from adapter to direct command (programmatic HMA API)
- Vault fallback: shell profile exports instead of .env files
- Removed all registry.opena2a.org references (registry not yet available)

## [0.4.0] - 2026-03-04

### Fixed
- Fix scan-soul/harden-soul dispatch: moved from broken ImportAdapter fallback to direct SoulScanner programmatic API
- Fix registry command: changed from import to spawn method (ai-trust parses process.argv on import)
- Fix SpawnAdapter.isAvailable(): missing await on Promise || Promise caused false negatives
- Fix guard verify/status/diff ignoring positional directory argument
- Fix runtime status/tail rejecting positional directory argument
- Fix CRED-002 misclassifying sk-ant-* Anthropic keys as OpenAI (broadened negative lookahead)
- Fix CRITICAL/HIGH severity label visibility in terminal output
- Fix drift detection tip text inaccuracy
- Exclude CLI own source files from credential scanning

### Added
- Bundle hackmyagent, secretless-ai, ai-trust as dependencies (npx opena2a-cli scan-soul works out of the box)
- Direct scan-soul command with --profile, --tier, --deep options
- Direct harden-soul command with --dry-run, --profile, --tier options
- Progress-oriented scan-soul output with path-forward guidance

### Changed
- Remove "product" language throughout CLI (replaced with tool/platform/library)
- scan-soul and harden-soul are now direct commands, not adapter-backed

## [0.3.1] - 2026-03-02

### Fixed
- Fix review score fairness: redesign score breakdown with structured explainers
- Fix NL natural language input requiring literal shell quotes (multi-word fallback before Commander)
- Wire `--contribute` flag to report-submission.ts (was dead code)
- Fix broker/dlp commands routing identically to secrets (added subcommand differentiation)
- Make Shield events project-scoped (`.opena2a/shield/`) instead of always global
- Fix command injection in detect.ts (use `execFileSync` instead of `execSync`)
- Fix RC file overwrite in init.ts (use `appendFileSync` instead of `writeFileSync`)
- Fix npx auto-install in status.ts (add `whichBinary` gate before exec)
- Fix genesis hash bug in integrity.ts (used empty string instead of `GENESIS_HASH`)
- Fix 13 additional security, correctness, and UX bugs found during QA review

### Changed
- Replace generic stat-hero cards with score banner and structured explainers in review dashboard
- Update help text to show quote-free NL examples (`find secrets`, `detect credentials`)

## [0.3.0] - 2026-03-02

### Added
- Shield `init` orchestration: unified security setup that runs scan, policy, and hooks
- Cross-tab navigation for finding IDs in HTML dashboard
- Standardized tool nav bar ordering across repos

### Fixed
- Fix CI security checks: sync lock file, remove redundant secret-scan job

### Changed
- Update README with Shield command, adapter mappings, and ecosystem table

## [0.2.0] - 2026-03-02

### Added
- ConfigGuard: 18 features including sign, verify, status, watch, diff, enforce, policy, hook, resign, snapshot
- ConfigGuard pre-commit hook integration
- ConfigGuard skill and heartbeat file signing
- Shield enforcement mode with command blocking and event logging
- Shield adaptive baselines module (learn/suggest/protect flow)
- Shield interactive HTML posture report
- Shield CI integration workflow and example
- Shield E2E integration test covering full lifecycle
- ARP-Shield bridge with genesis hash fix and posture scoring
- Actionable security reports with finding IDs, SARIF, and compliance mapping

### Fixed
- Fix posture score: exclude Shield diagnostic events from threat scoring
- Fix ConfigGuard detection in shield status
- Fix guard type mismatch from cherry-pick merge

### Changed
- Upgrade report to multi-page dashboard with improved scoring

## [0.1.2] - 2026-03-02

### Added
- DRIFT-002 AWS Bedrock liveness verification
- DRIFT-001 Google Maps/Gemini scope drift detection with liveness verification
- Shield modules wired to CLI with signing, LLM, and session support
- Init command: security posture assessment with trust scoring
- Guard command: config file integrity signing and verification
- Runtime command: ARP agent runtime protection wrapper
- Advisory intelligence with vulnerability database checks
- Community contribution prompting system
- Self-register, verify, and baselines commands
- Secretless AI integration for broker and DLP adapters

### Changed
- Rename npm package from `@opena2a/cli` to `opena2a-cli`
- Fix credential detection accuracy and CLI UX

## [0.1.0] - 2026-03-02

### Added
- Initial release: meta repo with ecosystem overview and security policy
- Terminal demo GIFs showcasing security checks
- AI Browser Guard ecosystem entry

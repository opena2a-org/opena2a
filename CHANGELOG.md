# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `create skill [name]` command: secure skill scaffolding with 3 templates (basic, mcp-tool, data-processor), auto-signing via ConfigGuard, HEARTBEAT.md generation, vitest test file, and GitHub Action template
- `guard harden` subcommand: scan SKILL.md and HEARTBEAT.md files for security issues using HackMyAgent HardeningScanner, with `--fix` (auto-fix) and `--dry-run` (preview) flags
- Docker adapter configurable port mapping for `train` command (full DVAA port range)

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

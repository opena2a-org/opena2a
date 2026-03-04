# Changelog

All notable changes to this project will be documented in this file.

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

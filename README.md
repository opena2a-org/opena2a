> **[OpenA2A](https://github.com/opena2a-org)**: [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/ai-browser-guard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) · [Registry](https://registry.opena2a.org)

<div align="center">

# OpenA2A

**Open-source security platform for AI agents**

Credential detection, scope drift analysis, config integrity, runtime monitoring, and supply chain verification -- one CLI.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)]()

[Website](https://opena2a.org) | [Docs](https://opena2a.org/docs) | [Registry](https://registry.opena2a.org) | [Discord](https://discord.gg/uRZa3KXgEn)

</div>

---

## Requirements

- Node.js >= 18
- Optional: Docker (for `opena2a train`)
- Optional: Python 3.9+ (for `opena2a crypto`)

## Install

```bash
# Try without installing
npx opena2a-cli init

# Install globally
npm install -g opena2a-cli

# Homebrew (macOS/Linux)
brew tap opena2a-org/tap && brew install opena2a
```

No configuration required. Works with Node.js, Python, Go, and MCP server projects.

## What It Does

Run `opena2a shield init` in any project directory. One command sets up credential protection, agent identity, config integrity, runtime monitoring, and AI tool configuration:

<p align="center">
  <img src="docs/vhs/shield-init.gif" alt="opena2a shield init demo" width="700" />
</p>

Or start with a quick assessment using `opena2a init`:

<p align="center">
  <img src="docs/vhs/init.gif" alt="opena2a init demo" width="700" />
</p>

```
  OpenA2A Security Report  v0.3.3

  Project      myapp v2.1.0
  Type         Node.js + MCP server
  Directory    /home/user/myapp

  Security Posture
  -----------------------------------------------
  Credential scan      3 findings
  .gitignore           present
  .env protection      NOT in .gitignore
  Lock file            package-lock.json
  Security config      none
  MCP config           found
  LLM server           Ollama on :11434 (no auth)
  -----------------------------------------------
  Security Score   30 / 100  -> 85 by running opena2a protect

  Recommended Actions
  -----------------------------------------------
  [CRITICAL]  Migrate 3 hardcoded credentials
              opena2a protect

  [HIGH]      Add .env to .gitignore
              opena2a protect

  [MEDIUM]    Sign config files for integrity
              opena2a protect
  -----------------------------------------------

  Scope Drift Detected
  -----------------------------------------------
  DRIFT-001 Google Maps key may access Gemini AI
    src/config.js:5

  Scope drift: keys provisioned for one service silently
  gain access to AI services, expanding attack surface.
  Run: opena2a protect
```

Then fix everything in one command:

```bash
opena2a protect       # Fix all findings: credentials, .gitignore, config signing
opena2a init          # Re-assess -- watch your score improve
```

<p align="center">
  <img src="docs/vhs/protect.gif" alt="opena2a protect demo" width="700" />
</p>

## Smart Input Modes

Multiple ways to interact with the CLI -- no memorization required:

```bash
opena2a                           # Interactive guided wizard (no args)
opena2a ~drift                    # Semantic search -- finds related commands
opena2a ~api keys                 # Semantic search with domain expansion
opena2a ?                         # Context-aware recommendations for your project
opena2a "find leaked credentials" # Natural language command matching
```

Semantic search uses a weighted index of tags, synonyms, and domains -- no API calls. Natural language mode falls back to Claude Haiku when static matching is insufficient (opt-in, ~$0.0002 per query).

## Scope Drift Detection

API keys provisioned for one service often silently grant access to others. A Google Maps key can call Gemini. An AWS S3 key may reach Bedrock.

OpenA2A detects these cross-service privilege escalations:

| Finding | What It Means |
|---------|---------------|
| **DRIFT-001** | Google API key can access Gemini AI models beyond intended Maps/Places scope |
| **DRIFT-002** | AWS access key can invoke Bedrock LLM models beyond intended S3/EC2 scope |

When drift is detected, `opena2a protect` migrates the key to environment variables and creates a deny-all broker policy so you can explicitly control which services each key is allowed to reach.

## Core Commands

### [`opena2a init`](https://opena2a.org/docs/cli/commands/init)

Assess your project's security posture. Detects project type, scans for credentials, checks hygiene (`.gitignore`, `.env` protection, lock file, security config), calculates a trust score (0-100), and provides prioritized next steps.

```bash
opena2a init                    # Assess current directory
opena2a init --dir ./my-agent   # Assess specific directory
opena2a init --verbose          # Show individual credential details
opena2a init --format json      # Machine-readable output for CI
```

### [`opena2a protect`](https://opena2a.org/docs/cli/commands/protect)

Single command to fix all auto-fixable findings. Migrates credentials, fixes `.gitignore`, excludes AI config files from git, signs config files, and shows before/after security score.

```bash
opena2a protect                 # Fix everything fixable
opena2a protect --dry-run       # Preview changes without modifying files
opena2a protect --skip-liveness # Skip drift liveness verification (offline/CI)
opena2a protect --skip-verify   # Skip verification re-scan after migration
opena2a protect --skip-sign     # Skip config signing phase
opena2a protect --skip-git      # Skip git hygiene fixes
opena2a protect --report out.html  # Generate interactive HTML report
opena2a protect --format json   # JSON output for CI pipelines
```

DRIFT findings (DRIFT-001, DRIFT-002) include liveness verification -- the CLI actually calls the API to check whether a Google Maps key can access Gemini, or an AWS key can reach Bedrock. Use `--skip-liveness` in CI or offline environments.

> See a [sample interactive report](docs/demos/sample-protect-report.html) generated by `opena2a protect --report`.

What protect fixes:
1. **Credentials** -- Detect, vault, and replace hardcoded secrets with env var references
2. **`.gitignore`** -- Create or update to exclude `.env` files
3. **AI config exclusion** -- Add `CLAUDE.md`, `.cursorrules`, etc. to `.git/info/exclude`
4. **Config signing** -- Sign config files for tamper detection (`.opena2a/guard/signatures.json`)
5. **Verification** -- Re-scan to confirm all credentials removed, show before/after score

### [`opena2a guard`](https://opena2a.org/docs/cli/commands/guard)

Config file integrity protection. Sign your config files, detect unauthorized modifications, enforce policies, and manage signature snapshots for rollback.

**Subcommands:**

```bash
opena2a guard sign              # Sign all detected config files (SHA-256)
opena2a guard verify            # Check for tampering or unsigned files
opena2a guard status            # Show signature summary (signed/unsigned/tampered counts)
opena2a guard watch             # Real-time file monitoring with tamper alerts
opena2a guard diff              # Show changes since last signing (file-level diffs)
opena2a guard policy init       # Initialize guard policy for this project
opena2a guard policy show       # Display current guard policy
opena2a guard hook install      # Install pre-commit hook (blocks commits when tampered)
opena2a guard hook uninstall    # Remove pre-commit hook
opena2a guard hook status       # Check if pre-commit hook is installed
opena2a guard resign            # Re-sign files after intentional changes (creates safety snapshot first)
opena2a guard snapshot create   # Create a timestamped signature snapshot
opena2a guard snapshot list     # List available snapshots
opena2a guard snapshot restore  # Restore signatures from a snapshot
```

**Flags:**

```bash
--enforce                       # Quarantine mode: exit code 3 on tampering instead of 1
--skills                        # Include SKILL.md files in signing/verification (HTML comment signature block)
--heartbeats                    # Include HEARTBEAT.md files (includes expires_at)
--files <files...>              # Sign/verify specific files only
--dir <path>                    # Target directory (defaults to current working directory)
--ci                            # CI mode: machine-readable output, non-interactive
```

**Behaviors:**

- Signatures stored in `.opena2a/guard/signatures.json`
- Exit codes: `0` = clean, `1` = tampered, `3` = quarantine (`--enforce`)
- Default files: `mcp.json`, `package.json`, `tsconfig.json`, `arp.yaml`, `go.mod`, `Dockerfile`, and more
- Policy can require specific files, block on unsigned, and auto-disable heartbeats when tampering is detected
- Pre-commit hook runs `opena2a guard verify --ci` before each commit
- Snapshots stored in `.opena2a/guard/snapshots/`, max 20 with auto-prune
- `resign` creates a safety snapshot before re-signing so you can roll back
- Shield integration: `opena2a shield status` includes ConfigGuard state

**Example workflow:**

```bash
opena2a guard sign                       # Sign all config files
opena2a guard policy init                # Set up integrity policy
opena2a guard hook install               # Block commits on tampering
# ... later, after intentional config changes ...
opena2a guard diff                       # Review what changed
opena2a guard resign                     # Re-sign (snapshot created automatically)
opena2a guard snapshot list              # View available snapshots
opena2a guard snapshot restore <id>      # Roll back if needed
```

### [`opena2a shield`](https://opena2a.org/docs/cli/commands/shield)

Unified security orchestration. One command to set up everything -- credential protection, agent identity, config integrity, policy generation, shell hooks, runtime monitoring, and AI tool configuration.

```bash
opena2a shield init             # Full 11-step security setup
opena2a shield status           # Unified view across all products
opena2a shield log              # Query tamper-evident event log
opena2a shield selfcheck        # Verify integrity
opena2a shield report           # Generate weekly security report
opena2a shield session          # Identify current AI assistant session
```

Shield orchestrates Secretless (credential protection), aim-core (agent identity), ConfigGuard (config integrity), ARP (runtime monitoring), and Browser Guard (browser session protection) into a single workflow. Optional products degrade gracefully when not installed.

<p align="center">
  <img src="docs/vhs/shield-status.gif" alt="opena2a shield status demo" width="700" />
</p>

### `opena2a review`

Run all security checks and open a unified HTML dashboard. Combines credential scanning, config integrity verification, and HMA scan results into a single composite score.

```bash
opena2a review                  # Scan and open HTML dashboard
opena2a review --format json    # JSON output for CI
opena2a review --report out.html  # Write to custom path
opena2a review --no-open        # Generate report without opening browser
opena2a review --skip-hma       # Skip HMA scan even if available
```

### [`opena2a runtime`](https://opena2a.org/docs/cli/commands/runtime)

Agent Runtime Protection (ARP) wrapper. Monitor process, network, and filesystem activity.

```bash
opena2a runtime init            # Generate arp.yaml for your project
opena2a runtime start           # Start monitoring
opena2a runtime status          # Show monitor/interceptor status
opena2a runtime tail            # View recent security events
```

### [`opena2a verify`](https://opena2a.org/docs/cli/commands/verify)

Binary integrity verification. Compares installed package hashes against the OpenA2A Trust Registry to detect supply chain tampering.

```bash
opena2a verify                  # Check all OpenA2A packages
opena2a verify --package hackmyagent  # Check specific package
```

### `opena2a self-register`

Register OpenA2A tools in the public Trust Registry with security scan results.

```bash
opena2a self-register --dry-run   # Preview what would be registered
opena2a self-register             # Register all 13 tools
```

### `opena2a baselines`

Collect behavioral observations for crowdsourced agent profiles (opt-in). Monitors a package's runtime behavior to build baseline profiles.

```bash
opena2a baselines --package hackmyagent          # Observe for 60 seconds (default)
opena2a baselines --package hackmyagent --duration 120  # Custom duration
```

### `opena2a config`

Manage user preferences and feature toggles.

```bash
opena2a config show               # Display current configuration
opena2a config contribute on      # Enable community data sharing
opena2a config llm on             # Enable LLM-powered command matching
```

### `opena2a shield`

Unified security orchestration. Shield ties together all OpenA2A products into a single command surface. Run `shield init` to set up your project, then use `shield status` to monitor posture across credentials, config integrity, runtime protection, and policy compliance.

**Subcommands:**

```bash
opena2a shield init               # Full environment scan, policy generation, shell hooks
opena2a shield status             # View security posture across all products
opena2a shield log                # Query the tamper-evident event log
opena2a shield selfcheck          # Run integrity checks across all subsystems
opena2a shield policy             # Show loaded policy summary
opena2a shield evaluate <action>  # Evaluate an action against the active policy
opena2a shield recover            # Exit lockdown mode after incident resolution
opena2a shield report             # Generate a security posture report
opena2a shield monitor            # Continuous security monitoring daemon
opena2a shield session            # Show current AI coding assistant session identity
opena2a shield baseline           # View adaptive enforcement baselines for agents
opena2a shield suggest            # LLM-powered policy suggestions from observed behavior
opena2a shield explain            # LLM-powered anomaly explanations for events
opena2a shield triage             # LLM-powered incident classification and response
```

**Key flags:**

```bash
--analyze                         # Include LLM-powered analysis in reports
--forensic                        # Deep forensic mode for log/report
--since <time>                    # Filter events by time (e.g., "1h", "24h", "7d", "1w", "1m")
--severity <level>                # Filter by severity (info, warning, error, critical)
--ci                              # Machine-readable output for CI pipelines
--format json                     # JSON output
```

**Example workflow:**

```bash
opena2a shield init                      # One-command security setup
opena2a shield status                    # Check posture at a glance
opena2a shield report --analyze          # Full posture report with LLM analysis
opena2a shield log --since 1h            # Review recent security events
opena2a shield triage                    # Classify and prioritize open incidents
opena2a shield suggest                   # Get policy improvement recommendations
```

Shield stores events in a local tamper-evident log at `.opena2a/shield/events.jsonl` and policies at `.opena2a/shield/policy.yaml`. No network calls are made unless LLM-powered subcommands are explicitly invoked.

## Adapter Commands

The CLI orchestrates specialized tools through a unified interface. Each command maps to a standalone product that can also be used independently.

| Command | Product | Docs | Description |
|---------|---------|------|-------------|
| `opena2a scan` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | [docs](https://opena2a.org/docs/hackmyagent) | 150+ security checks, attack simulation, auto-fix |
| `opena2a secrets` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | [docs](https://opena2a.org/docs/secretless) | Credential management for AI coding tools |
| `opena2a broker` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | [docs](https://opena2a.org/docs/secretless) | Identity-aware credential broker daemon |
| `opena2a dlp` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | [docs](https://opena2a.org/docs/secretless) | Data loss prevention for AI tool transcripts |
| `opena2a identity` | [AIM](https://github.com/opena2a-org/agent-identity-management) | [docs](https://opena2a.org/docs/aim) | Agent identity and access management |
| `opena2a benchmark` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | [docs](https://opena2a.org/docs/oasb) | 222 attack scenarios, compliance scoring (OASB) |
| `opena2a registry` | [Trust Registry](https://registry.opena2a.org) | | Trust Registry queries, package verification |
| `opena2a train` | [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | [docs](https://opena2a.org/docs/dvaa) | Vulnerable AI agent for security training |
| `opena2a crypto` | [CryptoServe](https://github.com/ecolibria/crypto-serve) | [docs](https://opena2a.org/docs/cryptoserve) | Cryptographic inventory, PQC readiness |

Adapters install tools on first use. Each tool works standalone or through the CLI.

**Command-to-product mapping:**

| Product | CLI Commands |
|---------|-------------|
| [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | `scan`, `benchmark` |
| [Secretless AI](https://github.com/opena2a-org/secretless-ai) | `secrets`, `broker`, `dlp` |
| [AIM](https://github.com/opena2a-org/agent-identity-management) | `identity` |
| [Trust Registry](https://registry.opena2a.org) | `registry`, `verify` |
| [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | `train` |
| [CryptoServe](https://github.com/ecolibria/crypto-serve) | `crypto` |
| ConfigGuard (built-in) | `guard` |
| ARP (included in HackMyAgent) | `runtime` |
| Shield (built-in) | `shield`, `init`, `review` |
| Protect (built-in, Secretless for vault) | `protect` |

## [CI/CD Integration](https://opena2a.org/docs/cli/ci-cd)

All commands support `--format json` and `--ci` flags for pipeline integration:

```yaml
# GitHub Actions example
- name: Security assessment
  run: npx opena2a-cli init --ci --format json > security-report.json

- name: Credential check
  run: |
    npx opena2a-cli protect --dry-run --ci --format json > cred-report.json
    # Fail if credentials found
    jq -e '.totalFound == 0' cred-report.json

- name: Config integrity
  run: npx opena2a-cli guard verify --ci --enforce
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | `--format text` (default) | Human-readable terminal output |
| JSON | `--format json` | CI pipelines, programmatic consumption |
| SARIF | `--format sarif` | Static analysis results (shield report) |
| HTML | `--report <path>` | Interactive report with filtering (protect, review, shield report) |

## Architecture

```
opena2a CLI
  |
  +-- shield        Unified orchestration layer
  |     +-- init        11-step setup (secretless + aim-core + guard + policy + arp + ai-tools)
  |     +-- status      Unified product status view
  |     +-- log         Tamper-evident event log (SHA-256 hash chain)
  |     +-- report      Weekly security posture report
  |     +-- selfcheck   Integrity verification + self-healing
  |
  +-- init          Project assessment, trust scoring
  +-- protect       Credential detection + migration (vault via Secretless AI)
  +-- guard         Config file integrity (ConfigGuard)
  +-- review        Unified HTML security dashboard
  +-- runtime       Agent runtime protection (ARP)
  +-- verify        Binary integrity via Trust Registry
  +-- self-register Tool registration in Trust Registry
  +-- baselines     Behavioral observation collection
  +-- config        User preferences
  |
  +-- Adapters (install on first use)
       +-- scan      -> HackMyAgent
       +-- secrets   -> Secretless AI
       +-- broker    -> Secretless AI
       +-- dlp       -> Secretless AI
       +-- identity  -> AIM
       +-- benchmark -> HackMyAgent (OASB)
       +-- registry  -> Trust Registry
       +-- train     -> DVAA (Docker)
       +-- crypto    -> CryptoServe (Python)
```

## Credential Patterns

Detected credential types and their finding IDs:

| ID | Pattern | Severity |
|----|---------|----------|
| CRED-001 | Anthropic API Key (`sk-ant-api*`) | Critical |
| CRED-002 | OpenAI API Key (`sk-*`, `sk-proj-*`, `sk-test-*`) | Critical |
| CRED-003 | GitHub Token (`ghp_*`, `ghs_*`) | High |
| CRED-004 | Generic API Key in assignment | Medium |
| DRIFT-001 | Google API Key with Gemini drift (`AIza*`) | High |
| DRIFT-002 | AWS Access Key with Bedrock drift (`AKIA*`) | High |

Language-aware replacements:

| Language | Replacement |
|----------|-------------|
| JavaScript/TypeScript | `process.env.VAR_NAME` |
| Python | `os.environ.get('VAR_NAME')` |
| Go | `os.Getenv("VAR_NAME")` |
| Ruby | `ENV['VAR_NAME']` |
| Java/Kotlin | `System.getenv("VAR_NAME")` |
| Rust | `std::env::var("VAR_NAME").unwrap_or_default()` |
| YAML/TOML/JSON | `${VAR_NAME}` |

## Ecosystem

OpenA2A is a platform of specialized security tools, each usable standalone or through the CLI.

| Product | Install | Purpose |
|---------|---------|---------|
| [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | `npx hackmyagent secure` | Security scanner, attack simulation, benchmarks, runtime protection |
| [Secretless AI](https://github.com/opena2a-org/secretless-ai) | `npx secretless-ai init` | Credential management, broker, DLP for AI coding tools |
| [AIM](https://github.com/opena2a-org/agent-identity-management) | Self-hosted (Go) | Agent identity and access management |
| [AI Browser Guard](https://github.com/opena2a-org/ai-browser-guard) | Chrome Web Store | Browser extension for AI agent detection and control |
| [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | `docker pull opena2a/dvaa` | Deliberately vulnerable AI agent for security training |
| [Trust Registry](https://registry.opena2a.org) | `registry.opena2a.org` | Supply chain verification, trust scores, package metadata |

All products are open source under Apache-2.0.

## Upstream Contributions

We contribute security fixes back to the open-source projects we audit.

**[OpenClaw](https://github.com/openclaw/openclaw)** (245K+ stars) -- 8 security PRs (7 merged, 1 open):

- Credential redaction in gateway config responses ([#9858](https://github.com/open-webui/open-webui/pull/9858))
- Skill/plugin code safety scanner ([#9806](https://github.com/open-webui/open-webui/pull/9806))
- Path traversal prevention in file serving ([#10525](https://github.com/open-webui/open-webui/pull/10525))
- Security headers for gateway HTTP responses ([#10526](https://github.com/open-webui/open-webui/pull/10526))
- Timing-safe comparison for hook token auth ([#10527](https://github.com/open-webui/open-webui/pull/10527))
- Supply chain hardening with --ignore-scripts ([#10528](https://github.com/open-webui/open-webui/pull/10528))
- File permission enforcement for credential files ([#10529](https://github.com/open-webui/open-webui/pull/10529))
- Skill scanner false positive reduction ([#10530](https://github.com/open-webui/open-webui/pull/10530))

**[Nanobot](https://github.com/HKUDS/nanobot)** -- Path traversal, XSS, and shell escape fixes ([#472](https://github.com/HKUDS/nanobot/pull/472))

## License

Apache-2.0

---

<div align="center">

[Report an Issue](https://github.com/opena2a-org/opena2a/issues) | [Contribute](https://github.com/opena2a-org/opena2a/blob/main/CONTRIBUTING.md)

</div>

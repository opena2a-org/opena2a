<div align="center">

# opena2a-cli

**Open-source security platform for AI agents**

Credential detection, scope drift analysis, config integrity, runtime monitoring, behavioral governance scanning, and supply chain verification -- one CLI.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/opena2a-org/opena2a/blob/main/LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)]()
[![npm](https://img.shields.io/npm/v/opena2a-cli.svg)](https://www.npmjs.com/package/opena2a-cli)

[Website](https://opena2a.org) | [Docs](https://opena2a.org/docs) | [Registry](https://registry.opena2a.org) | [Discord](https://discord.gg/uRZa3KXgEn) | [GitHub](https://github.com/opena2a-org/opena2a)

</div>

---

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

Run `opena2a init` in any project directory to get an instant security assessment:

```
  OpenA2A Security Report  v0.4.0

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

## Scope Drift Detection

API keys provisioned for one service often silently grant access to others. A Google Maps key can call Gemini. An AWS S3 key may reach Bedrock.

OpenA2A detects these cross-service privilege escalations:

| Finding | What It Means |
|---------|---------------|
| **DRIFT-001** | Google API key can access Gemini AI models beyond intended Maps/Places scope |
| **DRIFT-002** | AWS access key can invoke Bedrock LLM models beyond intended S3/EC2 scope |

When drift is detected, `opena2a protect` migrates the key to environment variables and creates a deny-all broker policy so you can explicitly control which services each key is allowed to reach.

## Core Commands

### `opena2a init`

Assess your project's security posture. Detects project type, scans for credentials, checks hygiene (`.gitignore`, `.env` protection, lock file, security config), calculates a trust score (0-100), and provides prioritized next steps.

```bash
opena2a init                    # Assess current directory
opena2a init --dir ./my-agent   # Assess specific directory
opena2a init --verbose          # Show individual credential details
opena2a init --format json      # Machine-readable output for CI
```

### `opena2a protect`

Single command to fix all auto-fixable findings. Migrates credentials, fixes `.gitignore`, excludes AI config files from git, signs config files, and shows before/after security score.

```bash
opena2a protect                 # Fix everything fixable
opena2a protect --dry-run       # Preview changes without modifying files
opena2a protect --skip-sign     # Skip config signing phase
opena2a protect --skip-git      # Skip git hygiene fixes
opena2a protect --report out.html  # Generate interactive HTML report
opena2a protect --format json   # JSON output for CI pipelines
```

What protect fixes:
1. **Credentials** -- Detect, vault, and replace hardcoded secrets with env var references
2. **`.gitignore`** -- Create or update to exclude `.env` files
3. **AI config exclusion** -- Add `CLAUDE.md`, `.cursorrules`, etc. to `.git/info/exclude`
4. **Config signing** -- Sign config files for tamper detection
5. **Verification** -- Re-scan and show before/after security score

### `opena2a guard`

Config file integrity protection. Sign your config files and detect unauthorized modifications.

```bash
opena2a guard sign              # Sign all detected config files (SHA-256)
opena2a guard verify            # Check for tampering or unsigned files
opena2a guard status            # Show signature summary
```

Default files: `mcp.json`, `package.json`, `tsconfig.json`, `arp.yaml`, `go.mod`, `Dockerfile`, and more.

### `opena2a runtime`

Agent Runtime Protection (ARP) wrapper. Monitor process, network, and filesystem activity.

```bash
opena2a runtime init            # Generate arp.yaml for your project
opena2a runtime start           # Start monitoring
opena2a runtime status          # Show monitor/interceptor status
opena2a runtime tail            # View recent security events
```

### `opena2a verify`

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

### `opena2a review`

Run all security checks and generate a unified HTML dashboard. Combines credential scanning, config integrity, Shield posture, advisory checks, and optional HMA deep scan into a single interactive report.

```bash
opena2a review                     # Scan + open HTML report in browser
opena2a review --no-open           # Generate report without opening
opena2a review --report out.html   # Save to custom path
opena2a review --format json       # JSON output for CI
```

### `opena2a config`

Manage user preferences and feature toggles.

```bash
opena2a config show               # Display current configuration
opena2a config contribute on      # Enable community data sharing
opena2a config llm on             # Enable LLM-powered command matching
```

## Shield: Unified Security Orchestration

Shield ties all OpenA2A tools into a single security layer for AI coding assistants. It provides a tamper-evident event log, policy evaluation, runtime monitoring, session identification, integrity verification, and LLM-powered analysis.

```bash
opena2a shield init              # Full environment scan + policy generation
opena2a shield status            # Tool availability and integrity state
opena2a shield selfcheck         # Run integrity checks across all subsystems
```

### How Shield protects your workstation

| Capability | What it does | Status |
|-----------|-------------|--------|
| **Credential scanning** | Detects hardcoded API keys (Anthropic, OpenAI, AWS, Google, GitHub) | Active |
| **Scope drift detection** | Finds API keys that silently access unintended services (DRIFT-001, DRIFT-002) | Active |
| **Tamper-evident event log** | SHA-256 hash-chained event log -- any modification breaks the chain | Active |
| **Policy evaluation** | Allow/deny rules for processes, credentials, network, filesystem, MCP servers | Active |
| **Session identification** | Detects which AI assistant is running (Claude Code, Cursor, Copilot, Windsurf) | Active |
| **Config integrity** | Signs config files and detects unauthorized modifications | Active |
| **ARP bridge** | Imports runtime protection events from HackMyAgent's ARP into Shield's log | Active |
| **Posture scoring** | 0-100 security score based on active tools, policy, hooks, credentials | Active |
| **LLM intelligence** | AI-powered policy suggestions, anomaly explanations, incident triage | Active (opt-in) |
| **Integrity selfcheck** | Verifies policy, shell hooks, event chain, process, and artifact signatures | Active |
| **Lockdown mode** | Enters lockdown when integrity checks fail; requires explicit recovery | Active |
| **Adaptive baselines** | Learns per-agent behavior, tracks stability across sessions, suggests policies | Active |
| **Enforcement mode** | Shell hooks check policy in enforce mode and block denied commands | Active |
| **HTML posture report** | Interactive dark-theme HTML report with severity chart, filters, and agent activity | Active |

Shield operates in three modes:
- **Monitor** (default): Logs and surfaces security events for developer review.
- **Enforce**: Shell hooks call `opena2a shield evaluate` before each command. Denied commands are blocked with exit code 1.
- **Baseline learning**: Observes agent behavior across sessions and suggests policy rules when behavior stabilizes.

### Subcommands

#### `opena2a shield init`

Full environment scan: detects project type, scans for credentials, discovers AI assistants, MCP servers, and OAuth sessions, generates a YAML policy file, installs shell hooks, and writes a genesis event to the tamper-evident log.

```bash
opena2a shield init                    # Scan current directory
opena2a shield init --dir ./my-agent   # Scan specific directory
opena2a shield init --format json      # Machine-readable output
```

#### `opena2a shield status`

Shows tool availability, policy mode, shell integration, and integrity state.

```bash
opena2a shield status
opena2a shield status --format json
```

#### `opena2a shield log`

Query the tamper-evident event log with filters.

```bash
opena2a shield log                           # Last 20 events
opena2a shield log --count 50               # Last 50 events
opena2a shield log --severity high          # High+ severity only
opena2a shield log --source arp             # ARP runtime events
opena2a shield log --agent claude-code      # Events from Claude Code
opena2a shield log --since 7d              # Last 7 days
opena2a shield log --format json           # JSON output
```

#### `opena2a shield selfcheck`

Runs five integrity checks: policy hash, shell hook content, event chain validity, process binary, and artifact signatures. Returns `healthy`, `degraded`, or `compromised` status.

```bash
opena2a shield selfcheck
opena2a shield check                    # Alias
opena2a shield selfcheck --format json
```

#### `opena2a shield policy`

Show the loaded security policy (mode, rule counts, agent overrides).

```bash
opena2a shield policy
opena2a shield policy --format json
```

#### `opena2a shield evaluate`

Evaluate an action against the loaded policy. Returns `ALLOWED`, `BLOCKED`, or `MONITORED`. In enforce mode, shell hooks call this before every command and block denied actions.

```bash
opena2a shield evaluate --category processes --agent claude-code
opena2a shield evaluate "curl evil.com"    # Evaluate a command string
opena2a shield evaluate --format json
```

#### `opena2a shield monitor`

Import ARP (Agent Runtime Protection) events into Shield's hash-chained log and display runtime stats.

```bash
opena2a shield monitor                      # Import events + show stats
opena2a shield monitor --agent cursor       # Tag imported events
opena2a shield monitor --since 7d          # Stats for last 7 days
opena2a shield monitor --format json
```

#### `opena2a shield report`

Generate a security posture report from event data. Includes severity breakdown, agent activity, policy violations, and top actions. Supports interactive HTML output.

```bash
opena2a shield report                       # Last 7 days (text)
opena2a shield report --report posture.html # Interactive HTML report
opena2a shield report --since 30d          # Last 30 days
opena2a shield report --analyze            # Include LLM narrative
opena2a shield report --format json
```

#### `opena2a shield session`

Detect the current AI coding assistant session. Identifies Claude Code, Cursor, GitHub Copilot, Windsurf, Aider, and Continue.

```bash
opena2a shield session
opena2a shield session --verbose            # Show raw detection signals
opena2a shield session --format json
```

#### `opena2a shield recover`

Exit lockdown mode after integrity failures. Optionally re-verify before lifting lockdown.

```bash
opena2a shield recover                      # Exit lockdown
opena2a shield recover --verify             # Verify first, then exit
```

#### `opena2a shield suggest`

LLM-powered policy suggestion based on observed agent behavior. Requires LLM backend (enable with `opena2a config llm on`).

```bash
opena2a shield suggest                      # Suggest policy from all events
opena2a shield suggest --agent cursor       # For specific agent
opena2a shield suggest --format json
```

#### `opena2a shield explain`

LLM-powered explanation of security events. Provides severity assessment, risk factors, and recommended actions.

```bash
opena2a shield explain                      # Explain most recent event
opena2a shield explain --count 5           # Explain last 5 events
opena2a shield explain --severity high     # High+ severity only
```

#### `opena2a shield triage`

LLM-powered incident classification. Correlates multiple events and classifies as false-positive, suspicious, or confirmed-threat.

```bash
opena2a shield triage                       # Triage high+ severity events
opena2a shield triage --severity medium    # Include medium severity
opena2a shield triage --agent windsurf     # For specific agent
```

#### `opena2a shield baseline`

Manage per-agent behavioral baselines. Baselines track observed actions across sessions and compute stability scores to determine when behavior has converged enough to generate policy recommendations.

```bash
opena2a shield baseline                    # List all baselines
opena2a shield baseline claude-code        # Show detail for specific agent
opena2a shield baseline --format json
```

Phases: **learning** (collecting observations) -> **stabilizing** (fewer new behaviors) -> **stable** (ready for policy generation). Stability is measured as the fraction of recent sessions with no previously-unseen behavior.

### CI Integration

Shield includes a GitHub Actions workflow for automated security checks on every PR.

```bash
# Copy the example workflow to your project
cp node_modules/opena2a-cli/examples/github-actions-shield.yml .github/workflows/shield.yml
```

See `examples/github-actions-shield.yml` for a minimal copy-paste-ready workflow, or `.github/workflows/shield-check.yml` for the full implementation with PR comment integration.

### Event Log Format

Shield maintains a tamper-evident event log. Events are stored in the project-local `.opena2a/shield/events.jsonl` when available, falling back to `~/.opena2a/shield/events.jsonl`. Each event is SHA-256 hash-chained to the previous event, starting from a genesis hash. Any modification to a past event breaks the chain and is detected by `selfcheck`.

```
[2026-03-02T12:00:00Z] [HIGH] process.anomaly -> curl evil.com (monitored)
[2026-03-02T12:01:00Z] [CRITICAL] prompt.threat -> injection-attempt (blocked)
[2026-03-02T12:02:00Z] [INFO] process.spawn -> /usr/bin/ls (allowed)
```

### Quick Start

```bash
# 1. Initialize Shield in your project
opena2a shield init

# 2. Check what AI assistants are running
opena2a shield session

# 3. View security events
opena2a shield log --severity medium

# 4. Generate a posture report
opena2a shield report

# 5. Run integrity verification
opena2a shield selfcheck
```

## Smart Input Modes

The CLI includes built-in intelligence for command discovery:

```bash
opena2a                           # Interactive guided wizard
opena2a ~drift                    # Semantic search (finds protect, init)
opena2a ~api keys                 # Semantic search with domain expansion
opena2a ?                         # Context-aware recommendations
opena2a find leaked credentials   # Natural language matching
opena2a detect hardcoded secrets  # Natural language matching
```

Semantic search uses a weighted index of tags, synonyms, and domains -- no API calls required. Natural language mode falls back to Claude Haiku when static matching is insufficient (opt-in, costs ~$0.0002 per query).

## Adapter Commands

The CLI orchestrates these specialized tools through a unified interface:

| Command | Tool | Description |
|---------|------|-------------|
| `opena2a scan` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | 150+ security checks, attack simulation, auto-fix |
| `opena2a scan-soul` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | Behavioral governance scan against AGS (SOUL.md) |
| `opena2a harden-soul` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | Generate or improve SOUL.md governance file |
| `opena2a secrets` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Credential management for AI coding tools |
| `opena2a benchmark` | [OASB](https://github.com/opena2a-org/oasb) | 222 attack scenarios, compliance scoring |
| `opena2a registry` | [AI Trust](https://github.com/opena2a-org/ai-trust) | Trust Registry queries, package verification |
| `opena2a train` | [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Vulnerable AI agent for training |
| `opena2a crypto` | [CryptoServe](https://github.com/ecolibria/crypto-serve) | Cryptographic inventory, PQC readiness |
| `opena2a identity` | [AIM](https://github.com/opena2a-org/agent-identity-management) | Agent identity management |
| `opena2a broker` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Identity-aware credential broker daemon |
| `opena2a dlp` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Data loss prevention for AI tool transcripts |

Adapters install tools on first use. Each tool works standalone or through the CLI.

## Behavioral Governance

The [Agent Governance Specification (AGS)](https://github.com/opena2a-org/agent-governance-spec) defines a tiered behavioral safety framework for AI agents across 8 domains and 68 controls (OASB v2). OpenA2A CLI integrates AGS scanning through HackMyAgent.

### `opena2a scan-soul`

Scan your governance file (SOUL.md or equivalent) against AGS controls for your agent's capability tier. Auto-detects tier from file content.

```bash
opena2a scan-soul                          # Scan SOUL.md in current directory
opena2a scan-soul ./agent/                 # Scan specific directory
opena2a scan-soul --tier TOOL-USING        # Force TOOL-USING tier (54 controls)
opena2a scan-soul --tier AGENTIC           # Force AGENTIC tier (65 controls)
opena2a scan-soul --tier MULTI-AGENT       # Force MULTI-AGENT tier (68 controls)
opena2a scan-soul --json                   # Machine-readable output for CI
opena2a scan-soul --deep                   # Enable LLM semantic analysis (requires ANTHROPIC_API_KEY)
opena2a scan-soul --fail-below 60          # Exit 1 if score below threshold
```

Tier-to-control mapping:

| Tier | Controls | Use Case |
|------|----------|----------|
| `BASIC` | 27 | Single-turn chatbots, no tool use |
| `TOOL-USING` | 54 | Agents with tool/function calling |
| `AGENTIC` | 65 | Long-running, multi-step autonomous agents |
| `MULTI-AGENT` | 68 | Orchestrators and sub-agent systems |

Governance file search order: `SOUL.md` > `system-prompt.md` > `CLAUDE.md` > `.cursorrules` > `agent-config.yaml` (and more).

Conformance levels shown in output:
- `none` — a critical control is missing (grade capped at C)
- `essential` — all critical controls pass
- `standard` — all critical + high controls pass, score ≥ 60
- `hardened` — all controls pass, score ≥ 75

### `opena2a harden-soul`

Generate a SOUL.md governance file, or add missing sections to an existing one. Existing content is always preserved.

```bash
opena2a harden-soul                # Add missing sections to SOUL.md
opena2a harden-soul ./agent/       # Target specific directory
opena2a harden-soul --dry-run      # Preview what would be added, no writes
opena2a harden-soul --json         # Machine-readable output
```

The 8 AGS behavioral domains (OASB v2, domains 7–14):

| Domain | What it governs |
|--------|----------------|
| Trust Hierarchy | Principal relationships, conflict resolution |
| Capability Boundaries | Allowed/denied actions, least privilege |
| Injection Hardening | Prompt injection defense, encoded payload rejection |
| Data Handling | PII protection, credential handling, data minimization |
| Hardcoded Behaviors | Immutable safety rules (no exfiltration, kill switch) |
| Agentic Safety | Iteration limits, budget caps, rollback, plan disclosure |
| Honesty and Transparency | Uncertainty acknowledgment, identity disclosure |
| Human Oversight | Approval gates, override mechanisms, monitoring |

## CI/CD Integration

Several commands support `--json` output and `--fail-below` for pipeline gates:

```yaml
# GitHub Actions example
- name: Credential check
  run: |
    npx opena2a-cli protect --dry-run --json > cred-report.json
    jq -e '.totalFound == 0' cred-report.json

- name: Behavioral governance gate
  run: npx opena2a-cli scan-soul --json --fail-below 60

- name: Config integrity
  run: npx opena2a-cli guard verify
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | (default) | Human-readable terminal output |
| JSON | `--json` | CI pipelines, programmatic consumption |
| HTML | `--report <path>` | Interactive report (protect and shield commands) |

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

## Requirements

- Node.js >= 18
- Optional: Docker (for `opena2a train`)
- Optional: Python 3.9+ (for `opena2a crypto`)

## License

Apache-2.0

---

<div align="center">

[Report an Issue](https://github.com/opena2a-org/opena2a/issues) | [Contribute](https://github.com/opena2a-org/opena2a/blob/main/CONTRIBUTING.md)

</div>

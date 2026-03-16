# opena2a

Open-source security platform for AI agents. Detect shadow AI, manage identity, enforce governance, scan for vulnerabilities, and protect credentials.

## Quick Start

```bash
npx opena2a-cli review
```

```
  OpenA2A Security Review  v0.7.2

  Project      myapp v2.1.0
  Type         Node.js + MCP server
  Directory    /home/user/myapp

  Findings
  -----------------------------------------------
  Credential scan        3 hardcoded keys
  Shadow AI              2 agents, 4 MCP servers
  Config integrity       unsigned
  Governance             no SOUL.md
  -----------------------------------------------
  Security Score   30 / 100  -> 85 by running opena2a protect

  Run: opena2a protect    (fix all findings)
```

Install globally if you prefer:

```bash
npm install -g opena2a-cli          # npm
brew tap opena2a-org/tap && brew install opena2a   # Homebrew
```

## What It Does

**Shadow AI Detection** -- Find every AI agent and MCP server in your environment.

```bash
opena2a detect          # -> 2 agents, 4 MCP servers, governance score 45/100
```

**Security Scanning** -- 163 checks for credentials, injection, MCP misconfigurations.

```bash
opena2a scan            # -> 12 findings (3 critical, 5 high, 4 medium)
```

**Credential Protection** -- Migrate hardcoded secrets to environment variables.

```bash
opena2a protect         # -> 3 credentials migrated, score 30 -> 85
```

## Built-in Help

You do not need this README to use opena2a. The CLI has built-in discovery:

```bash
opena2a ?                           # Context-aware recommendations for your project
opena2a ~shadow ai                  # Semantic search across all commands
opena2a "find leaked credentials"   # Natural language command matching
opena2a                             # Interactive guided wizard (no args)
```

Semantic search uses a local weighted index -- no API calls required. Natural language mode falls back to Claude Haiku when static matching is insufficient (opt-in via `opena2a config llm on`, costs ~$0.0002 per query).

## Use Cases

- [Developer using AI coding tools](../../docs/use-cases/developer.md)
- [Security team assessing AI risk](../../docs/use-cases/security-team.md)
- [MCP server author](../../docs/use-cases/mcp-server-author.md)
- [CI/CD pipeline integration](../../docs/use-cases/ci-cd.md)

## Commands

### Shadow AI Detection

| Command | Description |
|---------|-------------|
| `opena2a detect` | Discover AI agents, MCP servers, and AI configs on this machine |
| `opena2a detect --report` | Generate HTML executive report |
| `opena2a detect --export-csv assets.csv` | Export asset inventory for CMDB |

### Security Assessment

| Command | Description |
|---------|-------------|
| `opena2a review` | Full security review with interactive HTML dashboard (6 tabs) |
| `opena2a init` | Read-only security assessment with trust score |
| `opena2a protect` | Fix all findings: credentials, .gitignore, config signing |
| `opena2a protect --dry-run` | Preview changes without modifying files |

### Behavioral Governance

| Command | Description |
|---------|-------------|
| `opena2a scan-soul` | Scan SOUL.md against ABGS controls (27-68 checks by tier) |
| `opena2a harden-soul` | Generate or improve SOUL.md governance file |
| `opena2a scan-soul --deep` | LLM semantic analysis (requires ANTHROPIC_API_KEY) |
| `opena2a scan-soul --fail-below 60` | CI gate: exit 1 if score below threshold |

### Config and Runtime Protection

| Command | Description |
|---------|-------------|
| `opena2a guard sign` | Sign config files (SHA-256 integrity) |
| `opena2a guard verify` | Check for tampering or unsigned files |
| `opena2a runtime init` | Generate arp.yaml for runtime monitoring |
| `opena2a runtime start` | Start process/network/filesystem monitoring |

### Identity and Trust

| Command | Description |
|---------|-------------|
| `opena2a trust express` | Look up trust profile for an npm package |
| `opena2a trust --source pypi langchain` | Look up PyPI package |
| `opena2a claim my-agent` | Claim agent ownership via npm/GitHub verification |
| `opena2a identity list` | Show local Ed25519 agent identity |
| `opena2a identity trust` | Calculate trust score with factor breakdown |
| `opena2a verify` | Binary integrity check against Trust Registry |

### Shield: Security Orchestration

| Command | Description |
|---------|-------------|
| `opena2a shield init` | Full environment scan + policy generation + shell hooks |
| `opena2a shield status` | Tool availability and integrity state |
| `opena2a shield selfcheck` | Run integrity checks across all subsystems |
| `opena2a shield log` | Query tamper-evident event log |
| `opena2a shield report` | Generate security posture report (text or HTML) |
| `opena2a shield evaluate` | Evaluate an action against loaded policy |
| `opena2a shield session` | Detect current AI coding assistant |
| `opena2a shield baseline` | View per-agent behavioral baselines |

### Adapter Commands

These route to specialized tools, installed on first use:

| Command | Tool | Description |
|---------|------|-------------|
| `opena2a scan` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | 163 security checks, attack simulation, auto-fix |
| `opena2a secrets` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Credential management for AI coding tools |
| `opena2a broker` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Identity-aware credential broker daemon |
| `opena2a dlp` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Data loss prevention for AI transcripts |
| `opena2a benchmark` | [OASB](https://github.com/opena2a-org/oasb) | 222 attack scenarios, compliance scoring |
| `opena2a registry` | [AI Trust](https://github.com/opena2a-org/ai-trust) | Trust Registry queries, package verification |
| `opena2a train` | [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Vulnerable AI agent for training |
| `opena2a crypto` | [CryptoServe](https://github.com/ecolibria/crypto-serve) | Cryptographic inventory, PQC readiness |
| `opena2a identity` | [AIM](https://github.com/opena2a-org/agent-identity-management) | Agent identity management |

---

## Detailed Reference

### `opena2a review`

Run all security checks and generate a unified HTML dashboard. Combines credential scanning, config integrity, Shield posture, shadow AI detection, advisory checks, and optional HMA deep scan into a single interactive report with 6 tabs.

```bash
opena2a review                     # Scan + open HTML report in browser
opena2a review --no-open           # Generate report without opening
opena2a review --report out.html   # Save to custom path
opena2a review --format json       # JSON output for CI
```

### `opena2a detect`

Reports a governance score (0-100, where 100 = fully governed) with actionable findings.

What detect finds:
- **Running AI agents**: Claude Code, Cursor, GitHub Copilot, Windsurf, Aider, Ollama, LM Studio, and more
- **MCP servers**: Project-local and machine-wide configurations across Claude, Cursor, Windsurf, Cline, and VS Code
- **AI config files**: `.cursorrules`, `CLAUDE.md`, `.copilot`, `.windsurfrules`, and framework configs
- **Governance posture**: AIM identity, SOUL.md behavioral rules, capability policies

```bash
opena2a detect                              # Scan current project
opena2a detect --report                     # Generate HTML executive report
opena2a detect --export-csv assets.csv      # Export asset inventory for CMDB
opena2a detect --format json                # Machine-readable output
opena2a detect --verbose                    # Show full MCP server list and PIDs
```

The CSV export includes hostname, username, scan directory, and timestamp on every row for enterprise CMDB import.

### `opena2a init`

Read-only assessment. Detects project type (Node.js, Python, Go), scans for credentials, checks hygiene (.gitignore, .env protection, lock file, security config, MCP config), calculates a trust score (0-100), and provides prioritized next steps. Does not modify any files.

```bash
opena2a init                    # Assess current directory
opena2a init --dir ./my-agent   # Assess specific directory
opena2a init --verbose          # Show individual credential details
opena2a init --format json      # Machine-readable output for CI
```

### `opena2a protect`

Single command to fix all auto-fixable findings:

1. **Credentials** -- Detect, vault, and replace hardcoded secrets with env var references
2. **`.gitignore`** -- Create or update to exclude `.env` files
3. **AI config exclusion** -- Add `CLAUDE.md`, `.cursorrules`, etc. to `.git/info/exclude`
4. **Config signing** -- Sign config files for tamper detection
5. **Verification** -- Re-scan and show before/after security score

```bash
opena2a protect                 # Fix everything fixable
opena2a protect --dry-run       # Preview changes without modifying files
opena2a protect --skip-sign     # Skip config signing phase
opena2a protect --skip-git      # Skip git hygiene fixes
opena2a protect --report out.html  # Generate interactive HTML report
opena2a protect --format json   # JSON output for CI pipelines
```

### Scope Drift Detection

API keys provisioned for one service often silently grant access to others. A Google Maps key can call Gemini. An AWS S3 key may reach Bedrock.

| Finding | What It Means |
|---------|---------------|
| **DRIFT-001** | Google API key can access Gemini AI models beyond intended Maps/Places scope |
| **DRIFT-002** | AWS access key can invoke Bedrock LLM models beyond intended S3/EC2 scope |

When drift is detected, `opena2a protect` migrates the key to environment variables and creates a deny-all broker policy so you can explicitly control which services each key is allowed to reach.

### Behavioral Governance (ABGS)

The [Agent Behavioral Governance Specification (ABGS)](https://github.com/opena2a-org/agent-governance-spec) defines a tiered behavioral safety framework for AI agents across 8 domains and 68 controls (OASB v2).

```bash
opena2a scan-soul                          # Scan SOUL.md in current directory
opena2a scan-soul ./agent/                 # Scan specific directory
opena2a scan-soul --tier TOOL-USING        # Force tier (27/54/65/68 controls)
opena2a scan-soul --json                   # Machine-readable output for CI
opena2a scan-soul --deep                   # LLM semantic analysis
opena2a scan-soul --fail-below 60          # CI gate

opena2a harden-soul                        # Add missing sections to SOUL.md
opena2a harden-soul --dry-run              # Preview without writing
```

| Tier | Controls | Use Case |
|------|----------|----------|
| `BASIC` | 27 | Single-turn chatbots, no tool use |
| `TOOL-USING` | 54 | Agents with tool/function calling |
| `AGENTIC` | 65 | Long-running, multi-step autonomous agents |
| `MULTI-AGENT` | 68 | Orchestrators and sub-agent systems |

The 8 ABGS domains: Trust Hierarchy, Capability Boundaries, Injection Hardening, Data Handling, Hardcoded Behaviors, Agentic Safety, Honesty and Transparency, Human Oversight.

### Shield Subcommands

Shield ties all OpenA2A tools into a single security layer. It provides a tamper-evident event log, policy evaluation, runtime monitoring, session identification, integrity verification, and LLM-powered analysis.

| Capability | What it does |
|-----------|-------------|
| **Credential scanning** | Detects hardcoded API keys (Anthropic, OpenAI, AWS, Google, GitHub) |
| **Scope drift detection** | Finds API keys that silently access unintended services |
| **Tamper-evident event log** | SHA-256 hash-chained log -- any modification breaks the chain |
| **Policy evaluation** | Allow/deny rules for processes, credentials, network, filesystem, MCP servers |
| **Session identification** | Detects which AI assistant is running |
| **Config integrity** | Signs config files and detects unauthorized modifications |
| **Posture scoring** | 0-100 security score based on active tools, policy, hooks, credentials |
| **LLM intelligence** | AI-powered policy suggestions, anomaly explanations, incident triage (opt-in) |
| **Lockdown mode** | Enters lockdown when integrity checks fail; requires explicit recovery |
| **Adaptive baselines** | Learns per-agent behavior, tracks stability, suggests policies |
| **Enforcement mode** | Shell hooks block denied commands (exit code 1) |

Shield operates in three modes: **Monitor** (default, logs events), **Enforce** (blocks denied commands), and **Baseline learning** (observes behavior, suggests policies).

```bash
opena2a shield init                        # Full scan + policy + shell hooks
opena2a shield status                      # Tool availability and integrity
opena2a shield selfcheck                   # Five integrity checks
opena2a shield log                         # Last 20 events
opena2a shield log --severity high         # Filter by severity
opena2a shield log --agent claude-code     # Filter by agent
opena2a shield log --since 7d             # Filter by time
opena2a shield report                      # Posture report (text)
opena2a shield report --report posture.html  # Interactive HTML report
opena2a shield report --analyze            # Include LLM narrative
opena2a shield evaluate "curl evil.com"    # Evaluate command against policy
opena2a shield session                     # Detect AI assistant session
opena2a shield session --verbose           # Show raw detection signals
opena2a shield baseline                    # List per-agent baselines
opena2a shield suggest                     # LLM-powered policy suggestions
opena2a shield explain                     # LLM-powered event explanation
opena2a shield triage                      # LLM-powered incident classification
opena2a shield recover                     # Exit lockdown mode
opena2a shield policy                      # Show loaded security policy
opena2a shield monitor                     # Import ARP events into log
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Security review
  run: npx opena2a-cli review --format json

- name: Credential check
  run: |
    npx opena2a-cli protect --dry-run --json > cred-report.json
    jq -e '.totalFound == 0' cred-report.json

- name: Behavioral governance gate
  run: npx opena2a-cli scan-soul --json --fail-below 60

- name: Config integrity
  run: npx opena2a-cli guard verify
```

A copy-paste-ready GitHub Actions workflow is included at `examples/github-actions-shield.yml`.

### Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | (default) | Human-readable terminal output |
| JSON | `--json` | CI pipelines, programmatic consumption |
| HTML | `--report <path>` | Interactive report (protect and shield commands) |

### Credential Patterns

| ID | Pattern | Severity |
|----|---------|----------|
| CRED-001 | Anthropic API Key (`sk-ant-api*`) | Critical |
| CRED-002 | OpenAI API Key (`sk-*`, `sk-proj-*`, `sk-test-*`) | Critical |
| CRED-003 | GitHub Token (`ghp_*`, `ghs_*`) | High |
| CRED-004 | Generic API Key in assignment | Medium |
| DRIFT-001 | Google API Key with Gemini drift (`AIza*`) | High |
| DRIFT-002 | AWS Access Key with Bedrock drift (`AKIA*`) | High |

Language-aware replacements: JavaScript (`process.env.VAR`), Python (`os.environ.get('VAR')`), Go (`os.Getenv("VAR")`), Ruby (`ENV['VAR']`), Java/Kotlin (`System.getenv("VAR")`), Rust (`std::env::var("VAR")`), YAML/TOML/JSON (`${VAR}`).

## Requirements

- Node.js >= 18
- Optional: Docker (for `opena2a train`)
- Optional: Python 3.9+ (for `opena2a crypto`)

## License

Apache-2.0

---

<div align="center">

[Website](https://opena2a.org) | [Docs](https://opena2a.org/docs) | [Discord](https://discord.gg/uRZa3KXgEn) | [GitHub](https://github.com/opena2a-org/opena2a)

[Report an Issue](https://github.com/opena2a-org/opena2a/issues) | [Contribute](https://github.com/opena2a-org/opena2a/blob/main/CONTRIBUTING.md)

</div>

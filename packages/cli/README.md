<div align="center">

# opena2a-cli

**Open-source security platform for AI agents**

Credential detection, scope drift analysis, config integrity, runtime monitoring, and supply chain verification -- one CLI.

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
  OpenA2A Security Initialization  v0.1.0

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
  -----------------------------------------------
  Trust Score      30 / 100  [Grade: F]

  Next Steps
  -----------------------------------------------
  [CRITICAL]     Migrate 3 hardcoded credentials
                 opena2a protect

  [HIGH]         Add .env to .gitignore
                 echo '.env' >> .gitignore

  [MEDIUM]       Sign config files for integrity
                 opena2a guard sign
  -----------------------------------------------

  Scope Drift Detected
  -----------------------------------------------
  DRIFT-001 Google Maps key may access Gemini AI
    src/config.js:5

  Scope drift: keys provisioned for one service silently
  gain access to AI services, expanding attack surface.
  Run: opena2a protect
```

Then fix what it finds:

```bash
opena2a protect       # Migrate credentials to env vars + vault
opena2a guard sign    # Sign config files for tamper detection
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

Detect hardcoded credentials and migrate them to environment variables. Supports Anthropic, OpenAI, Google, AWS, GitHub, and generic API key patterns. Language-aware replacements for JS/TS, Python, Go, Ruby, Java, and Rust.

```bash
opena2a protect                 # Scan and migrate credentials
opena2a protect --dry-run       # Preview changes without modifying files
opena2a protect --report out.html  # Generate interactive HTML report
opena2a protect --format json   # JSON output for CI pipelines
```

Migration flow:
1. **Detect** -- Regex-based pattern matching across all source files
2. **Store** -- Save credential values in Secretless vault (or `.env` fallback with 0600 permissions)
3. **Replace** -- Swap hardcoded values with language-appropriate env var references
4. **Verify** -- Re-scan to confirm all credentials are removed from source

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

### `opena2a config`

Manage user preferences and feature toggles.

```bash
opena2a config show               # Display current configuration
opena2a config contribute on      # Enable community data sharing
opena2a config llm on             # Enable LLM-powered command matching
```

## Smart Input Modes

The CLI includes built-in intelligence for command discovery:

```bash
opena2a                           # Interactive guided wizard
opena2a ~drift                    # Semantic search (finds protect, init)
opena2a ~api keys                 # Semantic search with domain expansion
opena2a ?                         # Context-aware recommendations
opena2a "find leaked credentials" # Natural language matching
```

Semantic search uses a weighted index of tags, synonyms, and domains -- no API calls required. Natural language mode falls back to Claude Haiku when static matching is insufficient (opt-in, costs ~$0.0002 per query).

## Adapter Commands

The CLI orchestrates these specialized tools through a unified interface:

| Command | Tool | Description |
|---------|------|-------------|
| `opena2a scan` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | 150+ security checks, attack simulation, auto-fix |
| `opena2a secrets` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Credential management for AI coding tools |
| `opena2a benchmark` | [OASB](https://github.com/opena2a-org/oasb) | 222 attack scenarios, compliance scoring |
| `opena2a registry` | [AI Trust](https://github.com/opena2a-org/ai-trust) | Trust Registry queries, package verification |
| `opena2a train` | [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Vulnerable AI agent for training |
| `opena2a crypto` | [CryptoServe](https://github.com/ecolibria/crypto-serve) | Cryptographic inventory, PQC readiness |
| `opena2a identity` | [AIM](https://github.com/opena2a-org/agent-identity-management) | Agent identity management |
| `opena2a broker` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Identity-aware credential broker daemon |
| `opena2a dlp` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Data loss prevention for AI tool transcripts |

Adapters install tools on first use. Each tool works standalone or through the CLI.

## CI/CD Integration

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
  run: npx opena2a-cli guard verify --ci
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | `--format text` (default) | Human-readable terminal output |
| JSON | `--format json` | CI pipelines, programmatic consumption |
| HTML | `--report <path>` | Interactive report with filtering (protect command) |

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

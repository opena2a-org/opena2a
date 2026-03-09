> **[OpenA2A](https://github.com/opena2a-org)**: [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless AI](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [ARP](https://github.com/opena2a-org/hackmyagent) · [OASB](https://github.com/opena2a-org/hackmyagent) · [AGS](https://github.com/opena2a-org/hackmyagent) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) · [Browser Guard](https://github.com/opena2a-org/ai-browserguard) · [Registry](https://registry.opena2a.org)

<div align="center">

# OpenA2A CLI

**One CLI for all OpenA2A security tools**

Scan, protect, benchmark, and monitor AI agents from a single command.
This is the unified entry point to the entire [OpenA2A](https://github.com/opena2a-org) ecosystem.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)]()

[Website](https://opena2a.org) | [Docs](https://opena2a.org/docs) | [Registry](https://registry.opena2a.org) | [Discord](https://discord.gg/uRZa3KXgEn)

</div>

---

## What's Behind the CLI

Every OpenA2A project is accessible through `opena2a <command>`. Each tool also works standalone.

```
┌─────────────────────────────────────────────────────────────────┐
│                    opena2a-cli  (you are here)                  │
│                    npm install -g opena2a-cli                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  opena2a scan / benchmark  → HackMyAgent  (security scanner)   │
│  opena2a secrets / broker  → Secretless AI (credential mgmt)   │
│  opena2a identity          → AIM  (agent identity & access)    │
│  opena2a runtime           → ARP  (runtime protection)         │
│  opena2a scan-soul         → AGS  (behavioral governance)      │
│  opena2a benchmark oasb-2  → OASB (compliance benchmarks)      │
│  opena2a train             → DVAA (vulnerable agent training)  │
│                                                                 │
│  opena2a shield init       → All of the above, one command     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| CLI Command | Tool | Description |
|-------------|------|-------------|
| `scan`, `benchmark` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | 150+ security checks, OASB benchmarks, attack simulation |
| `secrets`, `broker`, `dlp` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Credential management for Claude Code, Cursor, Windsurf |
| `identity` | [AIM](https://github.com/opena2a-org/agent-identity-management) | Ed25519 keypairs, capability policies, audit logging |
| `runtime` | ARP ([in HMA](https://github.com/opena2a-org/hackmyagent)) | Process, network, filesystem monitoring |
| `scan-soul`, `harden-soul` | AGS ([in HMA](https://github.com/opena2a-org/hackmyagent)) | Behavioral governance — SOUL.md, 68 controls |
| `benchmark oasb-2` | OASB ([in HMA](https://github.com/opena2a-org/hackmyagent)) | 222 test scenarios, compliance scoring |
| `train` | [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Deliberately vulnerable AI agents for training |
| `guard` | ConfigGuard (built-in) | Config file integrity, SHA-256 signing |
| `shield` | Shield (built-in) | Unified orchestration across all tools |

Adapters install tools on first use — no manual setup required.

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

**Requirements:** Node.js >= 18. Optional: Docker (for `opena2a train`), Python 3.9+ (for `opena2a crypto`).

## Quick Start

### 1. Assess your project

```bash
opena2a init
```

<p align="center">
  <img src="docs/vhs/init.gif" alt="opena2a init demo" width="700" />
</p>

### 2. Fix everything

```bash
opena2a protect
```

<p align="center">
  <img src="docs/vhs/protect.gif" alt="opena2a protect demo" width="700" />
</p>

### 3. Full security setup

```bash
opena2a shield init
```

<p align="center">
  <img src="docs/vhs/shield-init.gif" alt="opena2a shield init demo" width="700" />
</p>

One command sets up credential protection, agent identity, config integrity, runtime monitoring, and AI tool configuration.

<p align="center">
  <img src="docs/vhs/shield-status.gif" alt="opena2a shield status demo" width="700" />
</p>

## Commands

### Built-in

| Command | What It Does | [Docs](https://opena2a.org/docs) |
|---------|-------------|------|
| [`init`](https://opena2a.org/docs/cli/commands/init) | Assess security posture, calculate trust score (0-100), prioritize next steps | [docs](https://opena2a.org/docs/cli/commands/init) |
| [`protect`](https://opena2a.org/docs/cli/commands/protect) | Fix all auto-fixable findings — credentials, .gitignore, config signing | [docs](https://opena2a.org/docs/cli/commands/protect) |
| [`guard`](https://opena2a.org/docs/cli/commands/guard) | Config file integrity — sign, verify, watch, diff, policy, pre-commit hooks | [docs](https://opena2a.org/docs/cli/commands/guard) |
| [`shield`](https://opena2a.org/docs/cli/commands/shield) | Unified orchestration — init, status, log, report, monitor, triage | [docs](https://opena2a.org/docs/cli/commands/shield) |
| [`review`](https://opena2a.org/docs/cli/commands/review) | Unified HTML security dashboard with composite score | [docs](https://opena2a.org/docs/cli/commands/review) |
| [`runtime`](https://opena2a.org/docs/cli/commands/runtime) | Agent Runtime Protection (ARP) — process, network, filesystem monitoring | [docs](https://opena2a.org/docs/cli/commands/runtime) |
| [`verify`](https://opena2a.org/docs/cli/commands/verify) | Binary integrity verification against Trust Registry | [docs](https://opena2a.org/docs/cli/commands/verify) |
| `config` | Manage user preferences and feature toggles | |
| `baselines` | Behavioral observation collection for crowdsourced agent profiles | |

### Adapters (install tools on first use)

| Command | Tool | [Docs](https://opena2a.org/docs) |
|---------|------|------|
| `scan` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) — 150+ security checks, attack simulation | [docs](https://opena2a.org/docs/hackmyagent) |
| `benchmark` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) — OASB-1 + OASB-2 compliance scoring | [docs](https://opena2a.org/docs/oasb) |
| `scan-soul` / `harden-soul` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) — AGS behavioral governance, 68 controls | [docs](https://opena2a.org/docs/hackmyagent) |
| `secrets` / `broker` / `dlp` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) — credential management for AI dev tools | [docs](https://opena2a.org/docs/secretless) |
| `identity` | [AIM](https://github.com/opena2a-org/agent-identity-management) — agent identity and access management | [docs](https://opena2a.org/docs/aim) |
| `train` | [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) — vulnerable AI agent for security training | [docs](https://opena2a.org/docs/dvaa) |
| `registry` | [Trust Registry](https://registry.opena2a.org) — package verification and trust scores | |
| `crypto` | [CryptoServe](https://github.com/ecolibria/crypto-serve) — cryptographic inventory, PQC readiness | [docs](https://opena2a.org/docs/cryptoserve) |

## Smart Input Modes

No memorization required:

```bash
opena2a                           # Interactive guided wizard (no args)
opena2a ~drift                    # Semantic search -- finds related commands
opena2a ?                         # Context-aware recommendations for your project
opena2a "find leaked credentials" # Natural language command matching
```

## Scope Drift Detection

API keys provisioned for one service often silently grant access to others. A Google Maps key can call Gemini. An AWS S3 key may reach Bedrock.

| Finding | What It Means |
|---------|---------------|
| **DRIFT-001** | Google API key can access Gemini AI models beyond intended Maps/Places scope |
| **DRIFT-002** | AWS access key can invoke Bedrock LLM models beyond intended S3/EC2 scope |

When drift is detected, `opena2a protect` migrates the key to environment variables and creates a deny-all broker policy.

## CI/CD Integration

All commands support `--format json` and `--ci` flags:

```yaml
# GitHub Actions
- name: Security assessment
  run: npx opena2a-cli init --ci --format json > security-report.json

- name: Credential check
  run: |
    npx opena2a-cli protect --dry-run --ci --format json > cred-report.json
    jq -e '.totalFound == 0' cred-report.json

- name: Config integrity
  run: npx opena2a-cli guard verify --ci --enforce
```

Output formats: `--format text` (default), `--format json`, `--format sarif`, `--report <path>` (interactive HTML).

## Standalone Tools

Each tool in the ecosystem can be used independently — the CLI is optional.

| Tool | Install Standalone | Purpose |
|------|-------------------|---------|
| [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | `npx hackmyagent secure` | Security scanner, attack simulation, OASB, ARP, AGS |
| [Secretless AI](https://github.com/opena2a-org/secretless-ai) | `npx secretless-ai init` | Credential management for AI coding tools |
| [AIM](https://github.com/opena2a-org/agent-identity-management) | `pip install aim-sdk` | Agent identity, keypairs, capability policies |
| [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | `docker pull opena2a/dvaa` | Deliberately vulnerable AI agent for training |
| [AI Browser Guard](https://github.com/opena2a-org/ai-browserguard) | Chrome Web Store | Browser extension for AI agent detection |
| [Trust Registry](https://registry.opena2a.org) | `registry.opena2a.org` | Supply chain verification and trust scores |

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

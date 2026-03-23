> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)
# opena2a

Open-source security platform for AI agents. Installed as `opena2a-cli` on npm.

```bash
npx opena2a-cli review
```

```
  OpenA2A Security Review  v0.7.2

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
npm install -g opena2a-cli
brew tap opena2a-org/tap && brew install opena2a
```

## Built-in Help

You do not need this README. The CLI has built-in discovery:

```bash
opena2a ?                           # Contextual recommendations for your project
opena2a ~shadow ai                  # Semantic search across all commands
opena2a "find leaked credentials"   # Natural language command matching
opena2a                             # Interactive guided wizard (no args)
```

## Commands

| Command | What it does |
|---------|-------------|
| `opena2a review` | Full security dashboard — HTML report, 6-phase assessment |
| `opena2a detect` | Find shadow AI agents, MCP servers, AI configs. Governance score. |
| `opena2a detect --report` | Executive HTML report |
| `opena2a detect --export-csv` | Asset inventory for CMDB/ServiceNow |
| `opena2a init` | Read-only security assessment with trust score |
| `opena2a protect` | Fix everything — credentials, .gitignore, config signing |
| `opena2a identity create` | Cryptographic identity for your project |
| `opena2a harden-soul` | Generate SOUL.md governance rules |
| `opena2a scan` | 199 security checks via HackMyAgent |
| `opena2a scan-soul` | Validate SOUL.md governance (72 controls, 9 domains) |
| `opena2a scan-soul --strict` | Fail on missing critical controls (IH-003, HB-001) |
| `opena2a harden-skill` | Analyze and harden skill files (frontmatter, permissions, pinning) |
| `opena2a mcp audit` | Audit MCP server configurations with trust scores |
| `opena2a guard sign` | Sign config files for tamper detection |
| `opena2a guard harden` | Scan skills for security issues, auto-fix with `--fix` |
| `opena2a create skill` | Scaffold a secure skill with signing, heartbeat, tests |
| `opena2a shield init` | Full security setup — all of the above, one command |

## Ecosystem

Each command routes to a specialized tool, installed on first use:

| Command | Tool | Description |
|---------|------|-------------|
| `detect` | Shadow AI | Discover AI agents, MCP servers, AI configs |
| `identity` | [AIM](https://github.com/opena2a-org/agent-identity-management) | Cryptographic identity, audit logs, trust scoring |
| `scan` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | 199 security checks, 115 attack payloads, auto-fix |
| `scan-soul` | SOUL Scanner | 72 governance controls, 9 domains, 6 profiles |
| `harden-skill` | Skill Hardener | Frontmatter validation, permission scoping, integrity pinning |
| `secrets` | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | Credential management for AI coding tools |
| `mcp` | MCP Security | Audit, sign, and verify MCP server configurations |
| `benchmark` | [OASB](https://github.com/opena2a-org/open-agent-security-benchmark) | 222 attack scenarios, compliance scoring |
| `train` | [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Vulnerable AI agent for security training |
| `create` | Skill Scaffolding | Secure skill templates with signing and heartbeat |
| `guard harden` | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | Scan skills for hardening issues, auto-fix |

## Skill Security Checks

HMA scans skill files for dangerous patterns (SKILL-001 through SKILL-019), and the CLI adds extended frontmatter/permission analysis (SKILL-020 through SKILL-024):

| Check | Severity | Description | Source |
|-------|----------|-------------|--------|
| SKILL-001 | High | Unsigned skill | HMA |
| SKILL-002 | Critical | Remote fetch and execute (`curl \| sh`) | HMA |
| SKILL-003 | High | Heartbeat installation risk | HMA |
| SKILL-004 | High | Filesystem write outside sandbox | HMA |
| SKILL-005 | Critical | Credential file access | HMA |
| SKILL-006 | Critical | Data exfiltration patterns | HMA |
| SKILL-007 | Critical | ClickFix social engineering | HMA |
| SKILL-008 | Critical | Reverse shell patterns | HMA |
| SKILL-009 | High | Typosquatting name | HMA |
| SKILL-010 | High | Env file exfiltration | HMA |
| SKILL-011 | High | Browser data access | HMA |
| SKILL-012 | Critical | Crypto wallet access | HMA |
| SKILL-019 | Medium | Stale skill signature | HMA |
| SKILL-020 | High | Missing/invalid YAML frontmatter | CLI |
| SKILL-021 | High | Overprivileged permission combos | CLI |
| SKILL-022 | Critical | Environment variable exfiltration via network | CLI |
| SKILL-023 | High | Obfuscated code (base64+eval, hex) | CLI |
| SKILL-024 | Medium | Unbounded tool chaining | CLI |

## Use Cases

- [Developer using AI coding tools](docs/use-cases/developer.md) — 5 minutes
- [Security team assessing AI risk](docs/use-cases/security-team.md) — 10 minutes
- [MCP server author](docs/use-cases/mcp-server-author.md) — 15 minutes
- [CI/CD pipeline integration](docs/use-cases/ci-cd.md)

## Docs

Full command reference, Shield subcommands, scope drift detection, behavioral governance, credential patterns, and CI/CD examples: [opena2a.org/docs](https://opena2a.org/docs)

## Requirements

- Node.js >= 18
- Optional: Docker (for `opena2a train`)

## License

Apache-2.0

---

[Website](https://opena2a.org) · [Docs](https://opena2a.org/docs) · [Discord](https://discord.gg/uRZa3KXgEn) · [GitHub](https://github.com/opena2a-org/opena2a)

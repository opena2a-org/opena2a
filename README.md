# opena2a-cli

[![Status: stable](https://img.shields.io/badge/status-stable-green)](./STATUS.md)

> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

Unified CLI for the OpenA2A security toolchain. One command finds credential leaks, shadow AI, unsigned configs, and ungoverned agents, then fixes them. Apache 2.0.

[![npm version](https://img.shields.io/npm/v/opena2a-cli.svg)](https://www.npmjs.com/package/opena2a-cli)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

[Website](https://opena2a.org) · [Docs](https://opena2a.org/docs) · [Demos](https://opena2a.org/demos) · [Discord](https://discord.gg/uRZa3KXgEn)

## Quick start

```bash
npx opena2a-cli review
```

```
  OpenA2A Security Review

  Findings
  -----------------------------------------------
  Credential scan        3 hardcoded keys
  Shadow AI              2 agents, 4 MCP servers
  Config integrity       unsigned
  Governance             no SOUL.md
  -----------------------------------------------
  Security Score   30 / 100  ->  85 by running opena2a protect

  Run: opena2a protect    (fix all findings)
```

![opena2a review](docs/images/review-demo.gif)

## Install

### npm

```bash
npx opena2a-cli review          # run once, no install
npm install -g opena2a-cli      # install globally
```

Requires Node.js 18 or later.

### Homebrew

```bash
brew install opena2a-org/tap/opena2a
```

### From source

This repo is a TypeScript turborepo. Clone and build if you want to inspect the source, contribute, or run an unreleased version.

```bash
git clone https://github.com/opena2a-org/opena2a.git
cd opena2a
git verify-tag $(git describe --tags --abbrev=0)   # verify the latest release tag
npm install
npm run build                                      # builds all workspaces via turbo
./packages/cli/dist/index.js review                # run the freshly-built binary

# Or link it globally for the current shell:
cd packages/cli && npm link
opena2a review
```

The workspaces. `packages/cli` is the binary; the rest are libraries it consumes.

```
packages/
├── cli                  the opena2a binary
├── aim-core             local-first identity, audit log, policies
├── check-core           scanner orchestration
├── cli-ui               shared render primitives
├── credential-patterns
├── registry-client
├── ai-classifier
├── telemetry
├── contribute           skill scaffolding
└── shared               types + utilities
```

The CLI also depends on three sister packages published from their own repos (declared as runtime deps in `packages/cli/package.json`): [`hackmyagent`](https://github.com/opena2a-org/hackmyagent), [`secretless-ai`](https://github.com/opena2a-org/secretless-ai), and [`ai-trust`](https://github.com/opena2a-org/ai-trust). `opena2a scan` delegates to `hackmyagent`. `opena2a secrets` delegates to `secretless-ai`. `opena2a trust` queries via `ai-trust`.

### Verifying what was installed

Every release publishes via npm Trusted Publishing with SLSA v1 provenance. No long-lived `NPM_TOKEN`. GitHub Actions exchanges its OIDC token with npm at publish time.

```bash
npm view opena2a-cli dist.attestations --json
# Expects non-empty result with predicateType "https://slsa.dev/provenance/v1"
```

For local CLI integrity (post-install tamper), `opena2a status` reports the binary signature state. `opena2a shield selfcheck` runs the full self-attestation against the embedded manifest.

Identity files (`~/.opena2a/aim-core/identity.json`) are written `mode 0600`. OAuth tokens live in the OS keychain by default. `~/.opena2a/auth.json` stores metadata only.

## Which OpenA2A CLI do I want

There are four published CLIs in the toolchain. `opena2a` is the unified front door. Each underlying tool can also be installed and run standalone if that fits better.

| You want to... | Use | Standalone install |
|---|---|---|
| Run one command and get a full security review of your project | `opena2a review` | (front door) |
| Scan a specific MCP server, skill, npm package, or GitHub repo | `opena2a scan <target>` or `hackmyagent check <target>` | `npm install -g hackmyagent` |
| Wrap any subprocess with credentials injected at runtime | `opena2a secrets run --only KEY -- <cmd>` or `secretless-ai run --only KEY -- <cmd>` | `npm install -g secretless-ai` |
| Check the trust posture of an npm or PyPI package before installing | `opena2a trust <pkg>` or `ai-trust <pkg>` | `npm install -g ai-trust` |
| Give your agent a cryptographic identity and local audit log, no server | `opena2a identity create --name X` | (bundled in `opena2a-cli`) |
| Benchmark a security tool against 222 standard attack scenarios | `opena2a benchmark` | (uses OASB internally) |

If you're not sure where to start, run `opena2a review` in your project root. It tells you what's wrong and which underlying tool to invoke for the fix.

## Built-in help

```bash
opena2a ?                              # recommendations for THIS project
opena2a ~shadow ai                     # semantic search ("ai" finds AI-related commands)
opena2a "find leaked credentials"      # natural language to matched command
opena2a                                # interactive guided wizard (no args)
```

## Commands

Three job categories: assess, protect, operate. Run any with `--help` for full flags.

### Assess

| Command | What it does |
|---|---|
| `opena2a review` | Full security dashboard. 6-phase assessment, HTML report. Most common entry point. |
| `opena2a init` | Read-only first-time security assessment with a trust score for your project. |
| `opena2a detect` | Shadow AI discovery. Finds undeclared agents, MCP servers, AI configs. Returns a governance score. |
| `opena2a scan <target>` | 209 static + 29 semantic + 164 adversarial-payload checks via HackMyAgent. Targets: local repo, npm package, GitHub repo, MCP server, skill, or standalone SOUL.md. |
| `opena2a check <target>` | Pre-install trust check. Queries the OpenA2A Registry and runs HMA locally. |
| `opena2a scan-soul <path>` | 72 governance controls across 9 domains, profile-aware. |
| `opena2a trust <pkg>` | Read-only Registry lookup for an npm or PyPI package. |
| `opena2a benchmark` | Run the OASB 222-scenario benchmark against your security tool. |

### Protect

| Command | What it does |
|---|---|
| `opena2a protect` | Migrate hardcoded credentials to env-var references, masked previews, rollback manifest. Adds `.gitignore` patterns. Signs configs. |
| `opena2a harden-soul` | Generate a `SOUL.md` governance file from your project state. |
| `opena2a harden-skill <path>` | Frontmatter validation, permission scoping, integrity pinning on a Claude or Cursor skill. |
| `opena2a guard sign` | Sign and watch config files (`mcp.json`, `claude_desktop_config.json`, etc.). Alerts on unauthorized changes. |
| `opena2a shield init` | One-shot 11-step setup: review, protect, identity, guard, secrets, runtime, policy, hooks. |

#### Optional AAP gate on `protect`

`protect` can be gated by the [Agent Authorization Protocol](https://github.com/opena2a-standards/agent-authorization-protocol). When `--grant` is set, the CLI presents an ATX and a grant reference to the local Secretless broker before any scan runs. The broker is the policy decision point; the CLI proceeds only if the broker authorizes.

```bash
opena2a protect \
  --grant grant://opena2a-protect \
  --atx ~/.opena2a/atx.json
```

Outcomes:

- **Broker authorizes** -> protect proceeds.
- **Broker denies (HTTP 403)** -> protect exits 3 with a one-line pointer to `~/.secretless-ai/policies/`. Per AAP §6.6 the denial is opaque; reasons live only in the broker's signed audit log.
- **Broker unreachable** -> protect exits 4 with a `secretless broker start` hint.
- **No `--grant` flag** -> protect runs exactly as before; the gate is opt-in.

This integration newly defends **T-3002** (cross-tenant grant leakage), **T-3003** (over-broad credential scope), **T-3006** (credential leaking into agent context), and **T-8002** (audit attribution gap) at the CLI surface. The broker is the integrity-protected decision and audit point; the CLI carries no policy state.

### Operate

| Command | What it does |
|---|---|
| `opena2a identity create --name X` | Generate an Ed25519 keypair locally. Writes `~/.opena2a/aim-core/identity.json`. |
| `opena2a identity integrate` | Wire up cross-tool bridges so Secretless, HMA, ConfigGuard, Shield, and ARP events flow into one unified audit log. |
| `opena2a identity audit [--limit N]` | Read back the unified audit log. The query path for incident response. |
| `opena2a identity trust` | Local 8-factor posture score. |
| `opena2a identity sign --data X` | Sign arbitrary bytes with the agent's Ed25519 key. |
| `opena2a runtime tail [-c N]` | Tail the HMA ARP runtime event stream for the current project. |
| `opena2a secrets ...` | Credential management via Secretless. `add`, `list`, `run`, `revoke`. |
| `opena2a mcp ...` | MCP server lifecycle: `audit`, `sign`, `verify`. |
| `opena2a status` | What's running, what's protected, what's missing. |
| `opena2a login` | OAuth 2.0 device flow against AIM Cloud or your self-hosted server. |
| `opena2a whoami` | Current auth status. |
| `opena2a skill create <name>` | Scaffold a new secure skill with signing and heartbeat. |
| `opena2a train` | Boot DVAA, the deliberately vulnerable AI agent, for security training. |

Full command reference: [opena2a.org/docs](https://opena2a.org/docs).

## Post-incident review

Once `opena2a identity integrate` runs once, every event the OpenA2A toolchain captures auto-bridges into a single local audit log. No decorator in your agent code. No server. When something goes wrong:

```bash
opena2a identity audit --limit 200
# 200 most recent events: credential injections, file accesses, config
# changes, scan findings, ARP runtime events. All in one timestamp-
# ordered JSON-lines view, sourced from Secretless, HackMyAgent,
# ConfigGuard, Shield, and ARP.

opena2a identity audit | jq 'select(.result == "denied")'
# just the denies
```

The audit log lives at `~/.opena2a/aim-core/audit.jsonl`. Append-only. Rotation at 50 MB, last 5 generations kept. Forward to Splunk or Sentinel via the standard tail-and-forward pattern.

Encryption at rest is filesystem-level. The JSONL stores unencrypted so `grep` and `jq` work without ceremony. For compliance use cases, encrypt `~/.opena2a/` with FileVault on macOS, LUKS on Linux, or BitLocker on Windows, or ship to a KMS-backed log aggregator.

## Self-host or AIM Cloud

`opena2a-cli` works offline by default. The optional server path:

- **AIM Cloud.** Managed at [aim.opena2a.org](https://aim.opena2a.org). `opena2a login` and you're done.
- **Self-hosted AIM.** Docker stack from [`agent-identity-management`](https://github.com/opena2a-org/agent-identity-management). REST API, dashboard, Postgres-backed audit log, OAuth, 9-factor real-time trust scoring with NanoMind, 5-step Fine-Grained Authorization pipeline. Run `bash quickstart.sh` to bring it up.

Local-only mode covers identity, audit, capability policies, and trust scoring. Server adds real-time enforcement, multi-machine fleet management, the dashboard, and MCP attestation. The CLI is the same in both modes. `--server` switches it.

## Use cases

| Guide | Time |
|---|---|
| [Developer using AI coding tools](docs/use-cases/developer.md) | 5 min |
| [Security team assessing AI risk across a fleet](docs/use-cases/security-team.md) | 10 min |
| [MCP server author shipping safely](docs/use-cases/mcp-server-author.md) | 15 min |
| [CI/CD pipeline integration](docs/use-cases/ci-cd.md) | 20 min |

Full index: [docs/USE-CASES.md](docs/USE-CASES.md).

## Contributing

Apache 2.0. PRs from outside the org welcome. [CONTRIBUTING.md](CONTRIBUTING.md) has the dev loop, test conventions, and pre-push review gates.

```bash
git clone https://github.com/opena2a-org/opena2a.git
cd opena2a && npm install && npm run build && npm test
```

Security issues: `security@opena2a.org` (coordinated disclosure, response within 24 hours).

## Links

- [Website](https://opena2a.org)
- [Documentation](https://opena2a.org/docs)
- [Demos](https://opena2a.org/demos)
- [AIM](https://github.com/opena2a-org/agent-identity-management)
- [HackMyAgent](https://github.com/opena2a-org/hackmyagent)
- [Secretless](https://github.com/opena2a-org/secretless-ai)
- [Research](https://research.opena2a.org)

Part of the [OpenA2A](https://opena2a.org) security platform.

## License

Apache-2.0. See [LICENSE](LICENSE).

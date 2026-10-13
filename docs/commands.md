# opena2a commands

There are four published CLIs in the toolchain. `opena2a` is the unified front door. Each underlying tool can also be installed and run standalone if that fits better.

If you're not sure where to start, run `opena2a init` in your project root. It tells you what's wrong and which underlying tool to invoke for the fix.

## Assess a project

```bash
opena2a init
```

Run one command and get a security assessment of your project. `opena2a init` is the front door; there is no standalone tool to install for it.

## Check a package, MCP server, skill or repo

```bash
opena2a check <target>
```

Check a specific MCP server, skill, npm package, or GitHub repo. Standalone: `hackmyagent check <target>`, after `npm install -g hackmyagent`.

## Run a command with injected credentials

```bash
opena2a secrets run --only KEY -- <cmd>
```

Wrap any subprocess with credentials injected at runtime. Standalone: `secretless-ai run --only KEY -- <cmd>`, after `npm install -g secretless-ai`.

## Look up a package's trust profile

```bash
opena2a trust <pkg>
```

Check the trust posture of an npm or PyPI package before installing. Standalone: `ai-trust <pkg>`, after `npm install -g ai-trust`.

## Give an agent an identity

```bash
opena2a identity create --name X
```

Give your agent a cryptographic identity and local audit log, no server. Bundled in `opena2a-cli`. [Post-incident review](post-incident-review.md) shows how to read the log back.

## Run the OASB benchmark

```bash
opena2a benchmark
```

Uses OASB internally.

## Command reference

Three job categories: assess, protect, operate. Run any with `--help` for full flags.

### Assess

| Command | What it does |
|---|---|
| `opena2a init` | Read-only security assessment with a trust score for your project. Start here. |
| `opena2a review` | Full security dashboard. 6-phase assessment, HTML report. First run downloads the NanoMind model files; `--no-open` skips the browser. |
| `opena2a detect` | Shadow AI discovery. Finds undeclared agents, MCP servers, AI configs. Returns a governance score. |
| `opena2a scan <target>` | Static, semantic, and adversarial-payload checks via HackMyAgent (current counts: `hackmyagent --help`). Targets: local repo, npm package, GitHub repo, MCP server, skill, or standalone SOUL.md. |
| `opena2a check <target>` | Pre-install trust check. Queries the OpenA2A Registry and runs HMA locally. |
| `opena2a scan-soul <path>` | Governance controls across every ABGS domain, profile-aware. |
| `opena2a trust <pkg>` | Read-only Registry lookup for an npm or PyPI package. |
| `opena2a benchmark` | Run the OASB benchmark against your security tool. |

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
- **Broker returns an unexpected status** -> protect exits 6. The response body is never echoed to the user; reasons live only in the broker audit log.
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
| `opena2a secrets ...` | Credential management via Secretless. `secret set`, `secret list`, `run`, `vault revoke`. |
| `opena2a mcp ...` | MCP server lifecycle: `audit`, `sign`, `verify`. |
| `opena2a status` | What's running, what's protected, what's missing. |
| `opena2a login` | OAuth 2.0 device flow against AIM Cloud or your self-hosted server. |
| `opena2a whoami` | Current auth status. |
| `opena2a skill create <name>` | Scaffold a new secure skill with signing and heartbeat. |
| `opena2a train` | Boot DVAA, the deliberately vulnerable AI agent, for security training. |

Full command reference: [opena2a.org/docs](https://opena2a.org/docs).

## Self-host or AIM Cloud

`opena2a-cli` works offline by default. The optional server path:

- **AIM Cloud.** Managed at [aim.opena2a.org](https://aim.opena2a.org). `opena2a login` and you're done.
- **Self-hosted AIM.** Docker stack from [`agent-identity-management`](https://github.com/opena2a-org/agent-identity-management). REST API, dashboard, Postgres-backed audit log, OAuth, 9-factor real-time trust scoring with NanoMind, 5-step Fine-Grained Authorization pipeline. Run `bash quickstart.sh` to bring it up.

Local-only mode covers identity, audit, capability policies, and trust scoring. Server adds real-time enforcement, multi-machine fleet management, the dashboard, and MCP attestation. The CLI is the same in both modes. `--server` switches it.

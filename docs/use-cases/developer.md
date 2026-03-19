# I'm a Developer Using AI Coding Tools

You use Claude Code, Cursor, GitHub Copilot, or another AI coding assistant. You want to secure your project without changing your workflow.

**Time estimate:** 5 minutes from start to a fully governed project.

**Prerequisites:**
- Node.js 18 or later
- An existing project directory

---

## Step 1: See What's Running

Start by discovering what AI tools are active in your environment and how well-governed they are.

```bash
npx opena2a-cli detect
```

Expected output:

```
  Shadow AI Detection  v0.7.2

  Machine    macbook-pro (darwin arm64)
  User       dev
  Directory  /home/dev/my-project

  AI Agents (2 running)
  -----------------------------------------------
  claude-code          PID 41023   v1.0.12
  cursor               PID 38291   v0.45.6

  MCP Servers (3 configured)
  -----------------------------------------------
  filesystem           claude     local
  postgres             claude     local
  slack                cursor     local

  AI Config Files (2 found)
  -----------------------------------------------
  CLAUDE.md            project    governance rules
  .cursorrules         project    editor config

  Governance Score     45 / 100

  Findings
  -----------------------------------------------
  - Project not registered (no AIM identity)
  - No SOUL.md behavioral governance file
  - MCP servers unsigned
  - 2 credentials detected in source files

  Run: opena2a protect    (fix all findings)
```

The governance score tells you how well-managed your AI environment is. A score of 45 means several gaps need attention.

---

## Step 2: Register the Project

Create a cryptographic identity for your project. This generates a local Ed25519 keypair that other OpenA2A tools use to verify ownership and sign artifacts.

```bash
npx opena2a-cli identity create --name my-project
```

Expected output:

```
  Agent Identity Created

  Name         my-project
  Agent ID     agent:ed25519:k1_a8f3...7d2e
  Key Type     Ed25519
  Created      2026-03-15T10:30:00Z
  Storage      .aim/identity.json

  The private key is stored locally. It never leaves this machine.
  Other tools can now reference this identity for signing and verification.
```

This identity is local-only. No data is sent to any server. The `.aim/` directory is automatically added to `.gitignore` by the `protect` command in a later step.

---

## Step 3: Set Governance Rules

Generate a `SOUL.md` file that defines behavioral boundaries for AI agents working in your project. This file is checked by `scan-soul` and used by governance-aware agents.

```bash
npx opena2a-cli harden-soul
```

Expected output:

```
  SOUL.md Governance Hardening

  Project      /home/dev/my-project
  Type         Node.js (detected)
  Tier         TOOL-USING (54 controls)

  Generated Sections
  -----------------------------------------------
  Trust Hierarchy          who can override whom
  Capability Boundaries    allowed/denied tool actions
  Injection Hardening      prompt injection defenses
  Data Handling            PII, credentials, exfiltration
  Hardcoded Behaviors      invariant safety rules
  Agentic Safety           delegation, recursion limits
  Honesty                  transparency requirements
  Human Oversight          approval gates, escalation

  Wrote: SOUL.md (54 controls, 8 domains)

  Run: opena2a scan-soul    (verify coverage)
```

The generated file uses the ABGS (Agent Behavioral Governance Specification) framework. You can edit the file to customize rules for your project. For example, you might restrict file deletion or require human approval for deployments.

To verify your governance file covers all required controls:

```bash
npx opena2a-cli scan-soul
```

Expected output:

```
  SOUL.md Governance Scan

  File         SOUL.md
  Tier         TOOL-USING (54 controls)

  Domain Scores
  -----------------------------------------------
  Trust Hierarchy          8 / 8    100%
  Capability Boundaries    7 / 7    100%
  Injection Hardening      6 / 6    100%
  Data Handling            7 / 7    100%
  Hardcoded Behaviors      6 / 6    100%
  Agentic Safety           8 / 8    100%
  Honesty                  6 / 6    100%
  Human Oversight          6 / 6    100%

  Overall Score    54 / 54   100%
```

---

## Step 4: Protect Credentials

If you have API keys or tokens in your source files, migrate them to environment variables. Secretless AI detects hardcoded credentials and replaces them with `process.env.VAR_NAME` (or the equivalent for your language).

```bash
npx secretless-ai init
```

Expected output:

```
  Secretless AI  v0.11.4

  Scanning /home/dev/my-project...

  Credentials Found (2)
  -----------------------------------------------
  src/config.ts:12     ANTHROPIC_API_KEY    sk-ant-api03-***
  src/config.ts:15     OPENAI_API_KEY       sk-proj-***

  Actions Taken
  -----------------------------------------------
  Created .env with 2 variables
  Updated src/config.ts (2 replacements)
  Added .env to .gitignore
  Created .env.example (variable names only, no values)
  Added CLAUDE.md secretless block

  All credentials migrated to environment variables.
  Run: npx secretless-ai verify    (confirm no leaks)
```

The original credential values are moved to `.env` (which is gitignored). Your source files now reference `process.env.ANTHROPIC_API_KEY` instead of the raw key.

---

## Step 5: Scan for Vulnerabilities

Run a full security scan to check for remaining issues across your AI configuration.

```bash
npx hackmyagent secure
```

Expected output:

```
  HackMyAgent  v0.10.4

  Scanning /home/dev/my-project...
  187 checks across 39 categories

  Results
  -----------------------------------------------
  Critical     0
  High         1    MCP server 'postgres' has unrestricted query access
  Medium       2    .cursorrules not signed, CLAUDE.md not signed
  Low          1    No runtime monitoring configured
  Info         3    Detected 3 MCP servers, 2 AI agents

  Score        82 / 100

  Recommended Fixes
  -----------------------------------------------
  1. Restrict postgres MCP server queries:
     Add allowedOperations to MCP config (see docs)

  2. Sign config files:
     opena2a guard sign

  3. Enable runtime monitoring:
     opena2a runtime init
```

Address the findings based on severity. Critical and high findings should be resolved before deploying to production.

---

## Step 6: Verify

Run detection again to confirm your governance score has improved.

```bash
npx opena2a-cli detect
```

Expected output:

```
  Shadow AI Detection  v0.7.2

  Machine    macbook-pro (darwin arm64)
  User       dev
  Directory  /home/dev/my-project

  AI Agents (2 running)
  -----------------------------------------------
  claude-code          PID 41023   v1.0.12    governed
  cursor               PID 38291   v0.45.6    governed

  MCP Servers (3 configured)
  -----------------------------------------------
  filesystem           claude     local      signed
  postgres             claude     local      signed
  slack                cursor     local      signed

  AI Config Files (4 found)
  -----------------------------------------------
  CLAUDE.md            project    governance rules    signed
  .cursorrules         project    editor config       signed
  SOUL.md              project    behavioral rules
  .aim/identity.json   project    agent identity

  Governance Score     100 / 100

  All checks passed. This project is fully governed.
```

Every AI agent is now tracked, credentials are protected, behavioral governance is defined, and config files are signed for tamper detection.

---

## Ongoing Maintenance

After the initial setup, use these commands as part of your regular workflow:

| When | Command | Purpose |
|------|---------|---------|
| Before commits | `opena2a protect --dry-run` | Check for new credential leaks |
| Weekly | `opena2a detect` | Verify governance posture |
| After config changes | `opena2a guard resign` | Re-sign modified config files |
| In CI/CD | `opena2a review --format json` | Automated security gate |

---

## Built-in Help

You do not need to memorize commands. The CLI provides contextual assistance:

```bash
opena2a ?                           # Context-aware recommendations for your project
opena2a ~shadow ai                  # Semantic search across all commands
opena2a "find leaked credentials"   # Natural language command matching
opena2a                             # Interactive guided wizard (no args)
```

---

## Related Use Cases

- [Security team assessing AI risk](./security-team.md)
- [MCP server author](./mcp-server-author.md)
- [CI/CD pipeline integration](./ci-cd.md)
- [Full documentation](https://opena2a.org/docs)

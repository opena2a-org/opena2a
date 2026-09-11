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

Captured from opena2a-cli v0.10.13 on 2026-09-04; the device line and the scan timestamp are replaced with fixed placeholders:
```
Shadow AI Agent Audit
macbook-pro | dev | /home/dev/my-project
2026-09-04 18:22:41 UTC

Governance: 63/100 -> 100/100 by addressing 3 findings
3 MCP servers | 3 AI configs

What This Means
  3 MCP servers give your AI agents additional capabilities (file access, database queries, API calls, etc.).
  None have verified identities, so there is no tamper-evident record of which server version is installed.

Findings (3)

  HIGH  AI config files grant broad permissions
  .claude/settings.json
  These configs allow AI agents to perform a wide range of actions without restrictions. Broad permissions increase the surface area if an agent behaves unexpectedly or if the config is modified by a third party.
  Fix: opena2a scan-soul

  MEDIUM  3 project MCP servers without verified identity
  These servers are configured in your project but have not been signed.
  Unverified servers could be modified or replaced without detection. Signing creates a tamper-evident record of exactly which server version is in use.
  Fix: opena2a mcp audit

  LOW  3 project MCP servers without signed identity
  Signing creates a tamper-evident record of each server's configuration.
  Without signing, you cannot detect if an MCP server configuration was modified by an attacker or by another agent. Signing lets you verify that the server you are using is the exact version you approved.
  Fix: opena2a mcp sign

Running AI Agents
  No AI agents detected

MCP Servers (3 found)
  Project-local (3)
    postgres             -- can read and modify your database
    filesystem           -- can read and write files on your machine
    slack                -- can send messages on your behalf

AI Config Files (3 found)
  .claude/settings.json              Claude Code
    Grants broad permissions to AI agents in this project
  + 2 low-risk config(s) -- run with --verbose to see all

```

The governance score tells you how well-managed your AI environment is: 100 is fully governed, and every point it deducts is attached to a finding with a fix. A score of 63 means several gaps need attention.

`Running AI Agents` lists the AI assistants it finds in the machine's process table. The capture above was taken on a build machine with none running; on a workstation with Claude Code or Cursor open, each one appears here with its identity and governance status, and an ungoverned agent costs the score more than any single MCP server does.

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

The three findings from Step 1 each name their own fix. The broad-permission config is narrowed, and each project MCP server is signed -- `npx opena2a-cli mcp sign filesystem`, then the same for `postgres` and `slack`, which writes one `.opena2a/mcp-identities/<name>.json` per server. Then run detection again:

```bash
npx opena2a-cli detect
```

Captured from opena2a-cli v0.10.13 on 2026-09-04; the device line and the scan timestamp are replaced with fixed placeholders:
```
Shadow AI Agent Audit
macbook-pro | dev | /home/dev/my-project
2026-09-04 18:22:41 UTC

Governance: 100/100 -- fully governed
3 MCP servers | 2 AI configs

What This Means
  3 MCP servers give your AI agents additional capabilities (file access, database queries, API calls, etc.).

All detected AI tools have governance in place. No findings.

Running AI Agents
  No AI agents detected

MCP Servers (3 found)
  Project-local (3)
    filesystem           verified -- can read and write files on your machine
    postgres             verified -- can read and modify your database
    slack                verified -- can send messages on your behalf

```

Signed servers are the ones marked `verified`; an unsigned project server is what the score deducts for. Credentials are in the environment, behavioral governance is defined in `SOUL.md`, and every project MCP server has a signature to check against.

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

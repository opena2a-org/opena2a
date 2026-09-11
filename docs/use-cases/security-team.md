# I'm a Security Team Assessing AI Risk

You are a CISO, security engineer, or compliance analyst. Developers on your team are using AI coding assistants, and you need visibility into what's running, what risks exist, and how to report on them.

**Time estimate:** 10 minutes per machine for initial discovery. 30 minutes for a full fleet assessment.

**Prerequisites:**
- Node.js 18 or later
- Access to developer workstations (directly or via remote execution)

---

## Step 1: Discover Shadow AI

Run detection on a developer workstation to see what AI tools are active. This command is read-only and does not modify any files.

```bash
npx opena2a-cli detect
```

Captured from opena2a-cli v0.10.13 on 2026-09-04; the device line and the scan timestamp are replaced with fixed placeholders:
```
Shadow AI Agent Audit
dev-laptop-042 | jsmith | /home/jsmith/payments-api
2026-09-04 18:22:41 UTC

Governance: 28/100 -> 100/100 by addressing 2 findings
5 MCP servers | 4 AI configs

What This Means
  5 MCP servers give your AI agents additional capabilities (file access, database queries, API calls, etc.).
  None have verified identities, so there is no tamper-evident record of which server version is installed.

Findings (2)

  CRITICAL  1 project MCP server with sensitive access
  shell-runner: can run any command on your computer
  These MCP servers are configured in your project and grant access to sensitive operations like running commands, accessing databases, or processing payments. Verifying them confirms they are the servers you intended to install.
  Fix: opena2a mcp audit

  CRITICAL  AI config files contain credential references
  .env.ai
  API keys or tokens appear to be stored directly in these configuration files. Anyone with access to the file (or the repository) can see and use these credentials. Moving them to environment variables limits exposure.
  Fix: opena2a protect

Running AI Agents
  No AI agents detected

MCP Servers (5 found)
  Project-local (5)
    shell-runner         -- can run any command on your computer
    postgres             -- can read and modify your database
    filesystem           -- can read and write files on your machine
    github               -- can read and push code to your repositories
    slack                -- can send messages on your behalf

AI Config Files (4 found)
  .env.ai                            AI Framework
    Contains credential references -- these should be in environment variables
  + 3 low-risk config(s) -- run with --verbose to see all

```

Key observations for security teams:
- **Running AI Agents** lists every AI coding assistant found in the machine's process table, including local model runtimes like Ollama that bypass corporate API gateways. The capture above was taken on a build machine with none running, so the section is empty; on a developer workstation each assistant appears with its identity and governance status.
- **MCP Servers** reveals what external services AI agents can access, in plain language. `can read and modify your database` is a postgres server; `can run any command on your computer` is shell access, which is the only capability the scoring treats as critical on its own.
- **Governance**, the first line of the report, is a single number (0-100) for executive reporting, followed by the score the machine would reach if every listed finding were addressed.

---

## Step 2: Generate an Executive Report

Create an HTML report suitable for sharing with leadership or including in security reviews.

```bash
npx opena2a-cli detect --report shadow-ai-report.html
```

On the terminal this prints the Step 1 audit unchanged and then one more line, naming the file it wrote and opening it in your browser.

Captured from opena2a-cli v0.10.13 on 2026-09-04 -- the last line of the run; everything above it is the same audit as Step 1:
```
Report: shadow-ai-report.html
```

Give `--report` a path, as above: with no argument it writes to a generated name under your temporary directory.

The HTML report includes:
- Executive summary with governance score
- Full inventory of AI agents, MCP servers, and config files
- Risk breakdown by category (credentials, governance, integrity, access)
- Remediation steps ordered by severity
- Machine metadata (hostname, OS, username, scan time) for audit trails

Add `--ci` to write the report without opening a browser, which is also what you want on a machine you reached over SSH:

```bash
npx opena2a-cli detect --report shadow-ai-report.html --ci
```

---

## Step 3: Export Asset Inventory

Export the discovery results as CSV for import into your CMDB, SIEM, or asset management system.

```bash
npx opena2a-cli detect --export-csv assets.csv
```

As with `--report`, the terminal shows the Step 1 audit and then one more line:

Captured from opena2a-cli v0.10.13 on 2026-09-04 -- the last line of the run; everything above it is the same audit as Step 1:
```
Asset inventory: assets.csv
```

The file it wrote carries one row per discovered asset -- one per AI agent, one per MCP server, one per AI config file:

Captured from opena2a-cli v0.10.13 on 2026-09-04; the `Hostname`, `Username`, `Scan Directory` and `Scan Timestamp` columns are replaced with fixed placeholders:
```csv
Hostname,Username,Scan Directory,Scan Timestamp,Asset Type,Name,Installed From,Transport,Capabilities,Risk
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-09-04T18:22:41.000Z,MCP Server,filesystem,This project,stdio,Can read and write files on your machine,medium
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-09-04T18:22:41.000Z,MCP Server,postgres,This project,stdio,Can read and modify your database,high
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-09-04T18:22:41.000Z,MCP Server,github,This project,stdio,Can read and push code to your repositories,medium
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-09-04T18:22:41.000Z,MCP Server,slack,This project,stdio,Can send messages on your behalf,medium
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-09-04T18:22:41.000Z,MCP Server,shell-runner,This project,stdio,Can run any command on your computer,critical
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-09-04T18:22:41.000Z,AI Config,.cursorrules,Cursor,,Cursor configuration,low
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-09-04T18:22:41.000Z,AI Config,CLAUDE.md,Claude Code,,Claude Code configuration,low
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-09-04T18:22:41.000Z,AI Config,.github/copilot-instructions.md,GitHub Copilot,,GitHub Copilot configuration,low
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-09-04T18:22:41.000Z,AI Config,.env.ai,AI Framework,,AI Framework config contains credential references,critical
```

The columns are named for CMDB and ServiceNow import. Every row repeats `Hostname`, `Username`, `Scan Directory` and `Scan Timestamp`, so you can aggregate results from multiple machines into a single spreadsheet or database. `Asset Type` is one of `AI Agent`, `MCP Server` or `AI Config`; the machine captured above had no AI agent processes running, so it exported no `AI Agent` rows.

---

## Step 4: Enrich with Community Trust Data

Cross-reference discovered MCP servers against the OpenA2A Trust Registry to see community trust scores, known vulnerabilities, and verification status.

```bash
npx opena2a-cli detect --registry
```

The report is the same one Step 1 prints. What `--registry` changes is the `MCP Servers` section: each server row gains a trust label, and the label has exactly three forms.

| What is known about the server | Label appended to its row |
|---|---|
| The registry has a record of it | `Trust: 92/100 \| 45 community scans` (the count is dropped when it is zero) |
| No record, but a local scan ran | `Scanned: 95/100 \| 0 critical` |
| Neither | `No trust data \| scan: opena2a detect --registry --auto-scan` |

No capture of this command is pasted here: its output depends on what the live registry holds for your servers on the day you run it, and a frozen copy of that is exactly the kind of thing the rest of this page used to get wrong. Run it and read your own.

`--registry` is the only flag on this page that leaves the machine. It sends the name and asset type of each discovered MCP server and nothing else -- no file contents, no findings, no scores. Scan results are sent only if you separately opt in with `opena2a config contribute on`. A server the registry has never seen is not unsafe by that fact alone -- custom and internal servers never appear in it -- but it has had no community vetting either. Adding `--auto-scan` scans those servers locally with HackMyAgent instead, which is where the `Scanned:` label comes from.

---

## Step 5: Full Security Review

Run a comprehensive 6-phase security assessment that combines credential scanning, config integrity, shadow AI detection, behavioral governance, advisory checks, and optional deep scanning.

```bash
npx opena2a-cli review
```

Expected output:

```
  OpenA2A Security Review

  Project      payments-api v2.1.0
  Type         Node.js + MCP server
  Directory    /home/jsmith/payments-api

  Phase 1: Credential Scan
  -----------------------------------------------
  3 hardcoded keys found
    src/config.ts:12     ANTHROPIC_API_KEY    critical
    src/config.ts:15     OPENAI_API_KEY       critical
    src/db.ts:8          DATABASE_URL         high

  Phase 2: Config Integrity
  -----------------------------------------------
  3 config files unsigned
    CLAUDE.md            not signed
    .cursorrules         not signed
    .copilot/config.yml  not signed

  Phase 3: Shadow AI
  -----------------------------------------------
  3 agents running, 5 MCP servers configured
  Governance score: 32 / 100

  Phase 4: Behavioral Governance
  -----------------------------------------------
  No SOUL.md found
  0 / 54 ABGS controls addressed

  Phase 5: Advisory Check
  -----------------------------------------------
  1 advisory for installed MCP servers
    slack MCP: CVE-2026-1234 (medium)

  Phase 6: HMA Deep Scan (optional)
  -----------------------------------------------
  Skipped (run with --deep to enable)

  Summary
  -----------------------------------------------
  Critical     2    hardcoded API keys
  High         2    database URL exposed, unsigned configs
  Medium       3    no governance, MCP advisory, no identity
  Low          1    no runtime monitoring

  Security Score   30 / 100  -> 85 by running opena2a protect

  Report: security-review.html (opened in browser)
```

The HTML dashboard provides an interactive 6-tab view with drill-down into each finding. Each finding includes a description of the issue, a verification command to see it yourself, and a fix command to resolve it.

To generate the report without opening a browser:

```bash
npx opena2a-cli review --no-open --report security-review.html
```

For CI/CD integration, use JSON output:

```bash
npx opena2a-cli review --format json
```

---

## Step 6: Aggregate Across Your Fleet

To assess AI risk across multiple developer workstations, run detection on each machine and combine the CSV exports.

### Option A: Manual Collection

Run on each machine:

```bash
npx opena2a-cli detect --export-csv assets-$(hostname).csv
```

Then combine:

```bash
# On your analysis machine, after collecting all CSVs:
head -1 assets-dev-laptop-001.csv > fleet-inventory.csv
tail -n +2 -q assets-*.csv >> fleet-inventory.csv
```

### Option B: Remote Execution

If you have SSH access to developer machines:

```bash
#!/bin/bash
# fleet-scan.sh
MACHINES="dev-laptop-001 dev-laptop-002 dev-laptop-003"
OUTPUT_DIR="./fleet-reports"
mkdir -p "$OUTPUT_DIR"

for machine in $MACHINES; do
  echo "Scanning $machine..."
  ssh "$machine" "npx opena2a-cli detect --export-csv /tmp/assets.csv" 2>/dev/null
  scp "$machine:/tmp/assets.csv" "$OUTPUT_DIR/assets-$machine.csv" 2>/dev/null
done

# Combine all CSVs
head -1 "$OUTPUT_DIR"/assets-*.csv | head -1 > "$OUTPUT_DIR/fleet-inventory.csv"
tail -n +2 -q "$OUTPUT_DIR"/assets-*.csv >> "$OUTPUT_DIR/fleet-inventory.csv"

echo "Fleet inventory: $OUTPUT_DIR/fleet-inventory.csv"
wc -l "$OUTPUT_DIR/fleet-inventory.csv"
```

### Option C: JSON Output for SIEM Integration

Use JSON output and forward to your SIEM or log aggregation system:

```bash
npx opena2a-cli detect --format json | curl -X POST \
  -H "Content-Type: application/json" \
  -d @- \
  https://your-siem.example.com/api/v1/events
```

### Interpreting Fleet Data

When reviewing aggregated data, look for:

| Pattern | Risk | Action |
|---------|------|--------|
| Agents running without governance | Shadow AI | Deploy SOUL.md and AIM identity |
| MCP servers not in Trust Registry | Unknown provenance | Review and register or block |
| Local models (Ollama, LM Studio) | Data exfiltration bypass | Assess data handling policies |
| Low governance scores (<50) | Ungoverned AI usage | Prioritize for remediation |
| Credentials in source files | Secret exposure | Run `opena2a protect` |

---

## Compliance Mapping

OpenA2A detection and governance maps to common compliance frameworks:

| Framework | Relevant Controls | OpenA2A Coverage |
|-----------|-------------------|------------------|
| SOC 2 | CC6.1 (Logical Access), CC7.1 (System Monitoring) | Shadow AI detection, runtime monitoring |
| ISO 27001 | A.8.1 (Asset Management), A.12.4 (Logging) | Asset inventory export, event logging |
| NIST AI RMF | MAP 1.1 (AI inventory), GOVERN 1.1 (policies) | Detect command, SOUL.md governance |
| EU AI Act | Article 9 (Risk Management), Article 13 (Transparency) | Review command, ABGS controls |

---

## Next Steps

After completing the initial assessment:

1. **Remediate critical findings** by running `opena2a protect` on machines with hardcoded credentials
2. **Establish governance baselines** by deploying SOUL.md templates to all projects
3. **Automate ongoing monitoring** by adding detection to CI/CD pipelines (see [CI/CD integration](./ci-cd.md))
4. **Track improvements** by comparing governance scores over time

---

## Related Use Cases

- [Developer using AI coding tools](./developer.md)
- [MCP server author](./mcp-server-author.md)
- [CI/CD pipeline integration](./ci-cd.md)
- [Full documentation](https://opena2a.org/docs)

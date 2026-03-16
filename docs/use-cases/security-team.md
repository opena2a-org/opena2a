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

Expected output:

```
  Shadow AI Detection  v0.7.2

  Machine    dev-laptop-042 (darwin arm64)
  User       jsmith
  Directory  /home/jsmith/payments-api

  AI Agents (3 running)
  -----------------------------------------------
  claude-code          PID 41023   v1.0.12
  cursor               PID 38291   v0.45.6
  ollama               PID 52100   v0.3.14    local model

  MCP Servers (5 configured)
  -----------------------------------------------
  filesystem           claude     local
  postgres             claude     local
  github               claude     local
  slack                cursor     local
  jira                 cursor     local

  AI Config Files (3 found)
  -----------------------------------------------
  CLAUDE.md            project    governance rules
  .cursorrules         project    editor config
  .copilot/config.yml  project    copilot settings

  Governance Score     32 / 100

  Findings
  -----------------------------------------------
  - Project not registered (no AIM identity)
  - No SOUL.md behavioral governance file
  - 5 MCP servers ungoverned (no capability restrictions)
  - 3 credentials detected in source files
  - Config files unsigned
  - Local model (ollama) running without audit trail

  Run: opena2a protect    (fix all findings)
```

Key observations for security teams:
- **AI Agents** shows every AI coding assistant running on the machine, including local models like Ollama that bypass corporate API gateways.
- **MCP Servers** reveals what external services AI agents can access. A postgres MCP server means Claude can execute database queries. A slack MCP server means it can send messages.
- **Governance Score** provides a single number (0-100) for executive reporting.

---

## Step 2: Generate an Executive Report

Create an HTML report suitable for sharing with leadership or including in security reviews.

```bash
npx opena2a-cli detect --report
```

Expected output:

```
  Shadow AI Detection  v0.7.2

  Scanning dev-laptop-042...

  Report generated: shadow-ai-report.html

  Summary
  -----------------------------------------------
  AI Agents          3 running
  MCP Servers        5 configured
  Config Files       3 found
  Governance Score   32 / 100
  Critical Findings  2

  Opened shadow-ai-report.html in browser
```

The HTML report includes:
- Executive summary with governance score
- Full inventory of AI agents, MCP servers, and config files
- Risk breakdown by category (credentials, governance, integrity, access)
- Remediation steps ordered by severity
- Machine metadata (hostname, OS, username, scan time) for audit trails

To save the report to a specific location without opening a browser:

```bash
npx opena2a-cli detect --report --no-open
```

---

## Step 3: Export Asset Inventory

Export the discovery results as CSV for import into your CMDB, SIEM, or asset management system.

```bash
npx opena2a-cli detect --export-csv assets.csv
```

Expected output:

```
  Shadow AI Detection  v0.7.2

  Scanning dev-laptop-042...

  Exported 11 assets to assets.csv

  Breakdown
  -----------------------------------------------
  AI Agents          3
  MCP Servers        5
  Config Files       3

  Governance Score   32 / 100
```

The CSV file includes these columns:

```csv
hostname,username,scanDirectory,scanTimestamp,assetType,name,platform,scope,status,details
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,ai-agent,claude-code,,machine,running,PID 41023 v1.0.12
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,ai-agent,cursor,,machine,running,PID 38291 v0.45.6
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,ai-agent,ollama,,machine,running,PID 52100 v0.3.14 local model
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,mcp-server,filesystem,claude,local,configured,
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,mcp-server,postgres,claude,local,configured,
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,mcp-server,github,claude,local,configured,
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,mcp-server,slack,cursor,local,configured,
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,mcp-server,jira,cursor,local,configured,
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,config-file,CLAUDE.md,,project,found,governance rules
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,config-file,.cursorrules,,project,found,editor config
dev-laptop-042,jsmith,/home/jsmith/payments-api,2026-03-15T10:30:00Z,config-file,.copilot/config.yml,,project,found,copilot settings
```

Each row includes `hostname`, `username`, `scanDirectory`, and `scanTimestamp` so you can aggregate results from multiple machines into a single spreadsheet or database.

---

## Step 4: Enrich with Community Trust Data

Cross-reference discovered MCP servers against the OpenA2A Trust Registry to see community trust scores, known vulnerabilities, and verification status.

```bash
npx opena2a-cli detect --registry
```

Expected output:

```
  Shadow AI Detection  v0.7.2

  Scanning dev-laptop-042...
  Enriching with Trust Registry data...

  MCP Servers (5 configured)
  -----------------------------------------------
  filesystem           claude     local      trust: 0.92   verified
  postgres             claude     local      trust: 0.87   verified
  github               claude     local      trust: 0.94   verified
  slack                cursor     local      trust: 0.78   unverified
  jira                 cursor     local      trust: --     not in registry

  Registry Findings
  -----------------------------------------------
  - slack: 2 known advisories (medium severity)
  - jira: not registered in Trust Registry (unknown provenance)

  Governance Score   32 / 100
```

The `--registry` flag queries the public Trust Registry API. Servers marked "verified" have had their identity cryptographically confirmed by the publisher. Servers not in the registry may be custom or internal tools -- they are not necessarily unsafe, but they lack community vetting.

---

## Step 5: Full Security Review

Run a comprehensive 6-phase security assessment that combines credential scanning, config integrity, shadow AI detection, behavioral governance, advisory checks, and optional deep scanning.

```bash
npx opena2a-cli review
```

Expected output:

```
  OpenA2A Security Review  v0.7.2

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

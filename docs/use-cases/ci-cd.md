# Adding AI Security to Your CI/CD Pipeline

You want to automate AI security checks in your CI/CD pipeline. This guide covers GitHub Actions integration with detection, review, and trust gating.

**Time estimate:** 15 minutes to set up a complete CI/CD security gate.

**Prerequisites:**
- A GitHub repository
- Node.js 18 or later available in your CI environment
- Familiarity with GitHub Actions (or equivalent CI system)

---

## Quick Start: Three-Step GitHub Actions Workflow

This workflow runs on every pull request and blocks merges when critical findings are detected.

```yaml
# .github/workflows/ai-security.yml
name: AI Security Gate
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  ai-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      # Step 1: Detect shadow AI and check governance
      - name: Shadow AI detection
        run: npx opena2a-cli detect --format json --ci > detect-results.json

      # Step 2: Full security review
      - name: Security review
        run: npx opena2a-cli review --format json --ci > review-results.json

      # Step 3: Trust score gate
      - name: Trust gate
        run: |
          score=$(jq -r '.governanceScore' detect-results.json)
          echo "Governance score: $score / 100"
          if [ "$score" -lt 60 ]; then
            echo "Governance score $score is below the required threshold of 60"
            jq '.findings' detect-results.json
            exit 1
          fi
```

---

## Understanding CLI Flags for CI

### The `--ci` Flag

The `--ci` flag adjusts behavior for non-interactive environments:

- Disables color output and interactive prompts
- Disables browser auto-open for HTML reports
- Uses compact output formatting
- Ensures deterministic exit codes

```bash
npx opena2a-cli detect --ci           # No colors, no prompts
npx opena2a-cli review --ci           # No browser open
npx opena2a-cli scan-soul --ci        # Deterministic output
```

### The `--format json` Flag

Returns machine-readable JSON for programmatic consumption:

```bash
npx opena2a-cli detect --format json
```

Example JSON output:

```json
{
  "version": "0.7.2",
  "hostname": "runner-abc123",
  "username": "runner",
  "scanDirectory": "/home/runner/work/my-project",
  "scanTimestamp": "2026-03-15T10:30:00Z",
  "agents": [
    {
      "name": "claude-code",
      "status": "configured",
      "details": "config file present"
    }
  ],
  "mcpServers": [
    {
      "name": "filesystem",
      "platform": "claude",
      "scope": "local",
      "signed": false
    }
  ],
  "configFiles": [
    {
      "name": "CLAUDE.md",
      "type": "governance",
      "signed": false
    }
  ],
  "governanceScore": 45,
  "findings": [
    {
      "severity": "medium",
      "category": "governance",
      "message": "No SOUL.md behavioral governance file"
    }
  ]
}
```

### The `--json` Flag

Some commands use `--json` instead of `--format json` (both are accepted):

```bash
npx opena2a-cli scan-soul --json      # SOUL.md governance scan
npx opena2a-cli protect --dry-run --json  # Credential check
npx opena2a-cli review --format json  # Full review
```

---

## Exit Codes

All opena2a commands use consistent exit codes:

| Exit Code | Meaning | CI Behavior |
|-----------|---------|-------------|
| 0 | No findings, or all findings are info/low | Pipeline passes |
| 1 | Critical or high findings detected | Pipeline fails |
| 2 | Command error (invalid args, missing files) | Pipeline fails |

For governance gating with a custom threshold:

```bash
npx opena2a-cli scan-soul --fail-below 60
# Exit 0 if score >= 60
# Exit 1 if score < 60
```

---

## Complete Workflow: Detection + Review + Governance + Credentials

A comprehensive workflow that runs four independent checks in parallel:

```yaml
# .github/workflows/ai-security-full.yml
name: AI Security Suite
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  # Job 1: Shadow AI detection and governance scoring
  detect:
    runs-on: ubuntu-latest
    outputs:
      governance-score: ${{ steps.detect.outputs.score }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Detect shadow AI
        id: detect
        run: |
          npx opena2a-cli detect --format json --ci > detect.json
          score=$(jq -r '.governanceScore' detect.json)
          echo "score=$score" >> "$GITHUB_OUTPUT"
          echo "Governance score: $score / 100"
          jq '.' detect.json

      - name: Upload detection report
        uses: actions/upload-artifact@v4
        with:
          name: shadow-ai-report
          path: detect.json

  # Job 2: Full security review
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Security review
        run: |
          npx opena2a-cli review --format json --ci > review.json
          critical=$(jq '[.findings[] | select(.severity == "critical")] | length' review.json)
          high=$(jq '[.findings[] | select(.severity == "high")] | length' review.json)
          echo "Critical: $critical, High: $high"
          if [ "$critical" -gt 0 ] || [ "$high" -gt 0 ]; then
            echo "Blocking findings detected"
            jq '[.findings[] | select(.severity == "critical" or .severity == "high")]' review.json
            exit 1
          fi

      - name: Upload review report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-review
          path: review.json

  # Job 3: Behavioral governance
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: SOUL.md governance scan
        run: npx opena2a-cli scan-soul --json --ci --fail-below 60

  # Job 4: Credential scan
  credentials:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Credential check
        run: |
          npx opena2a-cli protect --dry-run --json --ci > creds.json
          found=$(jq -r '.totalFound' creds.json)
          echo "Credentials found: $found"
          if [ "$found" -gt 0 ]; then
            jq '.credentials' creds.json
            exit 1
          fi

  # Gate: all checks must pass
  security-gate:
    needs: [detect, review, governance, credentials]
    runs-on: ubuntu-latest
    steps:
      - name: Governance score threshold
        run: |
          score=${{ needs.detect.outputs.governance-score }}
          echo "Final governance score: $score / 100"
          if [ "$score" -lt 60 ]; then
            echo "Governance score $score is below the required threshold of 60"
            exit 1
          fi
          echo "All security checks passed"
```

---

## HackMyAgent Deep Scan

For repositories with MCP servers or AI agent code, add a HackMyAgent deep scan:

```yaml
  # Add this job to the workflow above
  hma-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: HackMyAgent security scan
        run: |
          npx hackmyagent secure --ci --format json > hma.json
          critical=$(jq -r '.summary.critical' hma.json)
          high=$(jq -r '.summary.high' hma.json)
          echo "HMA: $critical critical, $high high findings"
          if [ "$critical" -gt 0 ]; then
            echo "Critical vulnerabilities detected"
            jq '.findings[] | select(.severity == "critical")' hma.json
            exit 1
          fi

      - name: Upload HMA report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: hma-report
          path: hma.json
```

---

## GitHub Actions from OpenA2A

Two pre-built GitHub Actions simplify integration:

### trust-gate-action

Blocks merges when the trust score drops below a threshold:

```yaml
- name: Trust gate
  uses: opena2a-org/trust-gate-action@v1
  with:
    threshold: 0.70
    fail-on-unsigned: true
```

Repository: [opena2a-org/trust-gate-action](https://github.com/opena2a-org/trust-gate-action)

### trust-badge-action

Generates a trust score badge for your README:

```yaml
- name: Update trust badge
  uses: opena2a-org/trust-badge-action@v1
  with:
    output-path: .github/badges/trust-score.svg
```

Repository: [opena2a-org/trust-badge-action](https://github.com/opena2a-org/trust-badge-action)

Add the badge to your README:

```markdown
![Trust Score](https://img.shields.io/endpoint?url=https://registry.opena2a.org/badge/your-package)
```

---

## Other CI Systems

The commands work in any CI environment with Node.js. Here are examples for other platforms.

### GitLab CI

```yaml
# .gitlab-ci.yml
ai-security:
  image: node:20
  stage: test
  script:
    - npx opena2a-cli detect --format json --ci > detect.json
    - npx opena2a-cli review --format json --ci > review.json
    - npx opena2a-cli scan-soul --json --ci --fail-below 60
    - |
      critical=$(cat review.json | jq '[.findings[] | select(.severity == "critical")] | length')
      if [ "$critical" -gt 0 ]; then
        echo "Critical findings detected"
        exit 1
      fi
  artifacts:
    paths:
      - detect.json
      - review.json
    when: always
```

### Azure Pipelines

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include: [main]

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '20.x'

  - script: npx opena2a-cli detect --format json --ci > detect.json
    displayName: Shadow AI Detection

  - script: npx opena2a-cli review --format json --ci > review.json
    displayName: Security Review

  - script: npx opena2a-cli scan-soul --json --ci --fail-below 60
    displayName: Governance Gate

  - publish: $(System.DefaultWorkingDirectory)/detect.json
    artifact: shadow-ai-report
    condition: always()
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1
jobs:
  ai-security:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run:
          name: Shadow AI detection
          command: npx opena2a-cli detect --format json --ci > detect.json
      - run:
          name: Security review
          command: npx opena2a-cli review --format json --ci > review.json
      - run:
          name: Governance gate
          command: npx opena2a-cli scan-soul --json --ci --fail-below 60
      - store_artifacts:
          path: detect.json
      - store_artifacts:
          path: review.json

workflows:
  security:
    jobs:
      - ai-security
```

---

## CSV Export for Compliance Reporting

Generate CSV reports in CI for compliance dashboards:

```yaml
- name: Generate compliance report
  run: |
    npx opena2a-cli detect --export-csv assets.csv --ci
    echo "Assets discovered:"
    wc -l assets.csv

- name: Upload compliance report
  uses: actions/upload-artifact@v4
  with:
    name: asset-inventory
    path: assets.csv
```

---

## Scheduling Periodic Scans

Run weekly scans across your organization's repositories:

```yaml
# .github/workflows/weekly-scan.yml
name: Weekly AI Security Scan
on:
  schedule:
    - cron: '0 9 * * 1'  # Every Monday at 9 AM UTC
  workflow_dispatch:       # Allow manual trigger

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Full security review
        run: |
          npx opena2a-cli review --format json --ci > review.json
          npx opena2a-cli detect --export-csv assets.csv --ci

      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: weekly-scan-${{ github.run_id }}
          path: |
            review.json
            assets.csv
          retention-days: 90
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| `npx opena2a-cli` hangs | npm prompting for install confirmation | Use `npx -y opena2a-cli` |
| Exit code 2 on `scan-soul` | No SOUL.md file in repository | Create one with `opena2a harden-soul` first |
| JSON parse errors | Command outputting text warnings before JSON | Use `--ci` flag to suppress non-JSON output |
| High download times | npx downloading on every run | Cache node_modules or install globally in a setup step |

### Caching for Faster Runs

```yaml
- name: Cache node modules
  uses: actions/cache@v4
  with:
    path: ~/.npm
    key: ${{ runner.os }}-npm-opena2a
    restore-keys: |
      ${{ runner.os }}-npm-

- name: Install opena2a-cli
  run: npm install -g opena2a-cli

- name: Run detection
  run: opena2a detect --format json --ci > detect.json
```

---

## Related Use Cases

- [Developer using AI coding tools](./developer.md)
- [Security team assessing AI risk](./security-team.md)
- [MCP server author](./mcp-server-author.md)
- [Full documentation](https://opena2a.org/docs)

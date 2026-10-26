# Adding AI Security to Your CI/CD Pipeline

You want to automate AI security checks in your CI/CD pipeline. This guide covers GitHub Actions integration with detection, review, and trust gating.

**Time estimate:** 15 minutes to set up a complete CI/CD security gate.

**Prerequisites:**
- A GitHub repository
- Node.js 20.19 or later available in your CI environment
- Familiarity with GitHub Actions (or equivalent CI system)

---

## Quick Start: Three-Step GitHub Actions Workflow

This workflow runs on every pull request and fails when the review score is below 50 or the governance score is below 60. `detect` exits 0 whatever it finds, so step 3 reads the score from its JSON.

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
        working-directory: ${{ runner.temp }}
        run: npx opena2a-cli detect "$GITHUB_WORKSPACE" --format json --ci > "$GITHUB_WORKSPACE/detect-results.json"

      # Step 2: Full security review
      - name: Security review
        working-directory: ${{ runner.temp }}
        run: npx opena2a-cli review "$GITHUB_WORKSPACE" --format json --ci > "$GITHUB_WORKSPACE/review-results.json"

      # Step 3: Trust score gate
      - name: Trust gate
        run: |
          score=$(jq -r '.summary.governanceScore' detect-results.json)
          echo "Governance score: $score / 100"
          if ! [ "$score" -ge 60 ]; then
            echo "Governance score $score is below the required threshold of 60"
            jq '.findings' detect-results.json
            exit 1
          fi
```

---

## Understanding CLI Flags for CI

### The `--ci` Flag

`--ci` does something different in each command, and each command's `--help` states it under `Automation:`. It does not turn color off: color is off when `NO_COLOR` is set or when stdout is not a terminal, as in a CI log or a `>` redirect. With `--ci`:

- `detect`: never asks before scanning unknown MCP packages, does not open the `--report` file, and does not share the summary; with `--auto-scan` and contributions enabled, each unknown server scan is still shared
- `review`: does not open the report in a browser
- `scan-soul`: no effect
- `protect`: migrates without prompting (needed when stdin is not a terminal)

```bash
npx opena2a-cli detect my-agent --ci      # No prompts, no browser, no shared summary
npx opena2a-cli review my-agent --ci      # No browser open
npx opena2a-cli scan-soul my-agent --ci   # Same as without --ci
```

### The `--format json` Flag

Returns machine-readable JSON for programmatic consumption:

```bash
npx opena2a-cli detect my-agent --format json
```

Example JSON output, abridged to one entry per array with some fields left out. The score is `.summary.governanceScore`:

```json
{
  "scanTimestamp": "2026-10-11T10:43:53.673Z",
  "scanDirectory": "/home/runner/work/my-project/my-project",
  "agents": [
    {
      "name": "Claude Code",
      "category": "ai-assistant",
      "identityStatus": "no identity",
      "governanceStatus": "no governance",
      "risk": "high"
    }
  ],
  "mcpServers": [
    {
      "name": "filesystem",
      "source": ".mcp.json (project)",
      "verified": false,
      "capabilities": ["filesystem"],
      "risk": "medium"
    }
  ],
  "aiConfigs": [{ "file": "CLAUDE.md", "tool": "Claude Code", "risk": "low" }],
  "summary": {
    "totalAgents": 2,
    "governanceScore": 15,
    "recoverablePoints": 85
  },
  "findings": [
    {
      "severity": "high",
      "category": "governance",
      "title": "2 AI agents running without governance"
    }
  ]
}
```

### The `--json` Flag

Some commands use `--json` instead of `--format json` (both are accepted):

```bash
npx opena2a-cli scan-soul my-agent --json          # SOUL.md governance scan
npx opena2a-cli protect my-agent --dry-run --json  # Credential check
npx opena2a-cli review my-agent --format json      # Full review
```

---

## Exit Codes

Each command has its own exit codes, listed at the end of its `--help` under `Exit codes:`. A step fails on any status other than 0. For the commands this guide runs:

| Command | Exit 0 | Exit 1 | Exit 2 |
|---------|--------|--------|--------|
| `detect` | discovery finished, whatever it found, critical findings included | the directory cannot be read, or the `--report` or `--export-csv` file could not be written | an unsupported `--format` |
| `review` | the composite score is 50 or higher | the score is below 50 | the directory does not exist, an unsupported `--format`, `--quiet` together with `--verbose`, or the HTML report could not be written |
| `scan-soul` | the governance score is 60 or higher (with `--strict`, also no critical control missing) | the score is below 60 (a directory with no SOUL.md scores 0), a critical control is missing under `--strict`, the scanner is unavailable, or the scan failed | not returned |
| `protect --dry-run` | nothing was found, or text credentials were found (count them with `.totalFound`) | the directory does not exist, or no text credential was found but key files were, which protect cannot migrate | not returned without `--grant`; `opena2a protect --help` lists 2 to 6 |

To fail on what `detect` finds, read its JSON, as the score gates in this guide do. `--strict` adds the critical SOUL controls to the `scan-soul` score check:

```bash
npx opena2a-cli scan-soul my-agent --strict
# Exit 0 if the score is 60 or higher and SOUL-IH-003 and SOUL-HB-001 both pass
# Exit 1 if the score is below 60, or SOUL-IH-003 or SOUL-HB-001 is missing
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
        working-directory: ${{ runner.temp }}
        run: |
          npx opena2a-cli detect "$GITHUB_WORKSPACE" --format json --ci > "$GITHUB_WORKSPACE/detect.json"
          score=$(jq -r '.summary.governanceScore' "$GITHUB_WORKSPACE/detect.json")
          echo "score=$score" >> "$GITHUB_OUTPUT"
          echo "Governance score: $score / 100"
          jq '.' "$GITHUB_WORKSPACE/detect.json"

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
        working-directory: ${{ runner.temp }}
        run: |
          npx opena2a-cli review "$GITHUB_WORKSPACE" --format json --ci > "$GITHUB_WORKSPACE/review.json"
          cd "$GITHUB_WORKSPACE"
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
        working-directory: ${{ runner.temp }}
        run: npx opena2a-cli scan-soul "$GITHUB_WORKSPACE" --json --ci --strict

  # Job 4: Credential scan
  credentials:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Credential check
        working-directory: ${{ runner.temp }}
        run: |
          npx opena2a-cli protect "$GITHUB_WORKSPACE" --dry-run --json --ci > creds.json
          found=$(jq -r '.totalFound' creds.json)
          echo "Credentials found: $found"
          if [ "$found" -gt 0 ]; then
            # Each .results[].credential carries the secret in .value: print only where it is.
            jq '[.results[].credential | {findingId, filePath, line, envVar}]' creds.json
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
          if ! [ "$score" -ge 60 ]; then
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
        working-directory: ${{ runner.temp }}
        run: |
          npx hackmyagent secure "$GITHUB_WORKSPACE" --ci --format json > hma.json
          critical=$(jq -r '[.findings[] | select(.severity == "critical")] | length' hma.json)
          high=$(jq -r '[.findings[] | select(.severity == "high")] | length' hma.json)
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
          path: ${{ runner.temp }}/hma.json
```

---

## GitHub Actions from OpenA2A

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
    # Run from outside the checkout, naming it as the operand, so a
    # committed .npmrc in the scanned tree cannot inject into npx itself.
    - cd /tmp
    - npx opena2a-cli detect "$CI_PROJECT_DIR" --format json --ci > "$CI_PROJECT_DIR/detect.json"
    - npx opena2a-cli review "$CI_PROJECT_DIR" --format json --ci > "$CI_PROJECT_DIR/review.json"
    - npx opena2a-cli scan-soul "$CI_PROJECT_DIR" --json --ci --strict
    - |
      critical=$(cat "$CI_PROJECT_DIR/review.json" | jq '[.findings[] | select(.severity == "critical")] | length')
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

  - script: npx opena2a-cli detect "$(Build.SourcesDirectory)" --format json --ci > "$(Build.SourcesDirectory)/detect.json"
    displayName: Shadow AI Detection
    workingDirectory: $(Agent.TempDirectory)

  - script: npx opena2a-cli review "$(Build.SourcesDirectory)" --format json --ci > "$(Build.SourcesDirectory)/review.json"
    displayName: Security Review
    workingDirectory: $(Agent.TempDirectory)

  - script: npx opena2a-cli scan-soul "$(Build.SourcesDirectory)" --json --ci --strict
    displayName: Governance Gate
    workingDirectory: $(Agent.TempDirectory)

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
      - image: cimg/node:20.19
    steps:
      - checkout
      - run:
          name: Shadow AI detection
          working_directory: /tmp
          command: npx opena2a-cli detect ~/project --format json --ci > ~/project/detect.json
      - run:
          name: Security review
          working_directory: /tmp
          command: npx opena2a-cli review ~/project --format json --ci > ~/project/review.json
      - run:
          name: Governance gate
          working_directory: /tmp
          command: npx opena2a-cli scan-soul ~/project --json --ci --strict
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
  working-directory: ${{ runner.temp }}
  run: |
    npx opena2a-cli detect "$GITHUB_WORKSPACE" --export-csv "$GITHUB_WORKSPACE/assets.csv" --ci
    echo "Assets discovered:"
    wc -l "$GITHUB_WORKSPACE/assets.csv"

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
        working-directory: ${{ runner.temp }}
        run: |
          npx opena2a-cli review "$GITHUB_WORKSPACE" --format json --ci > "$GITHUB_WORKSPACE/review.json"
          npx opena2a-cli detect "$GITHUB_WORKSPACE" --export-csv "$GITHUB_WORKSPACE/assets.csv" --ci

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
| Exit code 1 on `scan-soul` | No SOUL.md in the scanned directory (it scores 0), or a score below 60 | Create one with `opena2a harden-soul` first |
| JSON parse errors | Notices on stderr were captured into the JSON file, for example with `2>&1` | Redirect stdout only (`> file.json`); the JSON goes to stdout and notices to stderr |
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
  working-directory: ${{ runner.temp }}
  run: opena2a detect "$GITHUB_WORKSPACE" --format json --ci > "$GITHUB_WORKSPACE/detect.json"
```

---

## Related Use Cases

- [Developer using AI coding tools](./developer.md)
- [Security team assessing AI risk](./security-team.md)
- [MCP server author](./mcp-server-author.md)
- [Full documentation](https://opena2a.org/docs)

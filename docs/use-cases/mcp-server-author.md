# I Build MCP Servers

You develop or maintain MCP (Model Context Protocol) servers. You want to ensure your server is secure, trusted by the community, and discoverable in the OpenA2A Trust Registry.

**Time estimate:** 10 minutes for a full audit, signing, and registration.

**Prerequisites:**
- Node.js 20.19 or later
- An MCP server project directory
- npm account (for publishing and trust verification)

---

## Step 1: See How Your Server Looks to Users

Before users install your MCP server, they may run an audit to check its security posture. See what they see:

```bash
npx opena2a-cli mcp audit
```

Captured from opena2a-cli v0.10.13 on 2026-09-04; the config file path is replaced with a fixed placeholder:
```
MCP Server Audit
==================================================

Source: /home/dev/mcp-server-tools/.mcp.json (project-local)
  my-server            stdio    node ./dist/index.js                           not signed  no trust score
  filesystem           stdio    npx @modelcontextprotocol/server-filesystem .  not signed  no trust score
  postgres             stdio    npx @modelcontextprotocol/server-postgres      not signed  no trust score
  github               stdio    npx @modelcontextprotocol/server-github        not signed  no trust score

Summary
  Servers found:     4
  Signed:            0 / 4
  Verified:          0 / 4
  Trust scores:      0 / 4

Next Steps
  opena2a mcp sign <name>       Sign an MCP server with AIM identity
  opena2a mcp verify <name>     Verify server signature and trust score
```

Each row is one configured server: the transport it speaks, the command that launches it, whether a signature for it exists under `.opena2a/mcp-identities/`, and its registry trust score. `no trust score` means the registry held no record of that server when the audit ran -- which is what every unregistered server looks like, yours included, until Step 5. `Verified` in the summary counts something stricter than `Signed`: a signature whose recorded config hash still matches the command line in the config file today.

---

## Step 2: Sign Your Server

Signing creates a cryptographic attestation that links your MCP server package to your identity. Users who install your server can verify that the binary they received matches what you published.

First, ensure you have an identity:

```bash
npx opena2a-cli identity create --name my-server
```

Expected output:

```
  Agent Identity Created

  Name         my-server
  Agent ID     agent:ed25519:k1_b7c4...9f1a
  Key Type     Ed25519
  Created      2026-03-15T11:00:00Z
  Storage      .aim/identity.json

  The private key is stored locally. It never leaves this machine.
```

Then sign the server:

```bash
npx opena2a-cli mcp sign my-server
```

Expected output:

```
  MCP Server Signing

  Server       my-server
  Package      @myorg/mcp-server-tools@1.2.0
  Identity     agent:ed25519:k1_b7c4...9f1a

  Actions
  -----------------------------------------------
  Generated SHA-256 digest of server binary
  Created signature with Ed25519 private key
  Wrote .aim/signatures/my-server.sig

  Verification
  -----------------------------------------------
  Signature valid: YES
  Digest match:    YES

  Users can verify with:
    npx opena2a-cli verify @myorg/mcp-server-tools
```

The signature file (`.aim/signatures/my-server.sig`) should be included in your npm package so users can verify it after installation.

---

## Step 3: Run Security Checks

Run a full security scan against your MCP server project to catch vulnerabilities before your users do.

```bash
npx hackmyagent secure
```

Expected output:

```
  HackMyAgent  v0.10.4

  Scanning /home/dev/mcp-server-tools...
  187 checks across 39 categories

  Results
  -----------------------------------------------
  Critical     0
  High         0
  Medium       2
  Low          1
  Info         2

  Findings
  -----------------------------------------------
  MEDIUM   MCP-CONFIG-001   No capability restrictions in server manifest
           Verify: cat mcp.json | jq '.capabilities'
           Fix:    Add explicit tool/resource allowlists to mcp.json

  MEDIUM   SOUL-001         No SOUL.md governance file
           Verify: ls SOUL.md
           Fix:    opena2a harden-soul

  LOW      SIGN-001         Config files not signed
           Verify: opena2a guard verify
           Fix:    opena2a guard sign

  Score    78 / 100

  Run: opena2a harden-soul    (address governance gap)
  Run: opena2a guard sign     (sign config files)
```

Address at least all critical and high findings before publishing. Medium findings are recommended but not blocking.

For MCP servers specifically, pay attention to:
- **Capability restrictions**: Define exactly which tools and resources your server exposes. Open-ended capabilities increase the attack surface for users.
- **Input validation**: Ensure all tool inputs are validated. HackMyAgent checks for common injection patterns.
- **Dependency vulnerabilities**: Keep dependencies updated. HMA scans `node_modules` for known CVEs.

---

## Step 4: Check Your Trust Rating

Users who look your server up before installing it see the trust rating the OpenA2A Trust Registry holds for your published package. `ai-trust` reads that record:

```bash
npx ai-trust check @myorg/mcp-server-tools --no-scan
```

`check` expects the name your package is published under. Given a directory or the server's name from `.mcp.json`, it does not check your server. `ai-trust check . --no-scan` looks for a package called `.` and reports it not found. Without `--no-scan`, `ai-trust check .` runs `npm pack` on the current directory, which runs that directory's `prepack` script if it has one, and then exits 1 because the packed package is not named `.`. `ai-trust check my-server` reports whichever unrelated npm package holds the name `my-server`.

With `--no-scan` the command reads the registry record only. It shows the trust score out of 100, the trust level on the scale `Blocked > Warning > Listed > Scanned > Verified`, how many community scans stand behind the record, and how long ago the last one ran. A package the registry has no record of is reported as not found, with `--scan-if-missing` as the next step. Without `--no-scan`, `check` also downloads the latest published version, scans it with HackMyAgent and reports that scan's score; each such scan sends the registry the package name, the verdict and the score. Given the published name, neither path reads your working tree, so the rating moves when a published version is scanned again, not when you commit.

Add `--json` for a machine-readable result: `name` and `packageType` identify the package, and the fields below carry the rating. A local scan adds `score`, `maxScore` and its failed `findings`. No sample run is pasted here: `ai-trust` ships from its own repository on its own release cadence, so a copy of its output frozen into this page ages the moment it publishes.

| Field | Value |
|-------|-------|
| `source` | `registry`, or `scan` after a local scan |
| `found` | `false` when the registry has no record of the package, and there is then no `trustScore` |
| `verdict`, `trustLevel` | The verdict and trust level the score belongs to |
| `trustScore` | The trust score, a number between 0 and 1 |

---

## Step 5: Register with the Community

To claim your own package in the OpenA2A Trust Registry, use `opena2a claim`. It proves ownership through npm package maintainership or GitHub repository access, which is what stops anyone else from registering your name:

```bash
npx opena2a-cli claim @myorg/mcp-server-tools
npx opena2a-cli claim @myorg/mcp-server-tools --source github
```

`self-register` is a different command, and a common mix-up. It does not take a package argument and it will not register your server: it publishes the OpenA2A project's own tools -- a fixed list of eleven, compiled into the CLI -- along with their security scan results. It is a maintainer command for this repository. Run it with `--dry-run` to see the list without writing anything to the registry:

```bash
npx opena2a-cli self-register --dry-run
```

Captured from opena2a-cli v0.10.13 on 2026-09-04:
```
Registering 11 OpenA2A tool(s) at https://api.oa2a.org

[DRY RUN] No HTTP requests will be made.


Tool                       Status  Scan     Crit  High  Med  Low  Published
-------------------------  ------  -------  ----  ----  ---  ---  ---------
HackMyAgent                new     skipped  -     -     -    -    dry-run  
Secretless AI              new     skipped  -     -     -    -    dry-run  
Agent Runtime Protection   new     skipped  -     -     -    -    dry-run  
OASB Benchmark             new     skipped  -     -     -    -    dry-run  
BrowserGuard               new     skipped  -     -     -    -    dry-run  
AI Trust                   new     skipped  -     -     -    -    dry-run  
OpenA2A Registry           new     skipped  -     -     -    -    dry-run  
Agent Identity Management  new     skipped  -     -     -    -    dry-run  
Damn Vulnerable AI Agent   new     skipped  -     -     -    -    dry-run  
CryptoServe                new     skipped  -     -     -    -    dry-run  
Trust Gate                 new     skipped  -     -     -    -    dry-run  

Summary: 11 tools, 0 scanned, 5 metadata-only, 0 errors
Registry: https://api.oa2a.org
```

Without `--dry-run` the command asks before it writes, because the registry is public and the CLI cannot undo a publish. Each row is one tool: `Scan` is the HackMyAgent result behind the published record (`skipped` under `--dry-run`, which runs no scans), and `Published` says whether the record went out with scan findings or as metadata only.

After a successful claim, your server appears in `detect --registry` results with its trust score, and its row carries `Trust: <score>/100` instead of `No trust data`.

---

## Maintaining Your Server

After the initial setup, keep your trust score current:

| When | Command | Purpose |
|------|---------|---------|
| Before each publish | `npx hackmyagent secure` | Catch new vulnerabilities |
| After version bump | `opena2a mcp sign my-server` | Re-sign with new version |
| After version bump | `opena2a self-register` | Update registry entry |
| After each publish | `npx ai-trust check @myorg/mcp-server-tools` | Scan the published version; confirm the score did not drop |
| After adding tools | `opena2a scan-soul` | Ensure governance covers new capabilities |

### CI/CD Integration

Add these checks to your CI pipeline to maintain trust automatically:

```yaml
# .github/workflows/mcp-trust.yml
name: MCP Trust Gate
on: [push, pull_request]

jobs:
  trust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Security scan
        run: npx hackmyagent secure --ci

      - name: Governance check
        working-directory: ${{ runner.temp }}
        run: npx opena2a-cli scan-soul "$GITHUB_WORKSPACE" --strict

      - name: Trust score gate
        run: |
          npx ai-trust check @myorg/mcp-server-tools --no-scan --json > trust.json
          score=$(jq -r '.trustScore // empty' trust.json)
          if [ -z "$score" ]; then
            echo "The registry returned no trust score for @myorg/mcp-server-tools"
            exit 1
          fi
          if ! jq -e '.trustScore >= 0.70' trust.json > /dev/null; then
            echo "Trust score $score is below 0.70 threshold"
            exit 1
          fi
```

The gate reads the registry's record of your published package, as in Step 4. `check` exits 2 when the registry's verdict is `blocked` or `warning`, which stops the step before the score comparison runs, and a package the registry has no score for fails the step rather than passing it.

---

## Related Use Cases

- [Developer using AI coding tools](./developer.md)
- [Security team assessing AI risk](./security-team.md)
- [CI/CD pipeline integration](./ci-cd.md)
- [Full documentation](https://opena2a.org/docs)

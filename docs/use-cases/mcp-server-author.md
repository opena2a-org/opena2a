# I Build MCP Servers

You develop or maintain MCP (Model Context Protocol) servers. You want to ensure your server is secure, trusted by the community, and discoverable in the OpenA2A Trust Registry.

**Time estimate:** 10 minutes for a full audit, signing, and registration.

**Prerequisites:**
- Node.js 18 or later
- An MCP server project directory
- npm account (for publishing and trust verification)

---

## Step 1: See How Your Server Looks to Users

Before users install your MCP server, they may run an audit to check its security posture. See what they see:

```bash
npx opena2a-cli mcp audit
```

Expected output:

```
  MCP Server Audit  v0.7.2

  Scanning MCP configurations...

  Servers Found (4)
  -----------------------------------------------
  my-server            claude     local
  filesystem           claude     local
  postgres             claude     local
  github               cursor     local

  Detailed Audit: my-server
  -----------------------------------------------
  Package          @myorg/mcp-server-tools
  Version          1.2.0
  Source           npm
  Signature        unsigned
  Trust Score      --  (not registered)

  Capabilities Declared
  -----------------------------------------------
  tools            3 tools exposed
  resources        1 resource type
  prompts          0

  Security Checks
  -----------------------------------------------
  PASS   No known CVEs for dependencies
  PASS   Package checksum matches npm registry
  WARN   Server binary not signed
  WARN   No capability restrictions defined
  WARN   Not registered in Trust Registry
  FAIL   No SOUL.md governance file

  Audit Score      55 / 100

  To improve:
    1. Sign your server:     opena2a mcp sign my-server
    2. Add governance:       opena2a harden-soul
    3. Register publicly:    opena2a self-register
```

The audit checks what users see when they evaluate your server: whether it is signed, whether it has known vulnerabilities, whether its capabilities are declared and restricted, and whether it appears in the Trust Registry.

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
  MCP Server Signing  v0.7.2

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

## Step 4: Check Your Trust Score

The trust score is a composite metric that reflects your server's security posture, community standing, and verification status.

```bash
npx ai-trust check my-server
```

Expected output:

```
  AI Trust  v0.4.2

  Package    @myorg/mcp-server-tools@1.2.0

  Trust Score    0.72 / 1.00

  Factor Breakdown
  -----------------------------------------------
  Identity           0.15 / 0.20    Ed25519 identity present
  Signature          0.15 / 0.20    Package signed
  Governance         0.10 / 0.15    SOUL.md present, 48/54 controls
  Vulnerability      0.12 / 0.15    No critical/high CVEs
  Community          0.05 / 0.15    12 weekly downloads, 3 dependents
  Provenance         0.15 / 0.15    npm publish attestation verified

  Recommendations
  -----------------------------------------------
  +0.05   Complete remaining 6 SOUL.md controls
  +0.10   Increase adoption (community factor is usage-weighted)

  History
  -----------------------------------------------
  v1.0.0   0.45   initial publish
  v1.1.0   0.58   added identity + signature
  v1.2.0   0.72   added governance
```

The trust score is calculated locally using publicly available signals. No data is uploaded. The factors are:

| Factor | Weight | What It Measures |
|--------|--------|------------------|
| Identity | 0.20 | Cryptographic identity exists and is valid |
| Signature | 0.20 | Package is signed and signature matches |
| Governance | 0.15 | SOUL.md coverage of ABGS controls |
| Vulnerability | 0.15 | Known CVEs in dependencies |
| Community | 0.15 | Download count, dependent packages |
| Provenance | 0.15 | npm publish attestation, GitHub Actions provenance |

---

## Step 5: Register with the Community

Publish your server's trust profile to the OpenA2A Trust Registry so users can look you up before installing.

```bash
npx opena2a-cli self-register
```

Expected output:

```
  Trust Registry Self-Registration  v0.7.2

  Package      @myorg/mcp-server-tools@1.2.0
  Identity     agent:ed25519:k1_b7c4...9f1a
  Trust Score  0.72

  Verification Method
  -----------------------------------------------
  Checking npm ownership...
  Verified: you are a maintainer of @myorg/mcp-server-tools on npm

  Registration
  -----------------------------------------------
  Published trust profile to registry.opena2a.org
  Profile URL: https://registry.opena2a.org/p/@myorg/mcp-server-tools

  Users can now discover your server:
    npx opena2a-cli detect --registry
    npx ai-trust check @myorg/mcp-server-tools
```

Registration requires proving ownership through npm package maintainership or GitHub repository access. This prevents impersonation.

After registration, your server appears in `detect --registry` results with its trust score and verification status. Users see "verified" next to your server name instead of "not in registry."

---

## Maintaining Your Server

After the initial setup, keep your trust score current:

| When | Command | Purpose |
|------|---------|---------|
| Before each publish | `npx hackmyagent secure` | Catch new vulnerabilities |
| After version bump | `opena2a mcp sign my-server` | Re-sign with new version |
| After version bump | `opena2a self-register` | Update registry entry |
| After dependency updates | `npx ai-trust check my-server` | Verify score did not drop |
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
        run: npx opena2a-cli scan-soul --fail-below 80

      - name: Trust score gate
        run: |
          score=$(npx ai-trust check . --format json | jq -r '.trustScore')
          if (( $(echo "$score < 0.70" | bc -l) )); then
            echo "Trust score $score is below 0.70 threshold"
            exit 1
          fi
```

---

## Related Use Cases

- [Developer using AI coding tools](./developer.md)
- [Security team assessing AI risk](./security-team.md)
- [CI/CD pipeline integration](./ci-cd.md)
- [Full documentation](https://opena2a.org/docs)

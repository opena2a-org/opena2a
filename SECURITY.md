# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in any OpenA2A project, please report it responsibly.

**Email:** info@opena2a.org

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected tool/version
- Potential impact

We will acknowledge receipt within 48 hours and provide a timeline for remediation.

## Scope

This policy covers all repositories under the [opena2a-org](https://github.com/opena2a-org) GitHub organization.

## Known advisories

This section covers what you inherit by installing `opena2a-cli`, not the whole organization. It
exists so a reporter can tell what we already know about from what is new. Last checked 2026-08-25.

### adm-zip (GHSA-xcpc-8h2w-3j85): resolved

- **What it was.** "adm-zip: Crafted ZIP file triggers 4GB memory allocation." High, CVSS 7.5,
  reached transitively through `opena2a-cli` to `hackmyagent` to `onnxruntime-node` to `adm-zip`;
  no code in this repository calls `adm-zip`. Advisory:
  <https://github.com/advisories/GHSA-xcpc-8h2w-3j85>
- **Why it is gone.** `onnxruntime-node@1.29.0` declares `adm-zip: ^0.6.0`, the patched range.
  `hackmyagent@0.30.0`, which this CLI pins, declares `onnxruntime-node: ^1.27.0`, so a fresh
  install resolves `adm-zip@0.6.0`. Measured 2026-08-25; the consumer-resolution audit that
  gated this advisory now finds zero high or critical advisories in the published closure.
- **Verify.** `npm ls adm-zip` in the tree where you installed shows `0.6.0` or later, and
  `npm audit --omit=dev` reports no adm-zip advisory. If you installed before 2026-08-25, reinstall.

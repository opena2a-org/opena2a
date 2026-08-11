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
exists so a reporter can tell what we already know about from what is new. Last checked 2026-08-11.

### adm-zip (GHSA-xcpc-8h2w-3j85)

- **What.** "adm-zip: Crafted ZIP file triggers 4GB memory allocation." High, CVSS 7.5,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-400 and CWE-789. Advisory:
  <https://github.com/advisories/GHSA-xcpc-8h2w-3j85>
- **Where it comes from.** Not a direct dependency. The path is `opena2a-cli` to `hackmyagent` to
  `onnxruntime-node` to `adm-zip`. No code in this repository calls `adm-zip`.
- **Verify.** `npm audit --audit-level=high` in the tree where you installed, and `npm ls adm-zip`
  for the path. npm reports this as two high-severity vulnerabilities, one against `adm-zip` and
  one against `onnxruntime-node` for depending on it. It is one advisory.
- **Fix.** None you can apply today, and `npm audit fix` is not one. npm advertises it in the audit
  output; running it leaves the vulnerable `adm-zip` in place and the audit still failing. The fixed
  release is `adm-zip@0.6.0`, and the newest published `onnxruntime-node`, 1.27.0, declares
  `adm-zip: ^0.5.16`, a range that cannot reach it. So the fix has to come from upstream widening
  that range. `npm view onnxruntime-node dependencies.adm-zip` is the one-line check that tells you
  when it has, and we move the pin when it does.

Captured 2026-08-11 on npm 11.11.1, in a tree with the 0.11.0 dependency set:

```
# npm audit report

adm-zip  <0.6.0
Severity: high
adm-zip: Crafted ZIP file triggers 4GB memory allocation - https://github.com/advisories/GHSA-xcpc-8h2w-3j85
fix available via `npm audit fix`
node_modules/adm-zip
  onnxruntime-node  1.22.0-dev.20250415-c18e06d5e3 - 1.29.0-dev.20260724-ed98916356
  Depends on vulnerable versions of adm-zip
  node_modules/onnxruntime-node

2 high severity vulnerabilities

To address all issues, run:
  npm audit fix
```

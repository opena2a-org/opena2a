# Verifying OpenA2A npm packages

This page gives one copy-paste check for each of [`hackmyagent`](#hackmyagent), [`secretless-ai`](#secretless-ai), [`opena2a-cli`](#opena2a-cli) and [`@opena2a/aim-core`](#opena2aaim-core). Each block uses cosign to check the tarball the npm registry serves for a version against the SLSA provenance attestation published with it.

## What the check proves

A pass shows three things about the tarball the npm registry serves for the version checked:

- Its SHA-512 digest is the one recorded in that version's SLSA v1 provenance attestation. Changing a single byte of the tarball fails the check.
- The attestation was signed with a certificate that Sigstore issued, against a GitHub Actions OIDC token, to the workflow and tag named in the identity the block passes to cosign: a release workflow in the `opena2a-org` GitHub organization, running for that version's tag.
- The `package.json` inside the tarball names the package and version the block requested.

Together, these show that the registry's tarball for that version is the one the package's release workflow published for that version's tag.

## What it does not prove

- Installed files. The block checks the tarball the registry serves when it runs, not files already installed or written by a later install. Setting the version variable to an installed version checks the registry's tarball for that version number, not the installed copy.
- Dependencies. Only the named package is checked. Installing it still fetches its dependencies from the registry, unchecked.
- Quality or safety. `Verified OK` is about origin only. It does not show that the code was reviewed or tested before release, or that it is safe to run.
- That the version is the newest. By default the block checks the version the registry lists as latest. If the registry lists an older version as latest, the block checks that version and can pass.
- Versions published before the package began publishing with provenance. They have no attestation, so the check fails on them.
- The attestation type, on cosign older than 3.0.6, or older than 2.6.3 on the 2.x line.
- Its own trust anchors. The check relies on Sigstore's public infrastructure, on GitHub's OIDC token issuer, and on control of who can push release tags in the `opena2a-org` repositories. The identity names the organization and repository, not GitHub's numeric IDs for them, and the check does not show which kind of runner built the tarball.

## Prerequisites

- cosign 3.0.6 or later, or 2.6.3 or later on the 2.x line. Earlier releases can print `Verified OK` without checking the attestation type ([GHSA-w6c6-c85g-mmv6](https://github.com/advisories/GHSA-w6c6-c85g-mmv6)). `cosign version` prints the installed version. The checks on this page were run with cosign 3.1.3. Sigstore documents how to [install cosign](https://docs.sigstore.dev/cosign/system_config/installation/).
- npm, jq, openssl, tar and curl.
- bash or zsh.
- Network access to the npm registry and to Sigstore, from which cosign fetches its trust root.

Each block writes the tarball and the attestation bundle into the current directory. It runs in a subshell, so a failed step ends the block without closing the terminal. It prints the package and version it checks, then the result from cosign. The check passed only if the last line is `Verified OK`. Notices from npm, such as an available update, can also appear, and cosign 3.1.3 prints a notice that the `--new-bundle-format` flag is deprecated on every run, pass or fail. Neither is part of the result.

## `hackmyagent`

From a new, empty directory, paste this to check the origin of the registry's tarball for the latest `hackmyagent`, or for the version in `HACKMYAGENT_VERSION` if it is set.

```bash
(
  set -eu -o pipefail
  v=${HACKMYAGENT_VERSION:-$(npm view hackmyagent version)}
  [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release version: $v" >&2; exit 1; }
  npm pack "hackmyagent@$v" --silent >/dev/null
  [ "$(tar -xzOf "hackmyagent-$v.tgz" package/package.json | jq -r '.name + "@" + .version')" = "hackmyagent@$v" ] || { echo "tarball check failed: expected hackmyagent@$v" >&2; exit 1; }
  curl -sSf "https://registry.npmjs.org/-/npm/v1/attestations/hackmyagent@$v" | jq -e '.attestations[] | select(.predicateType=="https://slsa.dev/provenance/v1") | .bundle' > hackmyagent.sigstore.json
  echo "hackmyagent@$v"
  cosign verify-blob-attestation --bundle hackmyagent.sigstore.json --new-bundle-format --type slsaprovenance1 --certificate-identity "https://github.com/opena2a-org/hackmyagent/.github/workflows/release.yml@refs/tags/v$v" --certificate-oidc-issuer https://token.actions.githubusercontent.com --digestAlg sha512 --digest "$(openssl dgst -sha512 -r "hackmyagent-$v.tgz" | cut -d' ' -f1)"
)
```

## `secretless-ai`

From a new, empty directory, paste this to check the origin of the registry's tarball for the latest `secretless-ai`, or for the version in `SECRETLESS_AI_VERSION` if it is set.

```bash
(
  set -eu -o pipefail
  v=${SECRETLESS_AI_VERSION:-$(npm view secretless-ai version)}
  [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release version: $v" >&2; exit 1; }
  npm pack "secretless-ai@$v" --silent >/dev/null
  [ "$(tar -xzOf "secretless-ai-$v.tgz" package/package.json | jq -r '.name + "@" + .version')" = "secretless-ai@$v" ] || { echo "tarball check failed: expected secretless-ai@$v" >&2; exit 1; }
  curl -sSf "https://registry.npmjs.org/-/npm/v1/attestations/secretless-ai@$v" | jq -e '.attestations[] | select(.predicateType=="https://slsa.dev/provenance/v1") | .bundle' > secretless-ai.sigstore.json
  echo "secretless-ai@$v"
  cosign verify-blob-attestation --bundle secretless-ai.sigstore.json --new-bundle-format --type slsaprovenance1 --certificate-identity "https://github.com/opena2a-org/secretless-ai/.github/workflows/release.yml@refs/tags/v$v" --certificate-oidc-issuer https://token.actions.githubusercontent.com --digestAlg sha512 --digest "$(openssl dgst -sha512 -r "secretless-ai-$v.tgz" | cut -d' ' -f1)"
)
```

## `opena2a-cli`

From a new, empty directory, paste this to check the origin of the registry's tarball for the latest `opena2a-cli`, or for the version in `OPENA2A_CLI_VERSION` if it is set; its releases have used two tag forms, `cli-v` and `v` followed by the version, so the identity it passes to cosign accepts either, for that version only.

```bash
(
  set -eu -o pipefail
  v=${OPENA2A_CLI_VERSION:-$(npm view opena2a-cli version)}
  [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release version: $v" >&2; exit 1; }
  npm pack "opena2a-cli@$v" --silent >/dev/null
  [ "$(tar -xzOf "opena2a-cli-$v.tgz" package/package.json | jq -r '.name + "@" + .version')" = "opena2a-cli@$v" ] || { echo "tarball check failed: expected opena2a-cli@$v" >&2; exit 1; }
  curl -sSf "https://registry.npmjs.org/-/npm/v1/attestations/opena2a-cli@$v" | jq -e '.attestations[] | select(.predicateType=="https://slsa.dev/provenance/v1") | .bundle' > opena2a-cli.sigstore.json
  echo "opena2a-cli@$v"
  cosign verify-blob-attestation --bundle opena2a-cli.sigstore.json --new-bundle-format --type slsaprovenance1 --certificate-identity-regexp "^https://github\.com/opena2a-org/opena2a/\.github/workflows/release\.yml@refs/tags/(cli-)?v${v//./\\.}\$" --certificate-oidc-issuer https://token.actions.githubusercontent.com --digestAlg sha512 --digest "$(openssl dgst -sha512 -r "opena2a-cli-$v.tgz" | cut -d' ' -f1)"
)
```

## `@opena2a/aim-core`

From a new, empty directory, paste this to check the origin of the registry's tarball for the latest `@opena2a/aim-core`, or for the version in `AIM_CORE_VERSION` if it is set.

```bash
(
  set -eu -o pipefail
  v=${AIM_CORE_VERSION:-$(npm view @opena2a/aim-core version)}
  [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release version: $v" >&2; exit 1; }
  npm pack "@opena2a/aim-core@$v" --silent >/dev/null
  [ "$(tar -xzOf "opena2a-aim-core-$v.tgz" package/package.json | jq -r '.name + "@" + .version')" = "@opena2a/aim-core@$v" ] || { echo "tarball check failed: expected @opena2a/aim-core@$v" >&2; exit 1; }
  curl -sSf "https://registry.npmjs.org/-/npm/v1/attestations/@opena2a%2faim-core@$v" | jq -e '.attestations[] | select(.predicateType=="https://slsa.dev/provenance/v1") | .bundle' > opena2a-aim-core.sigstore.json
  echo "@opena2a/aim-core@$v"
  cosign verify-blob-attestation --bundle opena2a-aim-core.sigstore.json --new-bundle-format --type slsaprovenance1 --certificate-identity "https://github.com/opena2a-org/opena2a/.github/workflows/release.yml@refs/tags/aim-core-v$v" --certificate-oidc-issuer https://token.actions.githubusercontent.com --digestAlg sha512 --digest "$(openssl dgst -sha512 -r "opena2a-aim-core-$v.tgz" | cut -d' ' -f1)"
)
```

## If the check fails

The check passed only if the last line is `Verified OK` and the block exits 0. Anything else is a failure: do not install that version. Find the first row below that matches the output. Its next step says whether to report: a verification failure goes to the package's security policy, while a missing tool, a mistyped version or a network problem can be fixed and the block run again.

| Output | Meaning | Next step |
|---|---|---|
| `command not found` anywhere, or `Illegal option -o pipefail` | A required tool is missing, or the block ran in a shell other than bash or zsh. Whatever follows, the check did not complete. | Install the tool or switch to bash or zsh, then run the block again. |
| `not a release version:` and the version | The version, from `npm view` or from the version variable, is not three dot-separated numbers. | If you set the variable, correct it. Otherwise, report it. |
| The block stops before printing the package and version, and no row above matches | npm could not resolve or fetch that version, for example because it does not exist or the network is down, or npm lists no SLSA v1 provenance for it. | Check the version and the network, then run the block again. If it recurs with the default version, report it. |
| `tarball check failed: expected` and the package and version | The `package.json` in the tarball does not name the package and version requested. | Report it. |
| `curl: (56) The requested URL returned error: 404` (the number in brackets can differ, for example 22) | npm holds no provenance attestation for that version. Versions published before the package began publishing with provenance have none, and this check cannot verify them. | Report it, unless you set an older version that predates the package's provenance. |
| Any other `curl:` error | The attestation could not be downloaded. | Check the network, then run the block again. |
| `provided artifact digest does not match any digest in statement` | The tarball's bytes differ from the bytes the attestation records. | Report it. |
| `no matching CertificateIdentity found`, followed by the expected and the actual identity | The attestation was signed for a different repository, workflow or tag from the one in the block. | Report it. |
| Any other line starting `error during command execution:` | The attestation did not verify, or cosign could not run the check. | If `cosign version` meets the prerequisites, report it. |

To report, follow the security policy of the repository that publishes the package: [hackmyagent](https://github.com/opena2a-org/hackmyagent/blob/main/SECURITY.md), [secretless-ai](https://github.com/opena2a-org/secretless-ai/blob/main/SECURITY.md), or [opena2a](https://github.com/opena2a-org/opena2a/blob/main/SECURITY.md) for `opena2a-cli` and `@opena2a/aim-core`. Include the package, the version and the block's full output.

The messages above were copied from runs of these blocks with cosign 3.1.3. Captures of each run are in [`docs/captures/`](https://github.com/opena2a-org/opena2a/tree/main/docs/captures).

## Use in CI

In CI, run a block unchanged as a bash step, such as a GitHub Actions `run:` step, from an empty directory, with the package's version variable (for example `HACKMYAGENT_VERSION`) set to pin the version checked; any failure exits non-zero and fails the step.

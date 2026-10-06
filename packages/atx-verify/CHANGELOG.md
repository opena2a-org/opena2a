# Changelog

All notable changes to `@opena2a/atx-verify` are documented here.

## [0.5.0] - Unreleased

A minor bump, not a patch: one class of consumer sees credentials that used to
verify begin rejecting. That change is the fix.

Published `0.4.0` predates three commits already on `main` that touch this
package. One (#292) changes the published package; the other two (#325, #329)
change only the repository's tests and CI. Upgrading from the published package
therefore picks up two changes in behaviour together: ML-DSA-65 verification and
the `issuerChain` rule below.

### Changed

- **ML-DSA-65 signature entries are now verified, as Ed25519 entries already
  were.** ML-DSA-65 (FIPS 204) is verified via `@noble/post-quantum`, alongside
  Ed25519 via `node:crypto`. The verifier previously recorded that an ML-DSA-65
  entry was present without checking it, so a credential whose post-quantum
  signature was forged verified on the strength of its intact Ed25519
  signature. Every Ed25519 and ML-DSA-65 entry a credential declares must now
  verify, per atx-spec §13 and AAP §9.4; such an entry that does not verify, or
  for which no eligible anchor is configured, is now `SIGNATURE_INVALID`.
  ML-DSA-65 anchors are subject to the same key-to-issuer binding as Ed25519
  anchors.

  **Who this breaks, and it is deliberate.** A deployment that configures only
  Ed25519 trust anchors and verifies hybrid credentials will see those
  credentials move from ACCEPT to REJECT, with the reason
  `no ML-DSA-65 trust anchors configured`. The fix is to configure the
  post-quantum anchor; the previous acceptance was not safe.

  `mldsaPresent` keeps its meaning: an ML-DSA-65 entry was declared. On a
  `valid: true` result it now also implies that entry verified.

  **Not changed: an entry for any other algorithm is still skipped.** An entry
  whose `algorithm` is anything else (the match is exact), or is missing,
  neither rejects the credential nor counts toward accepting it. atx-spec §13
  requires a verifier to reject a credential that declares a suite it does not
  implement; this version does not do that yet.

- **An `issuerChain` entry extends key eligibility only if it is itself
  trusted** (`9ab7e747`, #292). On `main` but never published: `0.4.0` predates
  it. A credential could otherwise name an untrusted authority in its signed
  `issuerChain` and have that authority's key accepted.

- **The vendored conformance suite is pinned by CI at an explicit ref and
  byte-compared in both directions** (`3c6ea102`, #325). The vendored set
  includes the MUST-REJECT fixture for a chain whose authority is not a trusted
  anchor. Repository only: nothing in the published package changes.

- **The conformance test freezes the expected verdict of each of the 21
  vendored fixtures** (`caea9c4c`, #329), so a fixture that is added, removed,
  renamed or re-verdicted fails the test until the table changes with it.
  Repository only: nothing in the published package changes.

### Added

- `@noble/post-quantum` as a direct dependency, pinned exactly to `0.2.1`
  (no caret), the version this workspace's lockfile already resolves.

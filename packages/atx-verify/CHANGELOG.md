# Changelog

All notable changes to `@opena2a/atx-verify` are documented here.

## [0.5.0]

A minor bump, not a patch: one class of consumer sees credentials that used to
verify begin rejecting. That change is the fix.

This release carries **three** changes, not one. Published `0.4.0` predates two
commits that were already on `main`, so upgrading from the published package
picks all three up together.

### Changed

- **Both declared signature suites are now verified.** ML-DSA-65 (FIPS 204) is
  verified via `@noble/post-quantum`, alongside Ed25519 via `node:crypto`. The
  verifier previously recorded that an ML-DSA-65 entry was present without
  checking it, so a credential whose post-quantum signature was forged verified
  on the strength of its intact Ed25519 signature. atx-spec §13 and AAP §9.4
  require every declared entry to verify; a declared entry that does not verify,
  or for which no eligible anchor is configured, is now `SIGNATURE_INVALID`.

  **Who this breaks, and it is deliberate.** A deployment that configures only
  Ed25519 trust anchors and verifies hybrid credentials will see those
  credentials move from ACCEPT to REJECT, with the reason
  `no ML-DSA-65 trust anchors configured`. The fix is to configure the
  post-quantum anchor; the previous acceptance was not safe. Both known in-house
  consumers pin `0.3.0` exactly, so neither is upgraded automatically.

  `mldsaPresent` keeps its meaning — an ML-DSA-65 entry was declared. On a
  `valid: true` result it now additionally implies that entry verified.

- **An `issuerChain` entry extends key eligibility only if it is itself
  trusted** (`9ab7e747`, #292). Present on `main` but never published: `0.4.0`
  predates it. A credential could otherwise name an untrusted authority in its
  signed `issuerChain` and have that authority's key accepted.

- **The vendored conformance suite is pinned by CI at an explicit ref and
  byte-compared in both directions** (`3c6ea102`, #325, and this release's
  re-vendor). The vendored set now carries 23 fixtures, including the forged
  post-quantum MUST-REJECT control that surfaced the defect above and a
  MUST-PASS credential omitting the optional `transparencyLogIndex`. Fixture
  capability strings follow the AIP `namespace:action` grammar.

### Added

- `@noble/post-quantum` as a direct dependency, pinned exactly to `0.2.1`
  (no caret), matching the pin already carried elsewhere in this workspace.

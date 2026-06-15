# @opena2a/atx-verify

Spec-compliant **offline** verifier for ATX (Agent Trust eXtension) credentials —
the signed, portable credential that states what an agent *is*.

This is the single shared TypeScript verifier for the OpenA2A ecosystem. It is
**byte-for-byte interoperable** with the Go (`opena2a-registry/pkg/atcverify`)
and Python (`atx-conformance`) reference verifiers; canonicalization agreement
across Go == Python == TS is pinned by `atx-conformance/jcs-vectors`.

## What it does

`LocalAtxVerifier.verify(atx)` runs the full local check with no network call:

1. schema version (`atcVersion` `1.0` or `1.1`)
2. expiry
3. revocation (the credential's `revoked` field + a cached/federated CRL)
4. issuer trust (issuer DID against injected trust anchors)
5. Ed25519 signature over the canonical payload

Trust anchors (trusted issuers, public keys, CRL, clock) are **injected** — the
library does no I/O. A consumer wires the live anchors (and, in production, the
post-quantum half) via the `AtxVerifier` seam.

## Signature coverage depends on `atcVersion`

- **v1.0** (`canonicalPayload`) signs an 11-field pipe-delimited string covering
  identity, issuer, trustLevel, trustScore, contentHash, buildAttestation, and
  the validity window. It does **not** cover `capabilities`, `scanSummary`,
  `issuerChain`, or `publisher` — a holder can edit those without breaking the
  signature, so they MUST NOT be trusted for authorization.
- **v1.1** (`canonicalPayloadV11`) signs `JCS(TBS)` (RFC 8785), which **does**
  cover `capabilities`, `scanSummary`, `issuerChain`, `publisher`, and
  `behavioralProfile`.

The verified context exposes `signedCapabilities` (true iff v1.1) so callers can
gate capability-based authorization on whether those fields are signed.

## Scope

Ed25519 is verified fully via Node's `crypto`. **ML-DSA-65** presence is recorded
(`mldsaPresent`) but verification is delegated — Node's stdlib has no ML-DSA,
matching the Python reference verifier. Wire the PQC half via the `AtxVerifier`
seam in production.

## Usage

```ts
import { LocalAtxVerifier, type AtxTrustAnchors } from "@opena2a/atx-verify";

const anchors: AtxTrustAnchors = {
  trustedIssuers: ["did:opena2a:authority:opena2a.org"],
  publicKeys: [{ algorithm: "Ed25519", publicKeyHex: "<32-byte hex>" }],
  crl: { entries: [] },
};

const result = new LocalAtxVerifier(anchors).verify(atx);
if (result.valid) {
  // result.context — backend-free; only authorize on capabilities when
  // result.context.signedCapabilities is true (v1.1).
} else {
  // result.rejectCategory: UNSUPPORTED_VERSION | EXPIRED | REVOKED
  //   | UNTRUSTED_ISSUER | SIGNATURE_INVALID | MALFORMED
}
```

## Conformance

`src/conformance.test.ts` runs the verifier against the OpenA2A ATX conformance
fixtures (with their pinned signatures), and `src/atx.test.ts` pins the v1.1
JCS baseline canonical bytes from `atx-conformance/jcs-vectors`. Any drift from
the cross-language contract fails the package's own CI.

## License

Apache-2.0

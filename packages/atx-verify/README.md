# @opena2a/atx-verify

Spec-compliant **offline** verifier for ATX (Agent Trust eXtension) credentials —
the signed, portable credential that states what an agent *is*.

This is the single shared TypeScript verifier for the OpenA2A ecosystem. It is
**byte-for-byte interoperable** with the Go (`opena2a-registry/pkg/atcverify`)
and Python (`atx-conformance`) reference verifiers; canonicalization agreement
across Go == Python == TS is pinned by `atx-conformance/jcs-vectors`.

## What it does

`LocalAtxVerifier.verifyCredential(json)` takes the raw credential (string or
`Uint8Array`) and runs the full local check with no network call:

1. **strict parse** — a duplicate object member at any depth, exact-name or
   fold-colliding case variant, rejects as `MALFORMED` before any field is
   interpreted (RFC 8259 §4 leaves duplicate handling parser-divergent; the
   ATX credential is a signed body, so there is no layer with sanctioned
   last-wins semantics)
2. schema version (`atcVersion` `1.0` or `1.1`)
3. expiry
4. revocation (the credential's `revoked` field + a cached/federated CRL)
5. issuer trust (issuer DID against injected trust anchors)
6. Ed25519 signature over the canonical payload

`verify(atx)` runs steps 2-6 on an already-parsed object. Prefer
`verifyCredential` whenever you hold the wire form: `JSON.parse` is last-wins
on duplicate members, so a parsed object cannot carry the evidence step 1
rejects on.

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
  cover `capabilities`, `scanSummary`, `issuerChain`, `publisher`,
  `behavioralProfile`, and — when present — `declaredPurpose` (atx-spec §1.5;
  absent, `null`, and empty-object purposes are omitted from the TBS per
  §1.3a.2 rule 5, so an attacker-appended purpose value breaks the signature
  instead of riding it).

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
  publicKeys: [
    {
      algorithm: "Ed25519",
      publicKeyHex: "<32-byte hex>",
      // Recommended: a DID-URL keyId binds the key to its controller so it can
      // only verify credentials issued by that DID. Required to be safe with a
      // MULTI-issuer anchor set (see "Key-to-issuer binding" below).
      keyId: "did:opena2a:authority:opena2a.org#key-1",
    },
  ],
  crl: { entries: [] },
};

// Raw wire form (string | Uint8Array): strict-parses, then verifies.
const result = new LocalAtxVerifier(anchors).verifyCredential(credentialJson);
if (result.valid) {
  // result.context — backend-free; only authorize on capabilities when
  // result.context.signedCapabilities is true (v1.1).
} else {
  // result.rejectCategory: UNSUPPORTED_VERSION | EXPIRED | REVOKED
  //   | UNTRUSTED_ISSUER | SIGNATURE_INVALID | MALFORMED
}
```

## Key-to-issuer binding

A signature is only accepted from a key controlled by the credential's issuer.
A configured key whose `keyId` is a DID-URL (contains `#`) is **bound** to its
controller DID and may only verify credentials issued by that DID — or, for
v1.1 (where `issuerChain` is signed), by an authority named in the chain. This
prevents one trusted issuer's key from satisfying a credential issued under a
different issuer's DID.

A key with no `keyId`, or a `keyId` without a `#` fragment, is treated as
**unbound** and stays eligible for any issuer — safe for a single-issuer anchor
set, but supply DID-URL `keyId`s whenever the anchor set holds keys for more
than one issuer.

## Conformance

`src/conformance.test.ts` replays the FULL OpenA2A ATX conformance suite (20
fixtures, pinned signatures, vendored verbatim from `atx-conformance` at
`f4d40a4`) through the raw `verifyCredential` entry point; CI byte-compares the
vendored copies against the pinned suite so they cannot drift. `src/atx.test.ts`
pins the v1.1 JCS baseline canonical bytes from `atx-conformance/jcs-vectors`.
Where the reference verifiers report `PARSE_ERROR`, this SDK reports
`MALFORMED` (the shared SDK `RejectCategory` union has no `PARSE_ERROR`).

## License

Apache-2.0

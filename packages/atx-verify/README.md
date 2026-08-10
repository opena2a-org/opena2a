# @opena2a/atx-verify

Spec-compliant **offline** verifier for ATX (Agent Trust eXtension) credentials —
the signed, portable credential that states what an agent *is*.

This is the single shared TypeScript verifier for the OpenA2A ecosystem. It is
**byte-for-byte interoperable** with the Go
([`opena2a-registry/pkg/atcverify`](https://github.com/opena2a-org/opena2a-registry/tree/main/pkg/atcverify))
and Python ([`atx-conformance`](https://github.com/opena2a-standards/atx-conformance))
reference verifiers; canonicalization agreement
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
  §1.3a.2 rule 5, so an appended purpose value carrying any data breaks the
  signature instead of riding it — only the data-free `null`/`{}` forms
  canonicalize away as absent).

The verified context exposes `signedCapabilities` (true iff v1.1) so callers can
gate capability-based authorization on whether those fields are signed.

## Scope

Ed25519 is verified fully via Node's `crypto`. **ML-DSA-65** presence is recorded
(`mldsaPresent`) but verification is delegated — Node's stdlib has no ML-DSA,
matching the Python reference verifier. Wire the PQC half via the `AtxVerifier`
seam in production.

## Runtime and packaging

- **ESM-only** (`"type": "module"`). On Node >= 22, CommonJS consumers can
  `require()` it natively; on Node 18/20 use `await import('@opena2a/atx-verify')`
  (the pattern the secretless broker uses). The package exposes only the root
  entry via its `exports` map.
- **Node types**: the canonical-payload helpers return Node `Buffer`s, so a
  TypeScript consumer compiling with `skipLibCheck: false` needs `@types/node`
  (any recent version) in its own devDependencies.

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

## Building a test credential

There is no signing API here (issuance lives in the Registry), but the exported
canonical-payload helpers plus `node:crypto` are enough to build a valid signed
credential for tests:

```ts
import crypto from "node:crypto";
import {
  LocalAtxVerifier,
  canonicalPayloadV11,
  type Atx,
  type AtxTrustAnchors,
} from "@opena2a/atx-verify";

// 1. Issuer keypair (in production this is the issuing authority's key).
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" }) as { x: string };
const publicKeyHex = Buffer.from(jwk.x, "base64url").toString("hex");

// 2. The credential body. "1.1" signs JCS(TBS) — capabilities are covered.
const atx: Atx = {
  atcVersion: "1.1",
  agentId: "example-agent",
  agentDid: "did:opena2a:agent:example-agent",
  version: "1.0.0",
  contentHash:
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  issuerDid: "did:opena2a:authority:example.org",
  trustLevel: 2,
  trustScore: 80,
  issuedAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
  capabilities: ["registry:read"],
  signatures: [],
};

// 3. Sign the canonical payload (v1.0 credentials use canonicalPayload) and attach.
atx.signatures = [
  {
    algorithm: "Ed25519",
    value: crypto.sign(null, canonicalPayloadV11(atx), privateKey).toString("base64"),
    keyId: "did:opena2a:authority:example.org#key-1",
  },
];

// 4. Verify the wire form.
const anchors: AtxTrustAnchors = {
  trustedIssuers: ["did:opena2a:authority:example.org"],
  publicKeys: [
    {
      algorithm: "Ed25519",
      publicKeyHex,
      keyId: "did:opena2a:authority:example.org#key-1",
    },
  ],
  crl: { entries: [] },
};
const result = new LocalAtxVerifier(anchors).verifyCredential(JSON.stringify(atx));
// result.valid === true
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

## Additional exports

Beyond the verifier itself, the package exports the primitives its strict parse
and canonicalization are built from, for consumers that need to scope or
reproduce them: `canonicalPayload` / `canonicalPayloadV11` (canonical signing
bytes for v1.0 / v1.1), `firstDuplicateMember` (fold-aware duplicate scan over
a raw JSON body), `topLevelMemberSpan` + `ValueSpan` (byte-offset extraction of
one top-level member, for strict-parsing a credential embedded in a larger
envelope), `foldKey`, `normalizeRfc3339`, `StrictParseError`, `MAX_SCAN_DEPTH`,
and `SUPPORTED_ATX_VERSION` / `SUPPORTED_ATX_VERSION_V11`. Each carries doc
comments in the published `.d.ts`.

## Conformance

The package's test suite — in [the repository](https://github.com/opena2a-org/opena2a/tree/main/packages/atx-verify),
not the published tarball — replays the FULL OpenA2A ATX conformance suite (20
fixtures, pinned signatures, vendored verbatim from
[`atx-conformance`](https://github.com/opena2a-standards/atx-conformance) at
`f4d40a4`) through the raw `verifyCredential` entry point; CI byte-compares the
vendored copies against the pinned suite so they cannot drift, and pins the
v1.1 JCS baseline canonical bytes from
[`atx-conformance/jcs-vectors`](https://github.com/opena2a-standards/atx-conformance/tree/main/jcs-vectors).
Where the reference verifiers report `PARSE_ERROR`, this SDK reports
`MALFORMED` (the shared SDK `RejectCategory` union has no `PARSE_ERROR`).

## License

Apache-2.0

/**
 * @opena2a/atx-verify — spec-compliant offline verifier for ATX (Agent Trust
 * eXtension) credentials. Byte-for-byte interoperable with the Go
 * (`opena2a-registry/pkg/atcverify`) and Python (`atx-conformance`) reference
 * verifiers; canonicalization agreement is pinned by `atx-conformance/jcs-vectors`.
 */
export {
  LocalAtxVerifier,
  canonicalPayload,
  canonicalPayloadV11,
  normalizeRfc3339,
  SUPPORTED_ATX_VERSION,
  SUPPORTED_ATX_VERSION_V11,
  type Atx,
  type AtxSignature,
  type AtxPublicKey,
  type AtxTrustAnchors,
  type AtxVerifier,
  type AtxVerificationResult,
  type ResolutionContext,
  type RejectCategory,
} from './atx.js';

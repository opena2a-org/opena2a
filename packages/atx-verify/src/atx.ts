/**
 * ATX (Agent Trust eXtension) verification — the signed, portable credential
 * defined by ATP/ATX that states what an agent *is*.
 *
 * This verifier mirrors the OpenA2A reference verifiers
 * (`opena2a-registry/pkg/atcverify/verify.go canonicalPayload()` and the Python
 * port at `atx-conformance/verifiers/python/verify.py`) VERBATIM so a consumer
 * accepts exactly the credentials the conformance suite accepts. Byte agreement
 * across Go == Python == TS is pinned by `atx-conformance/jcs-vectors`.
 *
 * (ATX is the current name for the credential formerly called ATC; fixtures use
 * the `atcVersion` field. This verifier dual-supports both signing forms.)
 *
 * Scope: Ed25519 is verified fully. ML-DSA-65 presence is recorded but
 * verification is delegated — Node's stdlib has no ML-DSA, exactly as the Python
 * reference verifier skips it. A production deployment wires the post-quantum
 * half + the live trusted-issuer/CRL anchors via the {@link AtxVerifier} seam.
 *
 * SECURITY — signature coverage depends on atcVersion:
 *  - v1.0 (canonicalPayload): the pipe-delimited string covers identity, issuer,
 *    trustLevel, trustScore, contentHash, buildAttestation, and the validity
 *    window. It does NOT cover `capabilities`, `scanSummary.oasbLevel`,
 *    `issuerChain`, or `jurisdiction`. A holder of any validly-signed v1.0 ATX
 *    can edit those without invalidating the signature, so they MUST NOT be
 *    trusted for authorization.
 *  - v1.1 (canonicalPayloadV11): the signature covers JCS(TBS), which includes
 *    `capabilities`, `scanSummary`, `issuerChain`, `publisher`, and (when
 *    present) `declaredPurpose`. Those fields are integrity-protected and safe
 *    to authorize on.
 *
 * SECURITY — parse before trust: `verify(atx)` takes an already-parsed object,
 * and `JSON.parse` is last-wins on duplicate members, so a duplicate-member
 * smuggle is collapsed before that overload can see it. Wire consumers holding
 * credential text/bytes should call {@link LocalAtxVerifier.verifyCredential},
 * which strict-parses first (fold-aware duplicate rejection at any depth, see
 * `strict-parse.ts`) and then delegates.
 *
 * The verified context exposes `signedCapabilities` (true iff v1.1) so callers
 * can tell the two apart and gate capability-based authorization accordingly.
 */

import * as crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { firstDuplicateMember } from './strict-parse.js';

// `canonicalize` (RFC 8785) is a CommonJS module whose .d.ts declares an ESM
// default export; under Node16 ESM resolution that default is not callable at
// the type layer. createRequire pulls the real callable CJS export — the
// documented workspace idiom for ESM packages consuming a CJS dependency. The
// canonicalization output is identical to the Go/Python verifiers (byte
// agreement pinned by atx-conformance/jcs-vectors).
const require = createRequire(import.meta.url);
const canonicalize = require('canonicalize') as (input: unknown) => string | undefined;

/** Legacy schema version: signs the 11-field pipe string (Go quirk, replicated). */
export const SUPPORTED_ATX_VERSION = '1.0';

/**
 * ATX v1.1: signs JCS(TBS) (RFC 8785) per atx-spec core.md §1.3a.2, bringing
 * capabilities, scanSummary, issuerChain, publisher, and behavioralProfile under
 * the signature. Verified here using the same canonicalizer (erdtman/canonicalize)
 * and the same TBS projection the registry and conformance verifiers use; byte
 * agreement is proven by atx-conformance/jcs-vectors.
 */
export const SUPPORTED_ATX_VERSION_V11 = '1.1';

/** A signature reference on an ATX. */
export interface AtxSignature {
  keyId?: string;
  algorithm: 'Ed25519' | 'ML-DSA-65' | string;
  /** base64-encoded signature value. */
  value: string;
}

/** The ATX credential (subset used for verification + context derivation). */
export interface Atx {
  atcVersion?: string;
  agentId: string;
  agentDid: string;
  /** Publisher identity. Unsigned under v1.0; covered by the v1.1 signature. */
  publisher?: string;
  publisherDid?: string;
  version: string;
  contentHash: string;
  buildAttestation?: string;
  issuerDid: string;
  issuerChain?: string[];
  trustLevel: number;
  trustScore: number;
  issuedAt: string;
  expiresAt: string;
  capabilities?: string[];
  /**
   * Declared purpose (atx-spec §1.5); absent/null when not declared. Kept
   * untyped: the v1.1 TBS passes a present, non-empty value through verbatim
   * for JCS to re-canonicalize (§1.3a.2 rule 5).
   */
  declaredPurpose?: unknown;
  /** Observed-behavior summary. Covered by the v1.1 signature. */
  behavioralProfile?: { checksum?: string; generatedAt?: string; observationDays?: number } | null;
  scanSummary?: { oasbLevel?: string; [k: string]: unknown };
  /** Optional, optional-to-ignore jurisdiction claim (AAP §9). */
  jurisdiction?: string[];
  revoked?: boolean;
  signatures: AtxSignature[];
}

/** A public key the verifier trusts, keyed by algorithm. */
export interface AtxPublicKey {
  algorithm: 'Ed25519' | 'ML-DSA-65' | string;
  /** hex-encoded raw public key (32 bytes for Ed25519). */
  publicKeyHex: string;
  /**
   * Optional DID-URL identifying the key and its controller, e.g.
   * `did:opena2a:authority:opena2a.org#key-1`. When present (contains `#`), the
   * key is BOUND to its controller DID: it may only verify signatures for
   * credentials issued by that controller (or, for v1.1, an issuerChain
   * authority). This stops one trusted issuer's key from satisfying a credential
   * issued under a different DID. A key without a `#` fragment is unbound and is
   * eligible for any issuer (back-compat for single-issuer anchor sets).
   */
  keyId?: string;
}

/** Trust anchors the verifier evaluates against (in production: fetched from AIM/Registry). */
export interface AtxTrustAnchors {
  trustedIssuers: string[];
  publicKeys: AtxPublicKey[];
  /** Cached, federated CRL. Revocation rides entirely on the ATX + CRL (AAP §6). */
  crl?: { entries: Array<{ agentId: string; reason?: string }> };
  /** Clock source (injectable for tests). Defaults to wall clock. */
  now?: () => Date;
}

export type RejectCategory =
  | 'UNSUPPORTED_VERSION'
  | 'EXPIRED'
  | 'REVOKED'
  | 'UNTRUSTED_ISSUER'
  | 'SIGNATURE_INVALID'
  | 'MALFORMED';

/** Context derived from a *verified* ATX. Contains no backend information. */
export interface ResolutionContext {
  agentId: string;
  agentDid: string;
  issuerDid: string;
  issuerChain: string[];
  trustLevel: number;
  trustScore: number;
  capabilities: string[];
  oasbLevel?: string;
  jurisdiction?: string[];
  /**
   * True when the credential is v1.1+, i.e. capabilities/scanSummary/issuerChain
   * are covered by the signature and may be trusted for authorization. False for
   * v1.0, where those fields are forgeable by the holder. Callers gating
   * capability-based authorization should require this.
   */
  signedCapabilities: boolean;
}

export interface AtxVerificationResult {
  valid: boolean;
  /** Present when valid: the context to resolve authorization against. */
  context?: ResolutionContext;
  /** Present when invalid. */
  rejectCategory?: RejectCategory;
  reason?: string;
  /** Whether an ML-DSA-65 signature was present (and therefore delegated, not skipped silently). */
  mldsaPresent?: boolean;
}

/** The verification interface. Lets a consumer swap a local verifier for an AIM-backed one. */
export interface AtxVerifier {
  verify(atx: Atx): AtxVerificationResult;
}

/**
 * Local ATX verifier. Cryptographically real (Ed25519) and interoperable with the
 * conformance fixtures; trust anchors are injected. A production counterpart
 * fetches `trustedIssuers`, `publicKeys`, and the `crl` from AIM's verification
 * endpoint and adds ML-DSA-65 via the {@link AtxVerifier} seam.
 */
export class LocalAtxVerifier implements AtxVerifier {
  constructor(private readonly anchors: AtxTrustAnchors) {}

  /**
   * Verifies a credential from its raw JSON text or bytes, applying the strict
   * parse (reject a duplicate object member at any depth, folded — see
   * `strict-parse.ts`) before interpreting any field, then delegating to
   * {@link verify}. This is the entry point wire consumers should use: the
   * object-taking {@link verify} cannot see duplicate members `JSON.parse`'s
   * last-wins semantics have already collapsed. A duplicate or otherwise
   * unparseable credential rejects as MALFORMED (the SDK's structural-parse
   * category; the reference verifiers call it PARSE_ERROR), with a reason
   * naming the duplicate member. Degenerate inputs (JSON `null`, scalars, a
   * top-level array, empty/invalid text, non-UTF-8 bytes) reject MALFORMED —
   * this method never throws on bad input.
   */
  verifyCredential(credentialJson: string | Uint8Array): AtxVerificationResult {
    if (credentialJson === null || credentialJson === undefined) {
      return reject('MALFORMED', 'credential is null or undefined');
    }
    // Out-of-contract argument types stay MALFORMED rejections, never escaping
    // throws — including a Proxy whose getPrototypeOf trap throws inside the
    // instanceof check.
    let isBytes = false;
    try {
      isBytes = credentialJson instanceof Uint8Array;
    } catch {
      return reject('MALFORMED', 'credential must be a string or Uint8Array');
    }
    let text: string;
    if (typeof credentialJson === 'string') {
      text = credentialJson;
    } else if (isBytes) {
      try {
        // ignoreBOM keeps a leading U+FEFF in the decoded text so the strict
        // parse rejects it — same verdict as the string entry form and the
        // Go/Python reference verifiers. The default would silently strip it,
        // giving identical wire bytes two different verdicts by entry form.
        text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(credentialJson);
      } catch {
        return reject('MALFORMED', 'credential is not valid UTF-8');
      }
    } else {
      return reject('MALFORMED', 'credential must be a string or Uint8Array');
    }

    let dup: string | null;
    try {
      dup = firstDuplicateMember(text);
    } catch (err) {
      return reject('MALFORMED', `credential is not valid ATX JSON: ${(err as Error).message}`);
    }
    if (dup !== null) {
      return reject(
        'MALFORMED',
        `credential contains duplicate member "${dup}" (strict parse: the ATX credential is a ` +
          'signed body; RFC 8259 §4 duplicate names are parser-divergent)',
      );
    }

    // The scan above already vouches for well-formedness and bounds nesting,
    // but stay defensive: catch everything (including a hypothetical engine
    // RangeError on deep input) rather than let a throw escape.
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      return reject('MALFORMED', `credential is not valid ATX JSON: ${(err as Error).message}`);
    }
    // A bare JSON `null`, scalar, or array is not a credential — reject rather
    // than misread it as an Atx (the Java SDK's adversarial round caught an
    // NPE-on-JSON-null here; this is the equivalent guard).
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return reject('MALFORMED', 'credential is not a JSON object');
    }
    return this.verify(parsed as Atx);
  }

  verify(atx: Atx): AtxVerificationResult {
    // The type forbids it, but a plain-JS caller doing verify(JSON.parse(body))
    // reaches here with null (or a scalar) when the wire body is degenerate —
    // reject structurally rather than throw on the first property read.
    if (atx === null || typeof atx !== 'object') {
      return reject('MALFORMED', 'credential is not an object');
    }
    const now = (this.anchors.now ?? (() => new Date()))();

    // Step 1: schema version. Dispatch on atcVersion: "1.0" verifies the legacy
    // pipe form, "1.1" verifies JCS(TBS) (atx-spec §1.3a). The reason names
    // atcVersion — the schema field a consumer greps their credential for.
    if (atx.atcVersion !== SUPPORTED_ATX_VERSION && atx.atcVersion !== SUPPORTED_ATX_VERSION_V11) {
      return reject('UNSUPPORTED_VERSION', `unsupported atcVersion ${String(atx.atcVersion)}`);
    }
    const isV11 = atx.atcVersion === SUPPORTED_ATX_VERSION_V11;

    // Step 2: expiry.
    const expires = new Date(atx.expiresAt);
    if (Number.isNaN(expires.getTime())) {
      return reject('MALFORMED', 'expiresAt is not a valid timestamp');
    }
    if (now.getTime() > expires.getTime()) {
      return reject('EXPIRED', `expired at ${normalizeRfc3339(atx.expiresAt)}`);
    }

    // Step 3: revocation (ATX field + federated CRL).
    if (atx.revoked) {
      return reject('REVOKED', 'credential revoked field is true');
    }
    for (const entry of this.anchors.crl?.entries ?? []) {
      if (entry.agentId === atx.agentId) {
        return reject('REVOKED', `agent appears on CRL: ${entry.reason ?? ''}`);
      }
    }

    // Step 4: issuer trust.
    if (!this.anchors.trustedIssuers.includes(atx.issuerDid)) {
      return reject('UNTRUSTED_ISSUER', `issuer DID ${atx.issuerDid} is not trusted`);
    }

    // Step 5: signature verification (Ed25519 fully; ML-DSA-65 presence recorded).
    // A v1.1 TBS that fails to canonicalize is a malformed credential, not a
    // verifier error: reject closed rather than throwing.
    let payload: Buffer;
    if (isV11) {
      try {
        payload = canonicalPayloadV11(atx);
      } catch (err) {
        return reject('MALFORMED', `v1.1 canonicalization failed: ${(err as Error).message}`);
      }
    } else {
      payload = canonicalPayload(atx);
    }
    // Key↔issuer binding: a key may verify a signature for this credential only
    // if it is controlled by one of the credential's authorities — the issuer,
    // plus the issuerChain authorities for v1.1 (where the chain is signed; v1.0
    // chain is unsigned/forgeable, so only the issuer counts). A key whose keyId
    // is not a DID-URL (no '#') is unbound and stays eligible (back-compat).
    const authoritySet = new Set<string>([atx.issuerDid]);
    if (isV11) {
      for (const did of atx.issuerChain ?? []) authoritySet.add(did);
    }
    const edKeys = this.anchors.publicKeys
      .filter((k) => k.algorithm === 'Ed25519')
      .filter((k) => keyEligible(k.keyId, authoritySet))
      .map((k) => ed25519FromRawHex(k.publicKeyHex))
      .filter((k): k is crypto.KeyObject => k !== null);

    let edVerified = false;
    let mldsaPresent = false;

    for (const sig of atx.signatures ?? []) {
      if (sig.algorithm === 'Ed25519') {
        let sigBytes: Buffer;
        try {
          sigBytes = Buffer.from(sig.value, 'base64');
        } catch {
          return reject('SIGNATURE_INVALID', `signature ${sig.keyId ?? ''} has invalid base64`);
        }
        const ok = edKeys.some((key) => {
          try {
            return crypto.verify(null, payload, key, sigBytes);
          } catch {
            return false;
          }
        });
        if (!ok) {
          return reject('SIGNATURE_INVALID', `Ed25519 signature ${sig.keyId ?? ''} did not verify`);
        }
        edVerified = true;
      } else if (sig.algorithm === 'ML-DSA-65') {
        // Presence recorded; PQC verification delegated (see module docstring). Not silently skipped.
        mldsaPresent = true;
      }
    }

    if (!edVerified) {
      // Keep mldsaPresent on this rejection: an ML-DSA-only credential fails
      // here precisely because its PQC half is delegated, and the flag is how
      // a caller distinguishes "delegated, bring your own ML-DSA verifier"
      // from "carried no usable signature at all".
      return { ...reject('SIGNATURE_INVALID', 'no Ed25519 signature verified'), mldsaPresent };
    }

    return {
      valid: true,
      mldsaPresent,
      context: {
        agentId: atx.agentId,
        agentDid: atx.agentDid,
        issuerDid: atx.issuerDid,
        issuerChain: atx.issuerChain ?? [atx.issuerDid],
        trustLevel: atx.trustLevel,
        trustScore: atx.trustScore,
        capabilities: atx.capabilities ?? [],
        oasbLevel: atx.scanSummary?.oasbLevel,
        jurisdiction: atx.jurisdiction,
        signedCapabilities: isV11,
      },
    };
  }
}

function reject(rejectCategory: RejectCategory, reason: string): AtxVerificationResult {
  return { valid: false, rejectCategory, reason };
}

/**
 * Whether a key may verify a signature for an issuer in `authoritySet`. Binding
 * applies only to keys whose keyId is a DID-URL (contains '#', naming a
 * controller DID): such a key is eligible only if its controller is in the set.
 * A key without a '#' fragment (or no keyId) expresses no controller and is
 * treated as unbound (legacy single-issuer configs), so it stays eligible.
 */
function keyEligible(keyId: string | undefined, authoritySet: Set<string>): boolean {
  if (!keyId || !keyId.includes('#')) {
    return true;
  }
  return authoritySet.has(controllerDid(keyId));
}

/** The DID portion of a keyId DID-URL (everything before the first '#'). */
function controllerDid(keyId: string): string {
  const i = keyId.indexOf('#');
  return i >= 0 ? keyId.slice(0, i) : keyId;
}

/**
 * Mirror of `opena2a-registry/pkg/atcverify/verify.go canonicalPayload()`:
 *   fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%.6f|%s|%s|%s", ...)
 * with atxVersion hardcoded to "1.0".
 */
export function canonicalPayload(atx: Atx): Buffer {
  const fields = [
    atx.agentId,
    atx.agentDid,
    atx.version,
    atx.contentHash,
    atx.buildAttestation ?? '',
    atx.issuerDid,
    String(Math.trunc(atx.trustLevel)),
    Number(atx.trustScore).toFixed(6),
    normalizeRfc3339(atx.issuedAt),
    normalizeRfc3339(atx.expiresAt),
    SUPPORTED_ATX_VERSION,
  ];
  return Buffer.from(fields.join('|'), 'utf-8');
}

/**
 * Project an ATX into the v1.1 TBS and return JCS(TBS) (RFC 8785). Unlike
 * canonicalPayload, this covers capabilities, scanSummary, issuerChain,
 * publisher, declaredPurpose, and behavioralProfile. The projection (canonical empties,
 * always-full scanSummary, %.6f string trustScore, root-first issuerChain) and
 * the canonicalizer match opena2a-registry/pkg/atcverify and the conformance
 * verifiers exactly; byte agreement is pinned by atx-conformance/jcs-vectors.
 */
export function canonicalPayloadV11(atx: Atx): Buffer {
  const scan = (atx.scanSummary ?? {}) as Record<string, unknown>;
  const tbs: Record<string, unknown> = {
    atcVersion: atx.atcVersion,
    agentId: atx.agentId,
    agentDid: atx.agentDid,
    publisher: atx.publisher ?? '',
    publisherDid: atx.publisherDid ?? '',
    version: atx.version,
    contentHash: atx.contentHash,
    buildAttestation: atx.buildAttestation ?? '',
    capabilities: atx.capabilities ?? [],
    behavioralProfile: projectBehavioralProfile(atx.behavioralProfile),
    ...declaredPurposeTbsMember(atx.declaredPurpose),
    scanSummary: {
      hma: asString(scan.hma),
      criticalFindings: asInt(scan.criticalFindings),
      highFindings: asInt(scan.highFindings),
      secretless: asString(scan.secretless),
      cryptoServe: asString(scan.cryptoServe),
      oasbLevel: asString(scan.oasbLevel),
    },
    // trustScore is the %.6f string form so trustLevel is the only JSON number.
    trustScore: Number(atx.trustScore).toFixed(6),
    trustLevel: Math.trunc(atx.trustLevel),
    issuedAt: normalizeRfc3339(atx.issuedAt),
    expiresAt: normalizeRfc3339(atx.expiresAt),
    issuerDid: atx.issuerDid,
    issuerChain: atx.issuerChain ?? [],
  };
  const canonical = canonicalize(tbs);
  if (typeof canonical !== 'string') {
    throw new Error('canonicalize returned non-string');
  }
  return Buffer.from(canonical, 'utf-8');
}

/**
 * Presence-based rule for the optional declaredPurpose member (atx-spec
 * §1.3a.2 rule 5): an absent purpose — missing, JSON null, or an empty object
 * (emptiness is a parse-level property, so `{ }` counts) — is OMITTED from the
 * TBS, keeping a no-purpose credential byte-identical to one issued before the
 * field existed. Any other present value (a populated object, or a non-object
 * an attacker appends) passes through verbatim for JCS to re-canonicalize, so
 * unsigned purpose content breaks the signature instead of riding it. Matches
 * the Go/Python reference verifiers and the Java SDK's projectDeclaredPurpose.
 */
function declaredPurposeTbsMember(dp: unknown): { declaredPurpose?: unknown } {
  if (dp === null || dp === undefined) {
    return {};
  }
  if (typeof dp === 'object' && !Array.isArray(dp) && Object.keys(dp).length === 0) {
    return {};
  }
  return { declaredPurpose: dp };
}

/** behavioralProfile -> null when absent, else the canonical three-field object. */
function projectBehavioralProfile(
  bp: Atx['behavioralProfile'],
): null | { checksum: string; generatedAt: string; observationDays: number } {
  if (bp === null || bp === undefined) {
    return null;
  }
  return {
    checksum: asString(bp.checksum),
    generatedAt: bp.generatedAt ? normalizeRfc3339(bp.generatedAt) : '',
    observationDays: asInt(bp.observationDays),
  };
}

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function asInt(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : 0;
}

/** Normalize an RFC 3339 timestamp to UTC "YYYY-MM-DDTHH:MM:SSZ" (Go time.RFC3339 for UTC). */
export function normalizeRfc3339(s: string): string {
  const dt = new Date(s);
  if (Number.isNaN(dt.getTime())) {
    throw new Error(`invalid RFC 3339 timestamp: ${s}`);
  }
  return dt.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Build a Node KeyObject from a raw 32-byte Ed25519 public key (hex). */
function ed25519FromRawHex(hex: string): crypto.KeyObject | null {
  const raw = Buffer.from(hex, 'hex');
  if (raw.length !== 32) return null;
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return null;
  }
}

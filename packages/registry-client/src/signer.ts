import { randomUUID } from "node:crypto";
import nacl from "tweetnacl";

/**
 * Privileged provenance classes the registry honors only for a publish signed by an
 * allowlisted first-party key. `community` is the safe default and needs no signature.
 *
 * - `first_party_scanner` — our own batch scanner (e.g. hackmyagent CI/cron).
 * - `ci` — a continuous-integration publisher we operate.
 * - `partner` — a vetted external partner publishing under our banner.
 *
 * See `todo/2026-06-06-first-party-publish-signing-contract.md` and the registry's
 * `internal/application/publish_service.go` (resolveSource / isPrivilegedProvenance).
 */
export type PrivilegedSource = "first_party_scanner" | "ci" | "partner";
export type ScanSource = PrivilegedSource | "community";

/**
 * The fields a first-party signer stamps onto a publish so the registry can authenticate
 * the claimed `source`. Mirrors the server's strong canonical
 * (`name|version|score|maxScore|source|nonce|signedAt`) and the fields it verifies.
 */
export interface FirstPartyProvenance {
  source: ScanSource;
  nonce: string;
  /** Unix time in SECONDS at signing (matches the server freshness window). */
  signedAt: number;
  /** Ed25519 signature over the strong canonical, base64. */
  signature: string;
  /** Ed25519 public key, base64 (raw 32 bytes). Must be in FIRST_PARTY_SCANNER_PUBKEYS. */
  publicKey: string;
}

/** The subset of a scan a signature binds. */
export interface SignableScan {
  name: string;
  version?: string;
  score: number;
  maxScore: number;
}

const ED25519_SEED_BYTES = 32;
const ED25519_SECRET_KEY_BYTES = 64;

/**
 * Build the STRONG canonical string the registry signs and verifies:
 *   `name|version|score|maxScore|source|nonce|signedAt`
 *
 * Pipe-delimited, no surrounding whitespace. score/maxScore/signedAt are decimal
 * integers (no padding). version/source/nonce are the literal strings sent in the body.
 * This MUST byte-match `strongCanonical` in the registry's publish_service.go — a single
 * character difference makes the signature fail to verify (and the scan falls back to
 * community).
 */
export function strongCanonical(
  scan: SignableScan,
  source: ScanSource,
  nonce: string,
  signedAt: number,
): string {
  const version = scan.version ?? "";
  return `${scan.name}|${version}|${scan.score}|${scan.maxScore}|${source}|${nonce}|${signedAt}`;
}

// The pipe is the canonical field delimiter; a field carrying one (or a newline / control
// char) would make the signed string ambiguous. The Go server rebuilds the canonical from
// the same parsed fields so an embedded pipe still byte-matches — this is defense in depth,
// not a known exploit — but we refuse to sign such a field rather than emit an ambiguous
// canonical.
const CANONICAL_FIELD_FORBIDDEN = /[|\r\n\x00-\x1F\x7F]/;

function assertCanonicalField(value: string, label: string): void {
  if (CANONICAL_FIELD_FORBIDDEN.test(value)) {
    throw new Error(
      `FirstPartySigner: ${label} contains a pipe, newline, or control character and cannot be signed`,
    );
  }
}

// score/maxScore are formatted as bare integers in the canonical to match the Go server's
// %d formatting. A float ("90.5"), NaN, or Infinity would diverge from the server byte
// string and silently fail verification (→ community), so reject anything non-integer.
function assertCanonicalInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(
      `FirstPartySigner: ${label} must be a non-negative integer to sign (got ${value})`,
    );
  }
}

/**
 * Coerce a raw Ed25519 secret into the 64-byte tweetnacl secret key (seed||publicKey).
 *
 * Accepts either:
 *   - a 32-byte seed (the "raw 32-byte key" the contract refers to), expanded via
 *     `nacl.sign.keyPair.fromSeed`; or
 *   - a 64-byte tweetnacl/Go secret key, used as-is.
 *
 * Anything else throws — we never silently sign with a malformed key. The byte format is
 * deliberately identical to Go's `crypto/ed25519` (PrivateKeySize=64) so signatures
 * produced here verify in the registry without conversion.
 */
function toSecretKey(secret: Uint8Array): Uint8Array {
  if (secret.length === ED25519_SECRET_KEY_BYTES) {
    return secret;
  }
  if (secret.length === ED25519_SEED_BYTES) {
    return nacl.sign.keyPair.fromSeed(secret).secretKey;
  }
  throw new Error(
    `FirstPartySigner: secret key must be a 32-byte seed or 64-byte secret key (got ${secret.length} bytes)`,
  );
}

export interface FirstPartySignerOptions {
  /**
   * The Ed25519 secret — a 32-byte seed (preferred) or a 64-byte secret key
   * (seed||publicKey, tweetnacl/Go format). Keep this in the runtime's secret store;
   * never commit or log it.
   */
  secretKey: Uint8Array;
  /** The provenance class this publisher is authorized to claim. */
  source: PrivilegedSource;
  /**
   * Nonce generator (override for tests). Default: a UUIDv4 per call. Must be unique
   * per publish — the server enforces single-use.
   */
  generateNonce?: () => string;
  /**
   * Clock (override for tests). Returns Unix time in SECONDS. Default: real time.
   */
  now?: () => number;
}

/**
 * Signs a scan publish so the registry will honor its privileged `source`.
 *
 * The signer derives the public key from the secret, so the caller never has to keep the
 * two in sync. `sign()` is pure given a fixed nonce/clock; by default each call mints a
 * fresh nonce and stamps the current time (the server requires both: single-use nonce +
 * freshness window).
 */
export class FirstPartySigner {
  private readonly secretKey: Uint8Array;
  private readonly publicKeyB64: string;
  private readonly source: PrivilegedSource;
  private readonly generateNonce: () => string;
  private readonly now: () => number;

  constructor(options: FirstPartySignerOptions) {
    this.secretKey = toSecretKey(options.secretKey);
    // tweetnacl's secret key embeds the public key in its trailing 32 bytes; derive it so
    // the publicKey on the wire always matches the signing key.
    this.publicKeyB64 = Buffer.from(this.secretKey.slice(ED25519_SEED_BYTES)).toString(
      "base64",
    );
    this.source = options.source;
    this.generateNonce = options.generateNonce ?? randomUUID;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));

    // Self-verify: sign a fixed probe and confirm it verifies under the derived public
    // key. Catches a corrupted 64-byte secret key (whose embedded public-key bytes don't
    // match the signing half) loudly at construction, instead of silently emitting
    // signatures the server downgrades to community. (A 32-byte value that is actually a
    // public key used as a seed still yields a self-consistent — but wrong — keypair; that
    // case is undetectable here and is caught by the server allowlist, which fails closed.)
    const probe = Buffer.from("opena2a-first-party-signer-selfcheck", "utf-8");
    const ok = nacl.sign.detached.verify(
      probe,
      nacl.sign.detached(probe, this.secretKey),
      Buffer.from(this.publicKeyB64, "base64"),
    );
    if (!ok) {
      throw new Error(
        "FirstPartySigner: secret key failed self-verification (corrupted or malformed key)",
      );
    }
  }

  /** The base64 public key to register in the server's FIRST_PARTY_SCANNER_PUBKEYS. */
  get publicKey(): string {
    return this.publicKeyB64;
  }

  /**
   * Produce the provenance fields for a scan. Each call generates a fresh nonce and
   * signedAt, so a signer instance can sign many publishes.
   */
  sign(scan: SignableScan): FirstPartyProvenance {
    // Validate the fields that flow into the signed canonical. score/maxScore must be
    // integers (Go server formats with %d); name/version/nonce must not carry the pipe
    // delimiter or control chars. We refuse to sign rather than emit a canonical the
    // server would reject (silent community downgrade) or that is ambiguous.
    assertCanonicalField(scan.name, "name");
    assertCanonicalField(scan.version ?? "", "version");
    assertCanonicalInteger(scan.score, "score");
    assertCanonicalInteger(scan.maxScore, "maxScore");
    const nonce = this.generateNonce();
    assertCanonicalField(nonce, "nonce");
    const signedAt = this.now();
    const canonical = strongCanonical(scan, this.source, nonce, signedAt);
    const signature = nacl.sign.detached(
      Buffer.from(canonical, "utf-8"),
      this.secretKey,
    );
    return {
      source: this.source,
      nonce,
      signedAt,
      signature: Buffer.from(signature).toString("base64"),
      publicKey: this.publicKeyB64,
    };
  }
}

/**
 * Decode a raw Ed25519 secret from a string. Accepts base64 or hex, holding either a
 * 32-byte seed or a 64-byte secret key. Returns null for empty/whitespace input.
 * Throws on a non-empty value that is neither valid base64 nor valid hex of a plausible
 * length — we fail loud rather than silently signing with garbage.
 */
export function decodeSecretKey(raw: string): Uint8Array | null {
  const s = raw.trim();
  if (!s) return null;
  // Hex first (unambiguous: only [0-9a-f], even length 64 or 128).
  if (/^[0-9a-fA-F]+$/.test(s) && (s.length === 64 || s.length === 128)) {
    return Uint8Array.from(Buffer.from(s, "hex"));
  }
  const b = Uint8Array.from(Buffer.from(s, "base64"));
  if (b.length === ED25519_SEED_BYTES || b.length === ED25519_SECRET_KEY_BYTES) {
    return b;
  }
  throw new Error(
    "decodeSecretKey: expected a base64 or hex Ed25519 32-byte seed or 64-byte secret key",
  );
}

export interface SignerFromEnvOptions {
  /** Env var holding the base64/hex secret (seed or full key). Default OPENA2A_FIRST_PARTY_KEY. */
  keyEnv?: string;
  /** Provenance class to claim when the key is present. */
  source: PrivilegedSource;
  /** Override the environment (tests). Default process.env. */
  env?: NodeJS.ProcessEnv;
}

/**
 * Build a {@link FirstPartySigner} from a secret in the environment, or return undefined
 * when the key env var is unset/empty.
 *
 * This is the Secretless-compliant way for our CI/cron publishers to sign: the scanner
 * secret lives only in the runtime env, never in the repo. End-user runs (no env var)
 * get `undefined`, so their scans publish as community — we never mis-tag a community
 * scan as first-party.
 */
export function firstPartySignerFromEnv(
  options: SignerFromEnvOptions,
): FirstPartySigner | undefined {
  const env = options.env ?? process.env;
  const keyEnv = options.keyEnv ?? "OPENA2A_FIRST_PARTY_KEY";
  // Fail closed: an unset, malformed, or unusable key yields undefined (the caller then
  // publishes as community) rather than throwing. A misconfigured CI key must never crash
  // a publish; the staging-verify step (rows landing as community instead of the claimed
  // source) is where a wrong-but-valid key is caught. Use `new FirstPartySigner` directly
  // if you want construction to throw on a bad key.
  try {
    const secretKey = decodeSecretKey(env[keyEnv] ?? "");
    if (!secretKey) return undefined;
    return new FirstPartySigner({ secretKey, source: options.source });
  } catch {
    return undefined;
  }
}

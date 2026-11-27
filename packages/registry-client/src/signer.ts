import { randomUUID } from "node:crypto";
import { inspect } from "node:util";
import nacl from "tweetnacl";

/**
 * Privileged provenance classes the registry honors only for a publish signed by an
 * allowlisted first-party key. `community` is the safe default and needs no signature.
 *
 * - `first_party_scanner` — our own batch scanner (e.g. hackmyagent CI/cron).
 * - `ci` — a continuous-integration publisher we operate.
 * - `partner` — a vetted external partner publishing under our banner.
 *
 * The registry enforces this in `internal/application/publish_service.go`
 * (resolveSource / isPrivilegedProvenance).
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
const MIN_NONCE_LENGTH = 16;
const PRIVILEGED_SOURCES: readonly string[] = ["first_party_scanner", "ci", "partner"];

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
// Only safe integers are accepted: a value of 1e21 or more would format as "1e+21".
function assertCanonicalInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(
      `FirstPartySigner: ${label} must be a non-negative integer to sign (got ${value})`,
    );
  }
}

function assertPrivilegedSource(source: unknown): asserts source is PrivilegedSource {
  if (typeof source !== "string" || !PRIVILEGED_SOURCES.includes(source)) {
    throw new Error(
      `FirstPartySigner: source must be one of ${PRIVILEGED_SOURCES.join(", ")} (got ${String(source)})`,
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
    // Copy, so later changes to the caller's array cannot alter the signer's key.
    return Uint8Array.from(secret);
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
  // ES private fields: the key (and the other state) is not an enumerable property, so it
  // is absent from JSON.stringify, Object.keys, structured dumps and util.inspect output.
  readonly #secretKey: Uint8Array;
  readonly #publicKeyB64: string;
  readonly #source: PrivilegedSource;
  readonly #generateNonce: () => string;
  readonly #now: () => number;

  constructor(options: FirstPartySignerOptions) {
    assertPrivilegedSource(options.source);
    this.#secretKey = toSecretKey(options.secretKey);
    // tweetnacl's secret key embeds the public key in its trailing 32 bytes; derive it so
    // the publicKey on the wire always matches the signing key.
    this.#publicKeyB64 = Buffer.from(this.#secretKey.slice(ED25519_SEED_BYTES)).toString(
      "base64",
    );
    this.#source = options.source;
    this.#generateNonce = options.generateNonce ?? randomUUID;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));

    // Self-verify: sign a fixed probe and confirm it verifies under the derived public
    // key. Catches a corrupted 64-byte secret key (whose embedded public-key bytes don't
    // match the signing half) loudly at construction, instead of silently emitting
    // signatures the server downgrades to community. (A 32-byte value that is actually a
    // public key used as a seed still yields a self-consistent — but wrong — keypair; that
    // case is undetectable here and is caught by the server allowlist, which fails closed.)
    const probe = Buffer.from("opena2a-first-party-signer-selfcheck", "utf-8");
    const ok = nacl.sign.detached.verify(
      probe,
      nacl.sign.detached(probe, this.#secretKey),
      Buffer.from(this.#publicKeyB64, "base64"),
    );
    if (!ok) {
      throw new Error(
        "FirstPartySigner: secret key failed self-verification (corrupted or malformed key)",
      );
    }
  }

  /** Only the public key and source are ever serialised; the secret key is never included. */
  toJSON(): { publicKey: string; source: PrivilegedSource } {
    return { publicKey: this.#publicKeyB64, source: this.#source };
  }

  /** `console.log` / `util.inspect` show only the public key and source. */
  [inspect.custom](): string {
    return `FirstPartySigner ${inspect(this.toJSON())}`;
  }

  /** The base64 public key to register in the server's FIRST_PARTY_SCANNER_PUBKEYS. */
  get publicKey(): string {
    return this.#publicKeyB64;
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
    const nonce = this.#generateNonce();
    if (typeof nonce !== "string" || nonce.length < MIN_NONCE_LENGTH) {
      throw new Error(
        `FirstPartySigner: nonce must be a string of at least ${MIN_NONCE_LENGTH} characters`,
      );
    }
    assertCanonicalField(nonce, "nonce");
    const signedAt = this.#now();
    if (!Number.isSafeInteger(signedAt) || signedAt < 0) {
      throw new Error(
        `FirstPartySigner: signedAt must be a non-negative integer number of seconds (got ${signedAt})`,
      );
    }
    const canonical = strongCanonical(scan, this.#source, nonce, signedAt);
    const signature = nacl.sign.detached(
      Buffer.from(canonical, "utf-8"),
      this.#secretKey,
    );
    return {
      source: this.#source,
      nonce,
      signedAt,
      signature: Buffer.from(signature).toString("base64"),
      publicKey: this.#publicKeyB64,
    };
  }
}

/**
 * Decode a raw Ed25519 secret from a string. Accepts base64 or hex, holding either a
 * 32-byte seed or a 64-byte secret key. Returns null for empty/whitespace input.
 * Throws on a non-empty value that is neither valid base64 nor valid hex of a plausible
 * length — we fail loud rather than silently signing with garbage.
 */
const STRICT_BASE64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}(?:==)?|[A-Za-z0-9+/]{3}=?)?$/;

export function decodeSecretKey(raw: string): Uint8Array | null {
  const s = raw.trim();
  if (!s) return null;
  // Hex first (unambiguous: only [0-9a-f], even length 64 or 128).
  if (/^[0-9a-fA-F]+$/.test(s) && (s.length === 64 || s.length === 128)) {
    return Uint8Array.from(Buffer.from(s, "hex"));
  }
  // Standard base64 only (padding optional): Node's decoder silently skips characters
  // outside the alphabet, so the text is checked before decoding.
  if (STRICT_BASE64.test(s)) {
    const b = Uint8Array.from(Buffer.from(s, "base64"));
    if (b.length === ED25519_SEED_BYTES || b.length === ED25519_SECRET_KEY_BYTES) {
      return b;
    }
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
  /**
   * Throw when the variable holds a value that is not a usable key, instead of returning
   * undefined. An unset or empty variable still returns undefined. Default false.
   */
  strict?: boolean;
  /**
   * Delete the variable from the environment once it has been read, so child processes
   * do not inherit the key. Applies whether or not the value turns out to be usable.
   * Default true.
   */
  removeFromEnv?: boolean;
}

/**
 * Build a {@link FirstPartySigner} from a secret in the environment, or return undefined
 * when the key env var is unset/empty.
 *
 * This is the Secretless-compliant way for our CI/cron publishers to sign: the scanner
 * secret lives only in the runtime env, never in the repo. End-user runs (no env var)
 * get `undefined`, so their scans publish as community — we never mis-tag a community
 * scan as first-party.
 *
 * A value that is present but not a usable key returns `undefined` too, unless
 * `strict: true`, in which case the error is thrown. By default the variable is removed
 * from the environment after it is read (`removeFromEnv: false` keeps it), so a second
 * call for the same variable sees it unset.
 */
export function firstPartySignerFromEnv(
  options: SignerFromEnvOptions,
): FirstPartySigner | undefined {
  const env = options.env ?? process.env;
  const keyEnv = options.keyEnv ?? "OPENA2A_FIRST_PARTY_KEY";
  const raw = env[keyEnv] ?? "";
  if (options.removeFromEnv ?? true) {
    delete env[keyEnv];
  }
  try {
    const secretKey = decodeSecretKey(raw);
    if (!secretKey) return undefined;
    return new FirstPartySigner({ secretKey, source: options.source });
  } catch (err) {
    if (options.strict) throw err;
    return undefined;
  }
}

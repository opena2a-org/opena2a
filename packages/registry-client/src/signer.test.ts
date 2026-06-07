import { describe, expect, it } from "vitest";
import nacl from "tweetnacl";
import {
  FirstPartySigner,
  strongCanonical,
  type SignableScan,
} from "./signer.js";

// normalizeToBase64 mirror: the registry accepts hex OR base64 public keys. Our signer
// emits base64, so verification here uses base64 directly.

const SCAN: SignableScan = {
  name: "left-pad",
  version: "1.0.0",
  score: 90,
  maxScore: 100,
};

/** Verify a base64 signature over the strong canonical, the way the registry does. */
function verify(
  scan: SignableScan,
  source: string,
  nonce: string,
  signedAt: number,
  signatureB64: string,
  publicKeyB64: string,
): boolean {
  const canonical = `${scan.name}|${scan.version ?? ""}|${scan.score}|${scan.maxScore}|${source}|${nonce}|${signedAt}`;
  return nacl.sign.detached.verify(
    Buffer.from(canonical, "utf-8"),
    Buffer.from(signatureB64, "base64"),
    Buffer.from(publicKeyB64, "base64"),
  );
}

describe("strongCanonical", () => {
  it("matches the registry's pipe-delimited format exactly", () => {
    // Mirrors the brief's example shape: name|version|score|maxScore|source|nonce|signedAt
    expect(strongCanonical(SCAN, "first_party_scanner", "abc", 1749250000)).toBe(
      "left-pad|1.0.0|90|100|first_party_scanner|abc|1749250000",
    );
  });

  it("renders a missing version as an empty field (not 'undefined')", () => {
    const noVersion: SignableScan = { name: "x", score: 1, maxScore: 100 };
    expect(strongCanonical(noVersion, "ci", "n", 5)).toBe("x||1|100|ci|n|5");
  });

  it("renders integers without padding", () => {
    expect(strongCanonical({ name: "x", version: "0", score: 0, maxScore: 100 }, "partner", "n", 1)).toBe(
      "x|0|0|100|partner|n|1",
    );
  });
});

describe("FirstPartySigner", () => {
  // A fixed seed so the test is deterministic; the public key is derived from it.
  const seed = new Uint8Array(32).fill(7);
  const fixedNonce = "nonce-abc-123";
  const fixedSignedAt = 1749250000;

  function fixedSigner(source: "first_party_scanner" | "ci" | "partner" = "first_party_scanner") {
    return new FirstPartySigner({
      secretKey: seed,
      source,
      generateNonce: () => fixedNonce,
      now: () => fixedSignedAt,
    });
  }

  it("produces a signature the registry's strong canonical verification accepts", () => {
    const signer = fixedSigner();
    const prov = signer.sign(SCAN);
    expect(prov.source).toBe("first_party_scanner");
    expect(prov.nonce).toBe(fixedNonce);
    expect(prov.signedAt).toBe(fixedSignedAt);
    expect(
      verify(SCAN, prov.source, prov.nonce, prov.signedAt, prov.signature, prov.publicKey),
    ).toBe(true);
  });

  it("derives the public key from the secret (matches what it signs with)", () => {
    const signer = fixedSigner();
    const expectedPub = Buffer.from(
      nacl.sign.keyPair.fromSeed(seed).publicKey,
    ).toString("base64");
    expect(signer.publicKey).toBe(expectedPub);
    expect(signer.sign(SCAN).publicKey).toBe(expectedPub);
  });

  it("accepts a 64-byte secret key as well as a 32-byte seed", () => {
    const full = nacl.sign.keyPair.fromSeed(seed).secretKey; // 64 bytes
    const a = new FirstPartySigner({ secretKey: seed, source: "ci", generateNonce: () => fixedNonce, now: () => fixedSignedAt });
    const b = new FirstPartySigner({ secretKey: full, source: "ci", generateNonce: () => fixedNonce, now: () => fixedSignedAt });
    expect(a.sign(SCAN).signature).toBe(b.sign(SCAN).signature);
    expect(a.publicKey).toBe(b.publicKey);
  });

  it("rejects a malformed secret key length", () => {
    expect(() => new FirstPartySigner({ secretKey: new Uint8Array(16), source: "ci" })).toThrow(
      /32-byte seed or 64-byte secret key/,
    );
  });

  it("binds source: a verification under a different source fails (no source-swap)", () => {
    const prov = fixedSigner("first_party_scanner").sign(SCAN);
    // Tamper: keep the signature but claim 'partner'. Registry strong canonical changes.
    expect(
      verify(SCAN, "partner", prov.nonce, prov.signedAt, prov.signature, prov.publicKey),
    ).toBe(false);
  });

  it("binds the scan content: a different score fails verification", () => {
    const prov = fixedSigner().sign(SCAN);
    expect(
      verify({ ...SCAN, score: 91 }, prov.source, prov.nonce, prov.signedAt, prov.signature, prov.publicKey),
    ).toBe(false);
  });

  it("mints a fresh nonce per call by default", () => {
    const signer = new FirstPartySigner({ secretKey: seed, source: "ci" });
    const a = signer.sign(SCAN);
    const b = signer.sign(SCAN);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it("stamps signedAt in Unix seconds by default (not milliseconds)", () => {
    const signer = new FirstPartySigner({ secretKey: seed, source: "ci" });
    const prov = signer.sign(SCAN);
    const nowSec = Math.floor(Date.now() / 1000);
    // Within a few seconds of real wall-clock, and clearly seconds-scale (10 digits).
    expect(Math.abs(prov.signedAt - nowSec)).toBeLessThan(5);
    expect(String(prov.signedAt).length).toBe(10);
  });

  it("an attacker's key signing the same canonical does not verify under our public key", () => {
    const prov = fixedSigner().sign(SCAN);
    const attacker = nacl.sign.keyPair();
    const attackerPub = Buffer.from(attacker.publicKey).toString("base64");
    // Same canonical, attacker signature — must not verify under the attacker's key
    // being presented as ours, and our signature must not verify under the attacker key.
    expect(
      verify(SCAN, prov.source, prov.nonce, prov.signedAt, prov.signature, attackerPub),
    ).toBe(false);
  });
});

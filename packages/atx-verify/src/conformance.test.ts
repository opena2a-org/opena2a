/**
 * Conformance gate: run LocalAtxVerifier against the OpenA2A ATX conformance
 * fixtures (verbatim copies from `atx-conformance/fixtures/`, including their
 * PINNED Ed25519 signatures and issuer public keys). This proves the verifier
 * accepts/rejects exactly the credentials the cross-language suite does — the
 * same fixtures the Go and Python reference verifiers are gated against.
 *
 * We assert the machine contract (verifyResult + rejectCategory). We do NOT
 * assert the fixtures' `reasonContains` — that is the reference verifiers'
 * specific human wording; this verifier's reason strings are its own and the
 * structured rejectCategory is the interoperable contract.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  LocalAtxVerifier,
  type Atx,
  type AtxPublicKey,
  type AtxTrustAnchors,
} from './atx.js';

interface Fixture {
  name: string;
  verifierState: {
    clockRfc3339: string;
    trustedIssuers: string[];
    publicKeys: Array<{ algorithm: string; publicKeyHex: string; keyId?: string }>;
    crl?: { entries: Array<{ agentId: string; reason?: string }> };
  };
  expected: { verifyResult: 'ACCEPT' | 'REJECT'; rejectCategory?: string };
  atx: Atx;
}

/** Representative v1.0 fixtures lifted from atx-conformance/fixtures/. */
const FIXTURE_FILES = [
  'baseline-valid.json',
  'tampered-signature.json',
  'expired.json',
  'revoked.json',
  'wrong-issuer.json',
  'cross-issuer-key.json',
] as const;

function loadFixture(file: string): Fixture {
  const url = new URL(`./__fixtures__/${file}`, import.meta.url);
  return JSON.parse(readFileSync(url, 'utf-8')) as Fixture;
}

function anchorsFromFixture(f: Fixture): AtxTrustAnchors {
  const clock = new Date(f.verifierState.clockRfc3339);
  return {
    trustedIssuers: f.verifierState.trustedIssuers,
    publicKeys: f.verifierState.publicKeys.map(
      (k): AtxPublicKey => ({ algorithm: k.algorithm, publicKeyHex: k.publicKeyHex, keyId: k.keyId }),
    ),
    crl: f.verifierState.crl,
    now: () => clock,
  };
}

describe('conformance fixtures (atx-conformance/fixtures, pinned signatures)', () => {
  for (const file of FIXTURE_FILES) {
    const f = loadFixture(file);
    it(`${f.name} -> ${f.expected.verifyResult}${f.expected.rejectCategory ? ` (${f.expected.rejectCategory})` : ''}`, () => {
      const result = new LocalAtxVerifier(anchorsFromFixture(f)).verify(f.atx);
      expect(result.valid).toBe(f.expected.verifyResult === 'ACCEPT');
      if (f.expected.verifyResult === 'REJECT' && f.expected.rejectCategory) {
        expect(result.rejectCategory).toBe(f.expected.rejectCategory);
      }
    });
  }
});

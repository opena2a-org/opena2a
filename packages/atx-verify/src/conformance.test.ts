/**
 * Conformance gate: run LocalAtxVerifier against the FULL OpenA2A ATX
 * conformance suite (verbatim copies from `atx-conformance/fixtures/` pinned at
 * f4d40a4, including their PINNED Ed25519 signatures and issuer public keys —
 * CI byte-compares the vendored copies against the pinned suite). This proves
 * the verifier accepts/rejects exactly the credentials the Go and Python
 * reference verifiers do.
 *
 * Every fixture is replayed through the RAW entry point (`verifyCredential`)
 * so the strict parse — duplicate / fold-colliding members at any depth — runs
 * before any field is interpreted: the object-taking `verify(atx)` cannot see
 * members `JSON.parse`'s last-wins semantics have already collapsed. The
 * credential bytes are extracted from each fixture by tokenizer offsets
 * (`topLevelMemberSpan`), duplicates preserved; the fixture wrapper itself is
 * harness metadata and parses leniently.
 *
 * We assert the machine contract (verifyResult + rejectCategory). We do NOT
 * assert the fixtures' `reasonContains` — that is the reference verifiers'
 * specific human wording. Where the reference verifiers report PARSE_ERROR
 * (strict-parse rejections), this SDK reports MALFORMED — the SDK
 * RejectCategory union (shared with the AIM Java SDK) has no PARSE_ERROR, and
 * MALFORMED is its structural-parse category — so those fixtures map to
 * MALFORMED here.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import {
  LocalAtxVerifier,
  type AtxPublicKey,
  type AtxTrustAnchors,
  type RejectCategory,
} from './atx.js';
import { topLevelMemberSpan } from './strict-parse.js';

interface Fixture {
  name: string;
  verifierState: {
    clockRfc3339: string;
    trustedIssuers: string[];
    publicKeys: Array<{ algorithm: string; publicKeyHex: string; keyId?: string }>;
    crl?: { entries: Array<{ agentId: string; reason?: string }> };
  };
  expected: { verifyResult: 'ACCEPT' | 'REJECT'; rejectCategory?: string };
}

/** The suite pinned at atx-conformance f4d40a4 has exactly 20 fixtures. */
const PINNED_SUITE_SIZE = 20;

const FIXTURES_DIR = new URL('./__fixtures__/', import.meta.url);
const fixtureFiles = readdirSync(FIXTURES_DIR)
  .filter((f) => f.endsWith('.json'))
  .sort();

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

/** The reference suite's PARSE_ERROR is this SDK's MALFORMED (see header). */
function expectedCategory(suiteCategory: string): RejectCategory {
  return (suiteCategory === 'PARSE_ERROR' ? 'MALFORMED' : suiteCategory) as RejectCategory;
}

describe('conformance fixtures (atx-conformance @ f4d40a4, pinned signatures)', () => {
  it(`covers the full pinned suite (${PINNED_SUITE_SIZE} fixtures)`, () => {
    expect(fixtureFiles.length).toBe(PINNED_SUITE_SIZE);
  });

  for (const file of fixtureFiles) {
    const rawText = readFileSync(new URL(file, FIXTURES_DIR), 'utf-8');
    // Wrapper parse is lenient (harness metadata); the credential bytes are
    // sliced raw below so strict-parse fixtures keep their duplicate members.
    const f = JSON.parse(rawText) as Fixture;
    const span = topLevelMemberSpan(rawText, 'atx');
    if (span === null) {
      throw new Error(`fixture ${file} has no top-level atx member`);
    }
    const rawAtx = rawText.slice(span.start, span.end);

    it(`${f.name} -> ${f.expected.verifyResult}${f.expected.rejectCategory ? ` (${f.expected.rejectCategory})` : ''}`, () => {
      const result = new LocalAtxVerifier(anchorsFromFixture(f)).verifyCredential(rawAtx);
      if (f.expected.verifyResult === 'ACCEPT') {
        expect(result.valid, `expected ACCEPT, got: ${result.reason}`).toBe(true);
      } else {
        expect(result.valid, 'expected REJECT but verifier accepted').toBe(false);
        if (f.expected.rejectCategory) {
          expect(result.rejectCategory).toBe(expectedCategory(f.expected.rejectCategory));
        }
      }
    });
  }
});

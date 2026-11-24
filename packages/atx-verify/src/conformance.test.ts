/**
 * Conformance gate: run LocalAtxVerifier against all 23 fixtures of the OpenA2A
 * ATX conformance suite (verbatim copies from `atx-conformance/fixtures/`,
 * including their PINNED Ed25519 and ML-DSA-65 signatures and issuer public
 * keys). This proves the verifier accepts/rejects exactly the credentials the
 * Go and Python reference verifiers do.
 *
 * The fixtures come from two refs. 21 are under `./__fixtures__/`, pinned at
 * d2b8376; CI byte-compares that directory against the suite at its
 * `ATX_CONFORMANCE_REF` in both directions. The two the suite added at
 * eb06f2c (`v1_1-hybrid-mldsa-tampered`, `v1_1-no-transparency-log-index`)
 * are under `./__fixtures_eb06f2c__/`, so the CI byte-compare still holds
 * until CI moves its pin. 0.3.0 and 0.4.0 produced 21 of these 23
 * (opena2a-standards/atx-spec#46): they accepted `v1_1-hybrid-mldsa-tampered`
 * and `v1_1-untrusted-chain-authority`, both pinned REJECT SIGNATURE_INVALID.
 *
 * The expected verdict of every fixture is FROZEN in this file
 * (`PINNED_VERDICTS`, keyed by vendored file name) rather than read only from
 * each fixture's own `expected` member: the directory listing must equal the
 * table's key set, and each fixture's `expected` member must equal its table
 * row, before the verifier result is compared against that row. A fixture that
 * is renamed, deleted, added or re-verdicted in place therefore fails in a diff
 * of THIS file — the directory alone can no longer silently move the goalposts.
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
 * MALFORMED here. The table below keeps the suite's own PARSE_ERROR spelling;
 * the mapping is applied at compare time (`expectedCategory`).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import {
  LocalAtxVerifier,
  type AtxPublicKey,
  type AtxTrustAnchors,
  type AtxVerificationResult,
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

/**
 * The full atx-conformance commit the vendored fixtures are pinned at — the
 * same 40-character value `.github/workflows/ci.yml` spells as
 * `ATX_CONFORMANCE_REF` (asserted equal below). Its 7-character prefix is the
 * `d2b8376` named in this file's header, in the `PINNED_SUITE_SIZE` doc
 * comment and in the describe title.
 */
export const ATX_CONFORMANCE_REF = 'd2b8376daaec47046e54a3035178d706a5edec1d';

/** Workflow file that pins the suite ref, relative to this test file. */
const CI_WORKFLOW_URL = new URL('../../../.github/workflows/ci.yml', import.meta.url);

/** The suite pinned at atx-conformance d2b8376 has exactly 21 fixtures. */
const PINNED_SUITE_SIZE = 21;

/**
 * The atx-conformance commit the two fixtures under `./__fixtures_eb06f2c__/`
 * were copied from: the suite's 23-fixture ref.
 */
export const ADDED_FIXTURES_REF = 'eb06f2c76a264a3abf999e91e0502dba594e3495';

/** The fixtures the suite added between d2b8376 and eb06f2c. */
const ADDED_FIXTURE_FILES = [
  'v1_1-hybrid-mldsa-tampered.json',
  'v1_1-no-transparency-log-index.json',
] as const;

/** All 23 fixtures: the 21 at d2b8376 and the 2 added at eb06f2c. */
const CONFORMANCE_SUITE_SIZE = PINNED_SUITE_SIZE + ADDED_FIXTURE_FILES.length;

/** A frozen row: the suite's own spelling of the verdict (PARSE_ERROR kept). */
type PinnedVerdict =
  | { verifyResult: 'ACCEPT'; rejectCategory?: undefined }
  | { verifyResult: 'REJECT'; rejectCategory: string };

/**
 * The FROZEN verdict table for all 23 fixtures, keyed by vendored fixture FILE
 * NAME under `./__fixtures__/` or `./__fixtures_eb06f2c__/`. Each row is the
 * fixture's own `expected.verifyResult` and, for a REJECT, its own
 * `expected.rejectCategory` exactly as the suite writes it (PARSE_ERROR stays
 * PARSE_ERROR here; `expectedCategory` maps it to MALFORMED at compare time).
 *
 * Changing this table is a deliberate act reviewed in a diff of this file:
 * the tests below fail when the directory listing or any fixture's `expected`
 * member disagrees with it.
 */
export const PINNED_VERDICTS: Readonly<Record<string, PinnedVerdict>> = Object.freeze({
  'baseline-valid-hybrid.json': { verifyResult: 'ACCEPT' },
  'baseline-valid.json': { verifyResult: 'ACCEPT' },
  'cross-issuer-key.json': { verifyResult: 'REJECT', rejectCategory: 'SIGNATURE_INVALID' },
  'expired.json': { verifyResult: 'REJECT', rejectCategory: 'EXPIRED' },
  'malformed-schema.json': { verifyResult: 'REJECT', rejectCategory: 'UNSUPPORTED_VERSION' },
  'revoked.json': { verifyResult: 'REJECT', rejectCategory: 'REVOKED' },
  'tampered-signature.json': { verifyResult: 'REJECT', rejectCategory: 'SIGNATURE_INVALID' },
  'threshold-2of3-cosignature.json': { verifyResult: 'ACCEPT' },
  'v1_1-baseline-valid-hybrid.json': { verifyResult: 'ACCEPT' },
  'v1_1-baseline-valid.json': { verifyResult: 'ACCEPT' },
  'v1_1-case-variant-member.json': { verifyResult: 'REJECT', rejectCategory: 'PARSE_ERROR' },
  'v1_1-cross-issuer-key.json': { verifyResult: 'REJECT', rejectCategory: 'SIGNATURE_INVALID' },
  'v1_1-declared-purpose-array-injected.json': {
    verifyResult: 'REJECT',
    rejectCategory: 'SIGNATURE_INVALID',
  },
  'v1_1-declared-purpose-empty-whitespace.json': { verifyResult: 'ACCEPT' },
  'v1_1-declared-purpose-string-injected.json': {
    verifyResult: 'REJECT',
    rejectCategory: 'SIGNATURE_INVALID',
  },
  'v1_1-declared-purpose-valid.json': { verifyResult: 'ACCEPT' },
  'v1_1-duplicate-purpose-member.json': { verifyResult: 'REJECT', rejectCategory: 'PARSE_ERROR' },
  // Added at eb06f2c: a hybrid credential whose Ed25519 signature is intact and
  // whose ML-DSA-65 signature was flipped by one bit after signing.
  'v1_1-hybrid-mldsa-tampered.json': {
    verifyResult: 'REJECT',
    rejectCategory: 'SIGNATURE_INVALID',
  },
  // Added at eb06f2c: the optional transparencyLogIndex is outside JCS(TBS).
  'v1_1-no-transparency-log-index.json': { verifyResult: 'ACCEPT' },
  'v1_1-tampered-capabilities.json': { verifyResult: 'REJECT', rejectCategory: 'SIGNATURE_INVALID' },
  'v1_1-tampered-declared-purpose.json': {
    verifyResult: 'REJECT',
    rejectCategory: 'SIGNATURE_INVALID',
  },
  // Fixture 21: the MUST-REJECT chain-authority case the 21-fixture pin exists
  // to replay (a chain whose authority is not a trusted anchor).
  'v1_1-untrusted-chain-authority.json': {
    verifyResult: 'REJECT',
    rejectCategory: 'SIGNATURE_INVALID',
  },
  'wrong-issuer.json': { verifyResult: 'REJECT', rejectCategory: 'UNTRUSTED_ISSUER' },
});

const FIXTURES_DIR = new URL('./__fixtures__/', import.meta.url);
const ADDED_FIXTURES_DIR = new URL('./__fixtures_eb06f2c__/', import.meta.url);

function jsonFiles(dir: URL): string[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort();
}

/** The 21 fixtures at d2b8376 (the directory CI byte-compares). */
const pinnedFixtureFiles = jsonFiles(FIXTURES_DIR);
/** The 2 fixtures added at eb06f2c. */
const addedFixtureFiles = jsonFiles(ADDED_FIXTURES_DIR);
/** All 23, each with the directory it is read from. */
const fixtureSources: Array<{ file: string; dir: URL }> = [
  ...pinnedFixtureFiles.map((file) => ({ file, dir: FIXTURES_DIR })),
  ...addedFixtureFiles.map((file) => ({ file, dir: ADDED_FIXTURES_DIR })),
].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
const fixtureFiles = fixtureSources.map((s) => s.file);

interface LoadedFixture {
  fixture: Fixture;
  /** The credential bytes, sliced raw so strict-parse fixtures keep duplicates. */
  rawAtx: string;
}

function loadFixture(file: string, dir: URL): LoadedFixture {
  const rawText = readFileSync(new URL(file, dir), 'utf-8');
  // Wrapper parse is lenient (harness metadata); the credential bytes are
  // sliced raw so strict-parse fixtures keep their duplicate members.
  const fixture = JSON.parse(rawText) as Fixture;
  const span = topLevelMemberSpan(rawText, 'atx');
  if (span === null) {
    throw new Error(`fixture ${file} has no top-level atx member`);
  }
  return { fixture, rawAtx: rawText.slice(span.start, span.end) };
}

function loadNamedFixture(file: string): LoadedFixture {
  const source = fixtureSources.find((s) => s.file === file);
  if (source === undefined) {
    throw new Error(`fixture ${file} is not vendored`);
  }
  return loadFixture(source.file, source.dir);
}

/** Whether the verifier's result is the row's verdict and, for a REJECT, its category. */
function matchesPinned(pinned: PinnedVerdict, result: AtxVerificationResult): boolean {
  if (pinned.verifyResult === 'ACCEPT') {
    return result.valid;
  }
  return !result.valid && result.rejectCategory === expectedCategory(pinned.rejectCategory);
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

/** The reference suite's PARSE_ERROR is this SDK's MALFORMED (see header). */
function expectedCategory(suiteCategory: string): RejectCategory {
  return (suiteCategory === 'PARSE_ERROR' ? 'MALFORMED' : suiteCategory) as RejectCategory;
}

function describeVerdict(v: { verifyResult: string; rejectCategory?: string }): string {
  return `${v.verifyResult}${v.rejectCategory ? ` (${v.rejectCategory})` : ''}`;
}

describe('conformance fixtures (atx-conformance @ d2b8376 + eb06f2c, pinned signatures)', () => {
  it(`vendors the ${PINNED_SUITE_SIZE} fixtures at d2b8376 and the ${ADDED_FIXTURE_FILES.length} added at eb06f2c`, () => {
    expect(pinnedFixtureFiles.length).toBe(PINNED_SUITE_SIZE);
    expect(addedFixtureFiles).toEqual([...ADDED_FIXTURE_FILES]);
    expect(pinnedFixtureFiles.filter((f) => addedFixtureFiles.includes(f))).toEqual([]);
    expect(fixtureFiles.length).toBe(CONFORMANCE_SUITE_SIZE);
    expect(CONFORMANCE_SUITE_SIZE).toBe(23);
    expect(ADDED_FIXTURES_REF).toMatch(/^eb06f2c[0-9a-f]{33}$/);
  });

  it(`frozen verdict table has exactly ${CONFORMANCE_SUITE_SIZE} rows, each a complete verdict`, () => {
    const rows = Object.entries(PINNED_VERDICTS);
    expect(rows.length).toBe(CONFORMANCE_SUITE_SIZE);
    for (const [file, row] of rows) {
      expect(file, `table key ${file} must be a vendored .json file name`).toMatch(/^[^/\\]+\.json$/);
      if (row.verifyResult === 'ACCEPT') {
        expect(row.rejectCategory, `ACCEPT row ${file} must carry no rejectCategory`).toBeUndefined();
      } else {
        expect(row.verifyResult, `row ${file} must be ACCEPT or REJECT`).toBe('REJECT');
        expect(row.rejectCategory, `REJECT row ${file} must carry its rejectCategory`).toBeTruthy();
      }
    }
  });

  it('table key set equals the two vendored fixture directory listings', () => {
    const tableKeys = Object.keys(PINNED_VERDICTS).sort();
    // Both directions are reported in ONE assertion so a rename names both the
    // stray file and the orphaned table key.
    const problems = [
      ...fixtureFiles
        .filter((file) => !(file in PINNED_VERDICTS))
        .map((file) => `vendored fixture with no PINNED_VERDICTS row: ${file}`),
      ...tableKeys
        .filter((file) => !fixtureFiles.includes(file))
        .map((file) => `PINNED_VERDICTS row with no vendored fixture file: ${file}`),
    ];
    expect(problems, problems.join('\n')).toEqual([]);
    expect(tableKeys).toEqual(fixtureFiles);
  });

  it('pins fixture 21 (v1_1-untrusted-chain-authority.json) as REJECT SIGNATURE_INVALID', () => {
    expect(PINNED_VERDICTS['v1_1-untrusted-chain-authority.json']).toEqual({
      verifyResult: 'REJECT',
      rejectCategory: 'SIGNATURE_INVALID',
    });
    expect(fixtureFiles).toContain('v1_1-untrusted-chain-authority.json');
  });

  it('ATX_CONFORMANCE_REF equals the ref .github/workflows/ci.yml pins', () => {
    expect(ATX_CONFORMANCE_REF).toMatch(/^[0-9a-f]{40}$/);
    // The short ref named in this file's header, PINNED_SUITE_SIZE doc comment
    // and describe title is this constant's 7-character prefix.
    expect(ATX_CONFORMANCE_REF.slice(0, 7)).toBe('d2b8376');

    const workflow = readFileSync(CI_WORKFLOW_URL, 'utf-8');
    const match = /^\s*ATX_CONFORMANCE_REF:\s*([0-9a-f]{40})\s*$/m.exec(workflow);
    expect(match, 'ci.yml must pin ATX_CONFORMANCE_REF to a full 40-character ref').not.toBeNull();
    expect(match?.[1]).toBe(ATX_CONFORMANCE_REF);
  });

  it('v1_1-hybrid-mldsa-tampered: rejects SIGNATURE_INVALID on the ML-DSA-65 entry, not the Ed25519 one', () => {
    // 0.3.0 and 0.4.0 accepted this credential: they verified its intact
    // Ed25519 signature and only recorded that an ML-DSA-65 one was present.
    expect(PINNED_VERDICTS['v1_1-hybrid-mldsa-tampered.json']).toEqual({
      verifyResult: 'REJECT',
      rejectCategory: 'SIGNATURE_INVALID',
    });
    const { fixture, rawAtx } = loadNamedFixture('v1_1-hybrid-mldsa-tampered.json');
    const result = new LocalAtxVerifier(anchorsFromFixture(fixture)).verifyCredential(rawAtx);
    expect(result.valid).toBe(false);
    expect(result.rejectCategory).toBe('SIGNATURE_INVALID');
    expect(result.reason).toContain('ML-DSA-65');
    expect(result.reason).toContain('did not verify');
    expect(result.mldsaPresent).toBe(true);
  });

  it('v1_1-untrusted-chain-authority: rejects SIGNATURE_INVALID though the signed chain names the signer', () => {
    // 0.3.0 and 0.4.0 accepted this credential: its only signature is by an
    // authority its own signed issuerChain names and trustedIssuers does not.
    const { fixture, rawAtx } = loadNamedFixture('v1_1-untrusted-chain-authority.json');
    const chain = JSON.parse(rawAtx).issuerChain as string[];
    const untrusted = chain.filter((did) => !fixture.verifierState.trustedIssuers.includes(did));
    expect(untrusted.length, 'fixture must name an untrusted chain authority').toBeGreaterThan(0);
    const result = new LocalAtxVerifier(anchorsFromFixture(fixture)).verifyCredential(rawAtx);
    expect(result.valid).toBe(false);
    expect(result.rejectCategory).toBe('SIGNATURE_INVALID');
  });

  it(`produces the pinned verdict on ${CONFORMANCE_SUITE_SIZE} of ${CONFORMANCE_SUITE_SIZE} fixtures`, () => {
    const misses: string[] = [];
    for (const { file, dir } of fixtureSources) {
      const { fixture, rawAtx } = loadFixture(file, dir);
      const result = new LocalAtxVerifier(anchorsFromFixture(fixture)).verifyCredential(rawAtx);
      if (!matchesPinned(PINNED_VERDICTS[file], result)) {
        misses.push(`${file}: pinned ${describeVerdict(PINNED_VERDICTS[file])}, got ` +
          `${result.valid ? 'ACCEPT' : `REJECT (${result.rejectCategory}): ${result.reason}`}`);
      }
    }
    expect(misses, misses.join('\n')).toEqual([]);
    expect(fixtureSources.length - misses.length).toBe(23);
  });

  for (const { file, dir } of fixtureSources) {
    const { fixture: f, rawAtx } = loadFixture(file, dir);

    it(`${f.name} -> ${describeVerdict(f.expected)}`, () => {
      // The fixture's own `expected` member must agree with the frozen table
      // BEFORE the verifier result is compared: an edited fixture fails here,
      // naming the file, whether or not the verifier happens to agree with it.
      const pinned: PinnedVerdict | undefined = PINNED_VERDICTS[file];
      if (pinned === undefined) {
        throw new Error(`fixture ${file} has no row in PINNED_VERDICTS (renamed or added?)`);
      }
      expect(
        f.expected.verifyResult,
        `${file}: fixture expected.verifyResult disagrees with PINNED_VERDICTS`,
      ).toBe(pinned.verifyResult);
      expect(
        f.expected.rejectCategory,
        `${file}: fixture expected.rejectCategory disagrees with PINNED_VERDICTS`,
      ).toBe(pinned.rejectCategory);

      // The verifier is compared against the TABLE's row (not the fixture's).
      const result = new LocalAtxVerifier(anchorsFromFixture(f)).verifyCredential(rawAtx);
      if (pinned.verifyResult === 'ACCEPT') {
        expect(result.valid, `${file}: expected ACCEPT, got: ${result.reason}`).toBe(true);
      } else {
        expect(result.valid, `${file}: expected REJECT but verifier accepted`).toBe(false);
        expect(result.rejectCategory).toBe(expectedCategory(pinned.rejectCategory));
        // For the strict-parse fixtures, pin that the rejection is BECAUSE of
        // the duplicate member — not an incidental MALFORMED — so the gate
        // stays structurally non-vacuous.
        if (pinned.rejectCategory === 'PARSE_ERROR') {
          expect(result.reason).toContain('duplicate');
        }
      }
    });
  }
});

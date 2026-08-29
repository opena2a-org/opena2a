/**
 * `issuerChain` is declared `string[]` on both `Atx` and `ResolutionContext`, but
 * the wire value used to reach the consumer unvalidated. Two measured consequences,
 * which is why this is a structural rejection and not a cast:
 *
 *  - A STRING chain silently changes what a consumer predicate means.
 *    `["did:opena2a:authority:a.example"].includes("a.example")` is `false` —
 *    array-element equality. `"did:opena2a:authority:a.example".includes("a.example")`
 *    is `true` — substring matching. A federation predicate written against the
 *    declared type flips its verdict because the holder sent a string.
 *  - A non-iterable chain (`{}`, `5`, `true`) made `verifyCredential` throw a
 *    `TypeError` on v1.1, against its own docstring: "this method never throws on
 *    bad input". On v1.0 it did not throw here — it verified and handed the number
 *    or boolean straight to the caller, so the throw landed in the consumer instead.
 *
 * The guard covers BOTH credential versions. v1.0 never iterates the chain, so it
 * was the version that accepted every shape silently.
 */
import { describe, it, expect } from 'vitest';
import * as crypto from 'node:crypto';
import {
  LocalAtxVerifier,
  canonicalPayload,
  canonicalPayloadV11,
  type Atx,
  type AtxTrustAnchors,
} from './atx.js';

const ISSUER = 'did:opena2a:authority:a.example';
const CLOCK = new Date('2026-06-01T00:00:00Z');

function keypair(): { privateKey: crypto.KeyObject; pubHex: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  return { privateKey, pubHex: Buffer.from(jwk.x, 'base64url').toString('hex') };
}

const key = keypair();

function anchors(): AtxTrustAnchors {
  return {
    trustedIssuers: [ISSUER],
    publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: key.pubHex, keyId: `${ISSUER}#key-1` }],
    crl: { entries: [] },
    now: () => CLOCK,
  };
}

/** Signs whatever it is given, so the chain shape under test is genuinely signed. */
function signed(atcVersion: '1.0' | '1.1', issuerChain: unknown): string {
  const atx = {
    atcVersion,
    agentId: 'agent-1',
    agentDid: 'did:opena2a:agent:a/agent-1',
    version: '1.0.0',
    contentHash: 'sha256:abc',
    issuerDid: ISSUER,
    issuerChain,
    trustLevel: 2,
    trustScore: 0.9,
    issuedAt: '2026-01-01T00:00:00Z',
    expiresAt: '2027-01-01T00:00:00Z',
    capabilities: ['orders:read'],
    signatures: [],
  } as unknown as Atx;
  const payload = atcVersion === '1.1' ? canonicalPayloadV11(atx) : canonicalPayload(atx);
  return JSON.stringify({
    ...atx,
    signatures: [
      {
        keyId: `${ISSUER}#key-1`,
        algorithm: 'Ed25519',
        value: crypto.sign(null, payload, key.privateKey).toString('base64'),
      },
    ],
  });
}

const NON_ARRAYS: Array<[string, unknown]> = [
  ['a string', ISSUER],
  ['an object', {}],
  ['a number', 5],
  ['a boolean', true],
];

describe('issuerChain must be an array of strings', () => {
  for (const version of ['1.0', '1.1'] as const) {
    describe(`v${version}`, () => {
      for (const [label, value] of NON_ARRAYS) {
        it(`rejects ${label} as MALFORMED rather than passing it to the caller`, () => {
          const result = new LocalAtxVerifier(anchors()).verifyCredential(signed(version, value));
          expect(result.valid).toBe(false);
          expect(result.rejectCategory).toBe('MALFORMED');
          expect(result.reason).toMatch(/issuerChain/);
        });
      }

      // One case per member SHAPE. A mutation pass showed that testing only `7` left
      // `null` and a nested array unpinned: a guard written as
      // `typeof did !== 'string' && did !== null` survived the suite unchanged.
      for (const [memberLabel, member] of [
        ['a number', 7],
        ['null', null],
        ['a nested array', ['did:opena2a:authority:nested']],
        ['an object', {}],
        ['undefined', undefined],
      ] as Array<[string, unknown]>) {
        it(`rejects an array holding ${memberLabel}`, () => {
          const result = new LocalAtxVerifier(anchors()).verifyCredential(
            signed(version, [ISSUER, member]),
          );
          expect(result.valid).toBe(false);
          expect(result.rejectCategory).toBe('MALFORMED');
          expect(result.reason).toMatch(/issuerChain/);
        });
      }

      // The reported index must be the OFFENDING one. Hard-coding `[0]` passed every
      // test above, so the index was decorative rather than diagnostic.
      it('names the offending index, not the first', () => {
        const result = new LocalAtxVerifier(anchors()).verifyCredential(
          signed(version, [ISSUER, ISSUER, 7]),
        );
        expect(result.reason).toMatch(/issuerChain\[2\]/);
      });

      // Absence direction: the guard must not turn a legitimate credential away.
      it('accepts a well-formed chain', () => {
        const result = new LocalAtxVerifier(anchors()).verifyCredential(signed(version, [ISSUER]));
        expect(result.valid).toBe(true);
        expect(Array.isArray(result.context?.issuerChain)).toBe(true);
      });

      // An absent chain is accepted — and the caller is handed a chain the issuer did
      // NOT sign. The signed payload defaults to `[]`; the context defaults to
      // `[issuerDid]`. This test pins the CURRENT behaviour and names the divergence
      // so it cannot be mistaken for a verified value. Changing the default is a
      // behaviour change tracked separately, not something a type guard should do
      // quietly.
      it('accepts an absent chain, and synthesises a context chain that was never signed', () => {
        const result = new LocalAtxVerifier(anchors()).verifyCredential(
          signed(version, undefined),
        );
        expect(result.valid).toBe(true);
        expect(result.context?.issuerChain).toEqual([ISSUER]); // synthesised
        // Control: an explicitly empty chain IS what the signature covered, and it
        // arrives unchanged — so the line above is a substitution, not a formatting
        // detail.
        const explicit = new LocalAtxVerifier(anchors()).verifyCredential(signed(version, []));
        expect(explicit.context?.issuerChain).toEqual([]);
      });

      it('accepts an empty chain', () => {
        const result = new LocalAtxVerifier(anchors()).verifyCredential(signed(version, []));
        expect(result.valid).toBe(true);
      });
    });
  }

  // The documented contract, stated at the top of verifyCredential: it never throws
  // on bad input. Before the guard these three threw TypeError on v1.1.
  it('never throws on any of the non-array shapes, on either version', () => {
    for (const version of ['1.0', '1.1'] as const) {
      for (const [, value] of NON_ARRAYS) {
        expect(() =>
          new LocalAtxVerifier(anchors()).verifyCredential(signed(version, value)),
        ).not.toThrow();
      }
    }
  });

  // Ordering is deliberate, not incidental. The guard sits ahead of expiry, revocation
  // and issuer trust, so a credential that is BOTH malformed and expired reports the
  // structural defect. Placed later the verdict is identical, but the audit record would
  // report a comparison against a field the verifier could not read. Same reasoning the
  // signedCapabilities ordering was pinned with rather than left to chance.
  it('reports the structural defect ahead of expiry and issuer trust', () => {
    const expiredAndMalformed = JSON.parse(signed('1.1', [ISSUER])) as Record<string, unknown>;
    expiredAndMalformed.issuerChain = ISSUER; // not an array
    expiredAndMalformed.expiresAt = '2020-01-01T00:00:00Z'; // long expired
    const result = new LocalAtxVerifier(anchors()).verifyCredential(
      JSON.stringify(expiredAndMalformed),
    );
    expect(result.valid).toBe(false);
    expect(result.rejectCategory).toBe('MALFORMED');

    // Control: the SAME credential with a well-formed chain reports EXPIRED, which
    // proves this test distinguishes the ordering rather than just any rejection.
    const expiredOnly = JSON.parse(signed('1.1', [ISSUER])) as Record<string, unknown>;
    expiredOnly.expiresAt = '2020-01-01T00:00:00Z';
    const control = new LocalAtxVerifier(anchors()).verifyCredential(JSON.stringify(expiredOnly));
    expect(control.rejectCategory).toBe('EXPIRED');
  });

  // The guard must validate and deliver the SAME value. `verify(obj)` takes a
  // caller-supplied object, so a property whose getter returns something different on a
  // later read would otherwise let a validated array and a delivered non-array diverge.
  // Not reachable through verifyCredential — JSON.parse cannot produce an accessor — but
  // verify(obj) is a public entry point and this is what makes the guard atomic rather
  // than advisory. v1.0 is used because its signature does not cover issuerChain, so the
  // flipping getter cannot invalidate the signature and confound the arm.
  it('validates and delivers the same chain even when the property flips between reads', () => {
    const honest = JSON.parse(signed('1.0', [ISSUER])) as Record<string, unknown>;

    for (let flipAfter = 1; flipAfter <= 8; flipAfter++) {
      let reads = 0;
      const hostile = { ...honest };
      Object.defineProperty(hostile, 'issuerChain', {
        enumerable: true,
        get() {
          reads += 1;
          return reads > flipAfter ? 'did:evil:attacker' : [ISSUER];
        },
      });

      const result = new LocalAtxVerifier(anchors()).verify(hostile as unknown as Atx);
      if (result.valid) {
        // Whatever it accepted, the caller must never receive the unvalidated shape.
        expect(Array.isArray(result.context?.issuerChain)).toBe(true);
        expect(result.context?.issuerChain).toEqual([ISSUER]);
      } else {
        expect(result.rejectCategory).toBe('MALFORMED');
      }
    }

    // Control: a getter that never flips behaves exactly like a plain array, so the
    // loop above is testing the flip and not merely the presence of an accessor.
    const stable = { ...honest };
    Object.defineProperty(stable, 'issuerChain', {
      enumerable: true,
      get: () => [ISSUER],
    });
    const control = new LocalAtxVerifier(anchors()).verify(stable as unknown as Atx);
    expect(control.valid).toBe(true);
    expect(control.context?.issuerChain).toEqual([ISSUER]);
  });

  // The consumer-visible reason this is a rejection and not a coercion.
  it('a string chain would have changed what a membership predicate means', () => {
    expect([ISSUER].includes('a.example')).toBe(false);
    expect(ISSUER.includes('a.example')).toBe(true);
  });
});

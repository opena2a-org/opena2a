/**
 * Key↔issuer binding: a configured key whose keyId names a controller DID may
 * only verify signatures for credentials issued by that controller (or, for
 * v1.1, a signed issuerChain authority). One trusted issuer cannot impersonate
 * another. Keys without a DID-URL keyId stay unbound (back-compat).
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

const ISSUER_A = 'did:opena2a:authority:a.example';
const ISSUER_B = 'did:opena2a:authority:b.example';
const CLOCK = new Date('2026-05-25T00:00:00Z');

function keypair(): { privateKey: crypto.KeyObject; pubHex: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  return { privateKey, pubHex: Buffer.from(jwk.x, 'base64url').toString('hex') };
}

function atxBase(overrides: Partial<Atx> = {}): Atx {
  return {
    atcVersion: '1.0',
    agentId: 'agent-1',
    agentDid: 'did:opena2a:agent:a/agent-1',
    version: '1.0.0',
    contentHash: 'sha256:abc',
    issuerDid: ISSUER_A,
    issuerChain: [ISSUER_A],
    trustLevel: 2,
    trustScore: 0.9,
    issuedAt: '2026-05-20T00:00:00Z',
    expiresAt: '2026-06-20T00:00:00Z',
    capabilities: ['orders:read'],
    signatures: [],
    ...overrides,
  };
}

function signWith(atx: Atx, key: crypto.KeyObject, keyId: string): Atx {
  const payload = atx.atcVersion === '1.1' ? canonicalPayloadV11(atx) : canonicalPayload(atx);
  return {
    ...atx,
    signatures: [{ keyId, algorithm: 'Ed25519', value: crypto.sign(null, payload, key).toString('base64') }],
  };
}

function anchors(extra: Partial<AtxTrustAnchors>): AtxTrustAnchors {
  return {
    trustedIssuers: [ISSUER_A, ISSUER_B],
    publicKeys: [],
    crl: { entries: [] },
    now: () => CLOCK,
    ...extra,
  };
}

describe('key-to-issuer binding', () => {
  it('rejects a credential issued by A but signed by trusted issuer B (v1.0)', () => {
    const a = keypair();
    const b = keypair();
    const atx = signWith(atxBase({ issuerDid: ISSUER_A }), b.privateKey, `${ISSUER_B}#key-1`);
    const result = new LocalAtxVerifier(
      anchors({
        publicKeys: [
          { algorithm: 'Ed25519', publicKeyHex: a.pubHex, keyId: `${ISSUER_A}#key-1` },
          { algorithm: 'Ed25519', publicKeyHex: b.pubHex, keyId: `${ISSUER_B}#key-1` },
        ],
      }),
    ).verify(atx);
    expect(result.valid).toBe(false);
    expect(result.rejectCategory).toBe('SIGNATURE_INVALID');
  });

  it('rejects the same cross-issuer case under v1.1 (B not in signed issuerChain)', () => {
    const a = keypair();
    const b = keypair();
    const atx = signWith(
      atxBase({ atcVersion: '1.1', issuerDid: ISSUER_A, issuerChain: [ISSUER_A] }),
      b.privateKey,
      `${ISSUER_B}#key-1`,
    );
    const result = new LocalAtxVerifier(
      anchors({
        publicKeys: [
          { algorithm: 'Ed25519', publicKeyHex: a.pubHex, keyId: `${ISSUER_A}#key-1` },
          { algorithm: 'Ed25519', publicKeyHex: b.pubHex, keyId: `${ISSUER_B}#key-1` },
        ],
      }),
    ).verify(atx);
    expect(result.valid).toBe(false);
    expect(result.rejectCategory).toBe('SIGNATURE_INVALID');
  });

  it('accepts a v1.1 cross-org cosignature when the signer is in the signed issuerChain', () => {
    const b = keypair();
    // issuer is A, but B is a cosigning authority named in the (signed) issuerChain.
    const atx = signWith(
      atxBase({ atcVersion: '1.1', issuerDid: ISSUER_A, issuerChain: [ISSUER_A, ISSUER_B] }),
      b.privateKey,
      `${ISSUER_B}#key-1`,
    );
    const result = new LocalAtxVerifier(
      anchors({
        publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: b.pubHex, keyId: `${ISSUER_B}#key-1` }],
      }),
    ).verify(atx);
    expect(result.valid).toBe(true);
  });

  it('treats a key with no DID-URL keyId as unbound (back-compat)', () => {
    const a = keypair();
    const atx = signWith(atxBase({ issuerDid: ISSUER_A }), a.privateKey, 'legacy-key');
    const result = new LocalAtxVerifier(
      anchors({
        // keyId without '#': unbound, eligible for any issuer.
        publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: a.pubHex, keyId: 'legacy-key' }],
      }),
    ).verify(atx);
    expect(result.valid).toBe(true);
  });
});

describe('anchor-fault diagnostics (empty eligible key set names the configuration fault)', () => {
  it('no Ed25519 anchors configured', () => {
    const { privateKey } = keypair();
    const atx = signWith(atxBase(), privateKey, `${ISSUER_A}#key-1`);
    const result = new LocalAtxVerifier(anchors({ publicKeys: [] })).verify(atx);
    expect(result.valid).toBe(false);
    expect(result.rejectCategory).toBe('SIGNATURE_INVALID');
    expect(result.reason).toContain('no Ed25519 trust anchors configured');
  });

  it('all configured keys excluded by key-to-issuer binding', () => {
    const a = keypair();
    // Key bound to ISSUER_B; credential issued by ISSUER_A. The crypto WOULD
    // verify (same key signed it) — the reason must say binding, not bad bytes.
    const atx = signWith(atxBase({ issuerDid: ISSUER_A, issuerChain: [ISSUER_A] }), a.privateKey, `${ISSUER_B}#key-1`);
    const result = new LocalAtxVerifier(
      anchors({ publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: a.pubHex, keyId: `${ISSUER_B}#key-1` }] }),
    ).verify(atx);
    expect(result.valid).toBe(false);
    expect(result.rejectCategory).toBe('SIGNATURE_INVALID');
    expect(result.reason).toContain('key-to-issuer binding');
    expect(result.reason).toContain(ISSUER_A);
  });

  it('eligible key material fails to parse (bad hex)', () => {
    const { privateKey } = keypair();
    const atx = signWith(atxBase(), privateKey, `${ISSUER_A}#key-1`);
    const result = new LocalAtxVerifier(
      anchors({ publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: 'zz-not-hex', keyId: `${ISSUER_A}#key-1` }] }),
    ).verify(atx);
    expect(result.valid).toBe(false);
    expect(result.rejectCategory).toBe('SIGNATURE_INVALID');
    expect(result.reason).toContain('failed to parse');
  });

  it('a genuine bad-signature rejection has no dangling space when keyId is absent', () => {
    const a = keypair();
    const atx = signWith(atxBase(), a.privateKey, `${ISSUER_A}#key-1`);
    // Wrong-key anchor (unbound, so eligible): reaches the did-not-verify path.
    const other = keypair();
    const unsigned: Atx = { ...atx, signatures: [{ algorithm: 'Ed25519', value: atx.signatures[0].value }] };
    const result = new LocalAtxVerifier(
      anchors({ publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: other.pubHex }] }),
    ).verify(unsigned);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Ed25519 signature did not verify');
    expect(result.reason).not.toContain('  ');
  });
});

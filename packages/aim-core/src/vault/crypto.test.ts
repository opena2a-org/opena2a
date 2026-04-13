import { describe, it, expect } from 'vitest';
import * as nacl from 'tweetnacl';
import {
  ed25519PublicKeyToX25519,
  ed25519SecretKeyToX25519,
  deriveVaultKey,
  generateEphemeralKeypair,
  encrypt,
  decrypt,
  zeroize,
} from './crypto';

describe('vault/crypto', () => {
  // ── Ed25519→X25519 conversion ──────────────────────────────────

  describe('ed25519PublicKeyToX25519', () => {
    it('rejects keys that are not 32 bytes', () => {
      expect(() => ed25519PublicKeyToX25519(new Uint8Array(16))).toThrow('32 bytes');
      expect(() => ed25519PublicKeyToX25519(new Uint8Array(64))).toThrow('32 bytes');
    });

    it('converts consistently — same input always produces same output', () => {
      const kp = nacl.sign.keyPair();
      const x1 = ed25519PublicKeyToX25519(kp.publicKey);
      const x2 = ed25519PublicKeyToX25519(kp.publicKey);
      expect(Buffer.from(x1).toString('hex')).toBe(Buffer.from(x2).toString('hex'));
    });

    it('produces 32-byte output', () => {
      const kp = nacl.sign.keyPair();
      const x = ed25519PublicKeyToX25519(kp.publicKey);
      expect(x.length).toBe(32);
    });

    it('different Ed25519 keys produce different X25519 keys', () => {
      const kp1 = nacl.sign.keyPair();
      const kp2 = nacl.sign.keyPair();
      const x1 = ed25519PublicKeyToX25519(kp1.publicKey);
      const x2 = ed25519PublicKeyToX25519(kp2.publicKey);
      expect(Buffer.from(x1).toString('hex')).not.toBe(Buffer.from(x2).toString('hex'));
    });

    // Cross-verify: converting Ed25519 public key must produce the same X25519
    // public key as deriving from the converted secret key via scalar multiplication.
    // This validates both conversion functions against each other and against nacl.
    it('public key conversion matches scalar base multiplication of converted secret key', () => {
      for (let i = 0; i < 5; i++) {
        const edKp = nacl.sign.keyPair();
        const x25519Pub = ed25519PublicKeyToX25519(edKp.publicKey);
        const x25519Sec = ed25519SecretKeyToX25519(edKp.secretKey);
        // nacl.scalarMult.base computes the canonical X25519 public key from a secret key
        const expectedPub = nacl.scalarMult.base(x25519Sec);
        expect(Buffer.from(x25519Pub).toString('hex')).toBe(
          Buffer.from(expectedPub).toString('hex')
        );
      }
    });
  });

  describe('ed25519SecretKeyToX25519', () => {
    it('rejects keys that are not 64 bytes', () => {
      expect(() => ed25519SecretKeyToX25519(new Uint8Array(32))).toThrow('64 bytes');
    });

    it('produces 32-byte output', () => {
      const kp = nacl.sign.keyPair();
      const x = ed25519SecretKeyToX25519(kp.secretKey);
      expect(x.length).toBe(32);
    });

    it('clamped correctly — low 3 bits cleared, bit 254 set, bit 255 cleared', () => {
      const kp = nacl.sign.keyPair();
      const x = ed25519SecretKeyToX25519(kp.secretKey);
      // Low 3 bits of byte 0 must be 0
      expect(x[0] & 7).toBe(0);
      // Byte 31: bit 6 set (64), bit 7 cleared (128)
      expect(x[31] & 64).toBe(64);
      expect(x[31] & 128).toBe(0);
    });
  });

  // ── ECDH key agreement ─────────────────────────────────────────

  describe('deriveVaultKey + ECDH agreement', () => {
    it('agent and ephemeral keypair produce the same shared secret', () => {
      const agentKp = nacl.sign.keyPair();
      const ephemeralKp = generateEphemeralKeypair();

      // Agent derives key using ephemeral public key
      const agentVaultKey = deriveVaultKey(agentKp.secretKey, ephemeralKp.publicKey);

      // Simulate reverse: ephemeral derives using agent's X25519 public key
      const agentX25519Pub = ed25519PublicKeyToX25519(agentKp.publicKey);
      const reverseKey = nacl.box.before(agentX25519Pub, ephemeralKp.secretKey);

      expect(Buffer.from(agentVaultKey).toString('hex')).toBe(
        Buffer.from(reverseKey).toString('hex')
      );
    });

    it('different agent keys produce different vault keys', () => {
      const agent1 = nacl.sign.keyPair();
      const agent2 = nacl.sign.keyPair();
      const ephKp = generateEphemeralKeypair();

      const key1 = deriveVaultKey(agent1.secretKey, ephKp.publicKey);
      const key2 = deriveVaultKey(agent2.secretKey, ephKp.publicKey);

      expect(Buffer.from(key1).toString('hex')).not.toBe(
        Buffer.from(key2).toString('hex')
      );
    });
  });

  // ── Encrypt / Decrypt ──────────────────────────────────────────

  describe('encrypt + decrypt', () => {
    const key = nacl.randomBytes(32);

    it('round-trips arbitrary data', () => {
      const plaintext = new TextEncoder().encode('github_pat_abc123_credential');
      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, nonce, key);
      expect(Buffer.from(decrypted).toString()).toBe('github_pat_abc123_credential');
    });

    it('round-trips empty data', () => {
      const plaintext = new Uint8Array(0);
      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, nonce, key);
      expect(decrypted.length).toBe(0);
    });

    it('round-trips binary data', () => {
      const plaintext = nacl.randomBytes(256);
      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, nonce, key);
      expect(Buffer.from(decrypted).toString('hex')).toBe(
        Buffer.from(plaintext).toString('hex')
      );
    });

    it('each encryption produces a different nonce (unique ciphertext)', () => {
      const plaintext = new TextEncoder().encode('same data');
      const e1 = encrypt(plaintext, key);
      const e2 = encrypt(plaintext, key);
      expect(Buffer.from(e1.nonce).toString('hex')).not.toBe(
        Buffer.from(e2.nonce).toString('hex')
      );
    });

    it('rejects key that is not 32 bytes', () => {
      expect(() => encrypt(new Uint8Array(0), new Uint8Array(16))).toThrow('32 bytes');
    });

    it('rejects nonce that is not 24 bytes', () => {
      expect(() => decrypt(new Uint8Array(16), new Uint8Array(12), key)).toThrow('24 bytes');
    });
  });

  describe('decrypt — fail closed (CR-006)', () => {
    const key = nacl.randomBytes(32);

    it('wrong key throws', () => {
      const plaintext = new TextEncoder().encode('secret');
      const { ciphertext, nonce } = encrypt(plaintext, key);
      const wrongKey = nacl.randomBytes(32);
      expect(() => decrypt(ciphertext, nonce, wrongKey)).toThrow('authentication tag mismatch');
    });

    it('tampered ciphertext throws', () => {
      const plaintext = new TextEncoder().encode('secret');
      const { ciphertext, nonce } = encrypt(plaintext, key);
      // Flip a bit in the ciphertext
      const tampered = new Uint8Array(ciphertext);
      tampered[0] ^= 0x01;
      expect(() => decrypt(tampered, nonce, key)).toThrow('authentication tag mismatch');
    });

    it('tampered nonce throws', () => {
      const plaintext = new TextEncoder().encode('secret');
      const { ciphertext, nonce } = encrypt(plaintext, key);
      const tamperedNonce = new Uint8Array(nonce);
      tamperedNonce[0] ^= 0x01;
      expect(() => decrypt(ciphertext, tamperedNonce, key)).toThrow('authentication tag mismatch');
    });

    it('truncated ciphertext throws', () => {
      const plaintext = new TextEncoder().encode('secret');
      const { ciphertext, nonce } = encrypt(plaintext, key);
      const truncated = ciphertext.subarray(0, ciphertext.length - 1);
      expect(() => decrypt(truncated, nonce, key)).toThrow('authentication tag mismatch');
    });
  });

  // ── Zeroize ────────────────────────────────────────────────────

  describe('zeroize', () => {
    it('fills buffer with zeros', () => {
      const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      zeroize(secret);
      expect(secret.every((b) => b === 0)).toBe(true);
    });

    it('works on already-zero buffer', () => {
      const buf = new Uint8Array(32);
      zeroize(buf);
      expect(buf.every((b) => b === 0)).toBe(true);
    });

    it('works on large buffer', () => {
      const buf = nacl.randomBytes(4096);
      zeroize(buf);
      expect(buf.every((b) => b === 0)).toBe(true);
    });
  });

  // ── Full vault key derivation round-trip ───────────────────────

  describe('full vault round-trip', () => {
    it('agent encrypts credential, stores, and decrypts with derived key', () => {
      // Simulate vault init: agent identity + ephemeral keypair
      const agentKp = nacl.sign.keyPair();
      const ephKp = generateEphemeralKeypair();

      // Derive vault key
      const vaultKey = deriveVaultKey(agentKp.secretKey, ephKp.publicKey);

      // Store a credential
      const credential = new TextEncoder().encode('ghp_abc123def456');
      const { ciphertext, nonce } = encrypt(credential, vaultKey);

      // Later: re-derive vault key from stored ephemeral public key
      const vaultKey2 = deriveVaultKey(agentKp.secretKey, ephKp.publicKey);
      const decrypted = decrypt(ciphertext, nonce, vaultKey2);

      expect(Buffer.from(decrypted).toString()).toBe('ghp_abc123def456');

      // Clean up
      zeroize(vaultKey);
      zeroize(vaultKey2);
      zeroize(decrypted);
    });

    it('different agent cannot decrypt', () => {
      const agentKp = nacl.sign.keyPair();
      const attackerKp = nacl.sign.keyPair();
      const ephKp = generateEphemeralKeypair();

      const vaultKey = deriveVaultKey(agentKp.secretKey, ephKp.publicKey);
      const { ciphertext, nonce } = encrypt(
        new TextEncoder().encode('secret'),
        vaultKey
      );

      // Attacker tries with their key
      const attackerKey = deriveVaultKey(attackerKp.secretKey, ephKp.publicKey);
      expect(() => decrypt(ciphertext, nonce, attackerKey)).toThrow(
        'authentication tag mismatch'
      );

      zeroize(vaultKey);
      zeroize(attackerKey);
    });
  });
});

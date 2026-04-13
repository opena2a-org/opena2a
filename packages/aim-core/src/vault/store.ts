/**
 * VaultStore — encrypted credential storage.
 *
 * Manages ~/.aim/vault/ on disk. Each credential is independently encrypted
 * per-namespace using XSalsa20-Poly1305 with a key derived from the agent's
 * Ed25519 identity via X25519 ECDH.
 *
 * CR-001: credential never in agent context
 * CR-005: zero plaintext on disk
 * CR-006: fail closed
 */

import * as fs from 'fs';
import * as path from 'path';
import type { VaultFile, EncryptedBlob } from './types';
import {
  deriveVaultKey,
  generateEphemeralKeypair,
  encrypt,
  decrypt,
  zeroize,
} from './crypto';

const VAULT_FILE = 'vault.enc';

export class VaultStore {
  private readonly vaultDir: string;
  private readonly vaultPath: string;
  private vaultKey: Uint8Array | null = null;

  constructor(vaultDir: string) {
    this.vaultDir = vaultDir;
    this.vaultPath = path.join(vaultDir, VAULT_FILE);
  }

  /**
   * Initialize a new vault for the given agent identity.
   * Creates the vault directory and an empty encrypted vault file.
   *
   * @param agentId - The agent's unique identifier
   * @param edSecretKey - The agent's Ed25519 secret key (64 bytes)
   */
  init(agentId: string, edSecretKey: Uint8Array): void {
    if (this.exists()) {
      throw new Error('Vault already initialized at ' + this.vaultDir);
    }

    // Generate ephemeral X25519 keypair for vault key derivation
    const ephKp = generateEphemeralKeypair();

    // Derive vault key via ECDH
    this.vaultKey = deriveVaultKey(edSecretKey, ephKp.publicKey);

    // Zeroize ephemeral secret key — only the public key is stored
    zeroize(ephKp.secretKey);

    const vaultFile: VaultFile = {
      formatVersion: 1,
      agentId,
      ephemeralPublicKey: Buffer.from(ephKp.publicKey).toString('base64'),
      credentials: {},
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    fs.mkdirSync(this.vaultDir, { recursive: true });
    this.atomicWrite(vaultFile);

    // Set restrictive permissions
    try {
      fs.chmodSync(this.vaultPath, 0o600);
      fs.chmodSync(this.vaultDir, 0o700);
    } catch {
      // Windows doesn't support chmod
    }
  }

  /** Check if the vault file exists */
  exists(): boolean {
    return fs.existsSync(this.vaultPath);
  }

  /**
   * Unlock the vault by deriving the vault key from the agent's Ed25519 secret key.
   * Must be called before any read/write operations on an existing vault.
   */
  unlock(edSecretKey: Uint8Array): void {
    const vaultFile = this.readVaultFile();
    const ephPub = Buffer.from(vaultFile.ephemeralPublicKey, 'base64');
    this.vaultKey = deriveVaultKey(edSecretKey, new Uint8Array(ephPub));
  }

  /**
   * Store a credential in the vault under a namespace.
   * The credential is encrypted independently with the vault key.
   *
   * @param namespace - Namespace identifier
   * @param credential - Raw credential bytes (will be encrypted, then zeroized)
   */
  storeCredential(namespace: string, credential: Uint8Array): void {
    this.ensureUnlocked();

    const { ciphertext, nonce } = encrypt(credential, this.vaultKey!);

    const vaultFile = this.readVaultFile();
    const existingVersion = vaultFile.credentials[namespace]?.version ?? 0;

    vaultFile.credentials[namespace] = {
      ciphertext: Buffer.from(ciphertext).toString('base64'),
      nonce: Buffer.from(nonce).toString('base64'),
      algorithm: 'xsalsa20-poly1305',
      version: existingVersion + 1,
      encryptedAt: new Date().toISOString(),
    };
    vaultFile.updatedAt = new Date().toISOString();

    this.atomicWrite(vaultFile);
  }

  /**
   * Resolve (decrypt) a credential from the vault.
   *
   * CR-006: Throws on failure — never returns partial data or falls back.
   *
   * @returns Decrypted credential bytes. Caller MUST zeroize after use.
   */
  resolveCredential(namespace: string): Uint8Array {
    this.ensureUnlocked();

    const vaultFile = this.readVaultFile();
    const blob = vaultFile.credentials[namespace];
    if (!blob) {
      throw new Error(`No credential found for namespace "${namespace}"`);
    }

    return this.decryptBlob(blob);
  }

  /**
   * List all credential namespaces in the vault.
   * Returns metadata only — no credential values.
   */
  listCredentials(): Array<{ namespace: string; version: number; encryptedAt: string }> {
    const vaultFile = this.readVaultFile();
    return Object.entries(vaultFile.credentials).map(([ns, blob]) => ({
      namespace: ns,
      version: blob.version,
      encryptedAt: blob.encryptedAt,
    }));
  }

  /**
   * Delete a credential from the vault.
   *
   * @returns true if the credential existed and was deleted
   */
  deleteCredential(namespace: string): boolean {
    const vaultFile = this.readVaultFile();
    if (!(namespace in vaultFile.credentials)) {
      return false;
    }

    delete vaultFile.credentials[namespace];
    vaultFile.updatedAt = new Date().toISOString();
    this.atomicWrite(vaultFile);
    return true;
  }

  /**
   * Rotate a credential — store new value, increment version.
   *
   * @param namespace - Namespace to rotate
   * @param newCredential - New credential bytes (will be encrypted, then zeroized)
   */
  rotateCredential(namespace: string, newCredential: Uint8Array): void {
    this.ensureUnlocked();

    const vaultFile = this.readVaultFile();
    const existing = vaultFile.credentials[namespace];
    if (!existing) {
      throw new Error(`Cannot rotate: no credential found for namespace "${namespace}"`);
    }

    const { ciphertext, nonce } = encrypt(newCredential, this.vaultKey!);

    vaultFile.credentials[namespace] = {
      ciphertext: Buffer.from(ciphertext).toString('base64'),
      nonce: Buffer.from(nonce).toString('base64'),
      algorithm: 'xsalsa20-poly1305',
      version: existing.version + 1,
      encryptedAt: new Date().toISOString(),
    };
    vaultFile.updatedAt = new Date().toISOString();

    this.atomicWrite(vaultFile);
  }

  /** Get the agent ID from the vault file */
  getAgentId(): string {
    return this.readVaultFile().agentId;
  }

  /**
   * Destroy the vault — zeroize in-memory key, delete vault file.
   * This is irreversible.
   */
  destroy(): void {
    if (this.vaultKey) {
      zeroize(this.vaultKey);
      this.vaultKey = null;
    }
    if (fs.existsSync(this.vaultPath)) {
      fs.unlinkSync(this.vaultPath);
    }
  }

  /** Lock the vault — zeroize the in-memory key */
  lock(): void {
    if (this.vaultKey) {
      zeroize(this.vaultKey);
      this.vaultKey = null;
    }
  }

  // ── Private helpers ─────────────────────────────────────────────

  private ensureUnlocked(): void {
    if (!this.vaultKey) {
      throw new Error('Vault is locked. Call unlock() or init() first.');
    }
  }

  private readVaultFile(): VaultFile {
    if (!fs.existsSync(this.vaultPath)) {
      throw new Error('Vault not found at ' + this.vaultPath);
    }
    const raw = fs.readFileSync(this.vaultPath, 'utf-8');
    return JSON.parse(raw) as VaultFile;
  }

  private decryptBlob(blob: EncryptedBlob): Uint8Array {
    const ciphertext = new Uint8Array(Buffer.from(blob.ciphertext, 'base64'));
    const nonce = new Uint8Array(Buffer.from(blob.nonce, 'base64'));
    return decrypt(ciphertext, nonce, this.vaultKey!);
  }

  /** Atomic write: write to tmp file, then rename */
  private atomicWrite(vaultFile: VaultFile): void {
    const tmpPath = this.vaultPath + '.tmp.' + process.pid;
    fs.writeFileSync(tmpPath, JSON.stringify(vaultFile, null, 2), 'utf-8');
    try {
      fs.chmodSync(tmpPath, 0o600);
    } catch {
      // Windows
    }
    fs.renameSync(tmpPath, this.vaultPath);
  }
}

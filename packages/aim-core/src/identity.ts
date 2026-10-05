import * as nacl from 'tweetnacl';
import * as fs from 'fs';
import * as path from 'path';
import type { AIMIdentity, StoredIdentity } from './types';

const IDENTITY_FILE = 'identity.json';

/** Derive a short agent ID from an Ed25519 public key */
function deriveAgentId(publicKey: Uint8Array): string {
  // Use first 12 bytes of public key, base64url-encoded, prefixed with "aim_"
  const idBytes = publicKey.slice(0, 12);
  const b64 = Buffer.from(idBytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `aim_${b64}`;
}

/** Generate a new Ed25519 keypair and store it */
export function createIdentity(dataDir: string, agentName: string): StoredIdentity {
  const keypair = nacl.sign.keyPair();

  const identity: StoredIdentity = {
    agentId: deriveAgentId(keypair.publicKey),
    publicKey: Buffer.from(keypair.publicKey).toString('base64'),
    secretKey: Buffer.from(keypair.secretKey).toString('base64'),
    agentName,
    createdAt: new Date().toISOString(),
  };

  fs.mkdirSync(dataDir, { recursive: true });
  const identityPath = path.join(dataDir, IDENTITY_FILE);
  const tmpPath = identityPath + '.tmp.' + process.pid;
  // The file holds the secret key, so it is created owner-only (0o600) by the call that
  // creates it: an explicit mode on the open, not a chmod after the write, so there is no
  // window in which a umask-derived mode exposes the key. A stale temp file from an earlier
  // interrupted run is removed first so the mode always comes from this creation.
  fs.rmSync(tmpPath, { force: true });
  fs.writeFileSync(tmpPath, JSON.stringify(identity, null, 2), { encoding: 'utf-8', mode: 0o600 });
  // Belt and braces for platforms where the open(2) mode is not honoured; never relied on.
  try { fs.chmodSync(tmpPath, 0o600); } catch { /* Windows */ }
  fs.renameSync(tmpPath, identityPath);

  return identity;
}

/** Load an existing identity from disk */
export function loadIdentity(dataDir: string): StoredIdentity | null {
  const filePath = path.join(dataDir, IDENTITY_FILE);
  if (!fs.existsSync(filePath)) {
    return null;
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(raw) as StoredIdentity;
  } catch {
    return null;
  }
}

/**
 * Whether dataDir holds a readable identity. Never creates one: unlike
 * getOrCreateIdentity, asking has no side effect on disk. A missing or
 * unreadable identity file both answer false, the same two cases in which
 * getOrCreateIdentity would create a new identity.
 */
export function hasIdentity(dataDir: string): boolean {
  return loadIdentity(dataDir) !== null;
}

/** Get or create the agent's identity. Returns the public-facing identity (no secret key). */
export function getOrCreateIdentity(dataDir: string, agentName: string): AIMIdentity {
  let stored = loadIdentity(dataDir);
  if (!stored) {
    stored = createIdentity(dataDir, agentName);
  }

  // Return public identity only (strip secret key)
  return {
    agentId: stored.agentId,
    publicKey: stored.publicKey,
    agentName: stored.agentName,
    createdAt: stored.createdAt,
  };
}

/** Get the Ed25519 secret key as Uint8Array (for signing operations) */
export function getSecretKey(dataDir: string): Uint8Array | null {
  const stored = loadIdentity(dataDir);
  if (!stored) return null;
  return Buffer.from(stored.secretKey, 'base64');
}

/** Get the Ed25519 public key as Uint8Array (for verification) */
export function getPublicKey(dataDir: string): Uint8Array | null {
  const stored = loadIdentity(dataDir);
  if (!stored) return null;
  return Buffer.from(stored.publicKey, 'base64');
}

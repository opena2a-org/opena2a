// Shield artifact signing and verification.
//
// Uses SHA-256 hashing (same pattern as guard.ts) to protect Shield's own
// artifacts: policy.yaml, scan.json, llm-cache.json. Signatures are stored
// in ~/.opena2a/shield/signatures.json with 0o600 permissions.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { userInfo } from 'node:os';

import type { ShieldSignature, ShieldSignatureStore } from './types.js';
import {
  SHIELD_SIGNATURES_FILE,
  SHIELD_POLICY_FILE,
  SHIELD_SCAN_FILE,
  SHIELD_LLM_CACHE_FILE,
} from './types.js';
import { getShieldDir } from './events.js';

// Files that Shield signs (relative to shield dir)
const SHIELD_ARTIFACT_FILES = [
  SHIELD_POLICY_FILE,
  SHIELD_SCAN_FILE,
  SHIELD_LLM_CACHE_FILE,
];

/**
 * Compute a SHA-256 signature for a single artifact file.
 */
export function signArtifact(filePath: string): ShieldSignature {
  const content = readFileSync(filePath);
  const hash = 'sha256:' + createHash('sha256').update(content).digest('hex');
  const stat = statSync(filePath);
  const shieldDir = getShieldDir();

  // Compute relative path from shield dir
  let relPath = filePath;
  if (filePath.startsWith(shieldDir)) {
    relPath = filePath.slice(shieldDir.length + 1);
  }

  return {
    filePath: relPath,
    hash,
    signedAt: new Date().toISOString(),
    signedBy: userInfo().username + '@opena2a-cli',
    fileSize: stat.size,
  };
}

/**
 * Verify an artifact file against its stored signature.
 *
 * Returns { valid: true } when:
 *   - No signatures file exists (never signed = acceptable)
 *   - The file has no stored signature (not yet tracked)
 *   - The current hash matches the stored hash
 *
 * Returns { valid: false, detail } when signatures exist and hash doesn't match.
 */
export function verifyArtifact(filePath: string): { valid: boolean; detail: string } {
  const store = loadSignatures();
  if (!store) {
    return { valid: true, detail: 'No signatures file found; skipping verification.' };
  }

  const shieldDir = getShieldDir();
  let relPath = filePath;
  if (filePath.startsWith(shieldDir)) {
    relPath = filePath.slice(shieldDir.length + 1);
  }

  const sig = store.signatures.find(s => s.filePath === relPath);
  if (!sig) {
    return { valid: true, detail: `No signature recorded for ${relPath}.` };
  }

  if (!existsSync(filePath)) {
    return { valid: false, detail: `Signed file ${relPath} is missing.` };
  }

  const content = readFileSync(filePath);
  const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');

  if (currentHash === sig.hash) {
    return { valid: true, detail: `${relPath} integrity verified.` };
  }

  return {
    valid: false,
    detail: `${relPath} has been modified since ${sig.signedAt}. Expected ${sig.hash}, got ${currentHash}.`,
  };
}

/**
 * Sign all known Shield artifacts that exist on disk.
 */
export function signAllArtifacts(): void {
  const shieldDir = getShieldDir();
  const signatures: ShieldSignature[] = [];

  for (const relPath of SHIELD_ARTIFACT_FILES) {
    const fullPath = join(shieldDir, relPath);
    if (!existsSync(fullPath)) continue;
    signatures.push(signArtifact(fullPath));
  }

  const store: ShieldSignatureStore = {
    version: 1,
    signatures,
    updatedAt: new Date().toISOString(),
  };

  saveSignatures(store);
}

/**
 * Load the signatures store from disk.
 * Returns null if the file does not exist or is malformed.
 */
export function loadSignatures(): ShieldSignatureStore | null {
  const sigPath = join(getShieldDir(), SHIELD_SIGNATURES_FILE);
  if (!existsSync(sigPath)) return null;

  try {
    const raw = readFileSync(sigPath, 'utf-8');
    const parsed = JSON.parse(raw) as ShieldSignatureStore;
    if (parsed.version !== 1) return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Save the signatures store to disk with restricted permissions.
 */
export function saveSignatures(store: ShieldSignatureStore): void {
  const sigPath = join(getShieldDir(), SHIELD_SIGNATURES_FILE);
  writeFileSync(sigPath, JSON.stringify(store, null, 2), {
    encoding: 'utf-8',
    mode: 0o600,
  });
}

/**
 * Verify all Shield artifact signatures.
 * Returns a summary suitable for use as an IntegrityCheck.
 */
export function verifyAllArtifacts(): { valid: boolean; detail: string } {
  const store = loadSignatures();
  if (!store) {
    return { valid: true, detail: 'No artifact signatures recorded; skipping.' };
  }

  const shieldDir = getShieldDir();
  const failures: string[] = [];

  for (const sig of store.signatures) {
    const fullPath = join(shieldDir, sig.filePath);
    const result = verifyArtifact(fullPath);
    if (!result.valid) {
      failures.push(result.detail);
    }
  }

  if (failures.length === 0) {
    return {
      valid: true,
      detail: `All ${store.signatures.length} artifact signatures verified.`,
    };
  }

  return {
    valid: false,
    detail: failures.join(' '),
  };
}

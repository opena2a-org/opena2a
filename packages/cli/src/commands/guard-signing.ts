/**
 * Skill.md and Heartbeat.md signing bridge for ConfigGuard.
 *
 * Signs and verifies SKILL.md / HEARTBEAT.md files using SHA-256 hashing
 * with inline HTML-comment signature blocks (matching HMA signcrypt pattern).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHash } from 'node:crypto';

// --- Types ---

export interface SignResult {
  filePath: string;
  hash: string;
  signedAt: string;
  signedBy: string;
  expiresAt?: string;
}

export interface VerifyResult {
  filePath: string;
  status: 'pass' | 'tampered' | 'unsigned' | 'expired';
  currentHash?: string;
  expectedHash?: string;
  expiresAt?: string;
}

interface SignatureBlock {
  pinnedHash: string;
  signedAt: string;
  signedBy: string;
  expiresAt?: string;
}

// --- Constants ---

const SKILL_PATTERNS = ['SKILL.md', '*.skill.md'];
const HEARTBEAT_PATTERNS = ['HEARTBEAT.md', '*.heartbeat.md'];
const HEARTBEAT_EXPIRY_DAYS = 7;
const SIG_BLOCK_START = '<!-- opena2a-guard';
const SIG_BLOCK_END = '-->';
const SIG_BLOCK_RE = /<!-- opena2a-guard\n([\s\S]*?)-->/;

// --- Signing ---

export async function signSkillFiles(targetDir: string): Promise<SignResult[]> {
  const files = findFiles(targetDir, SKILL_PATTERNS);
  return signFiles(files, targetDir, false);
}

export async function signHeartbeatFiles(targetDir: string): Promise<SignResult[]> {
  const files = findFiles(targetDir, HEARTBEAT_PATTERNS);
  return signFiles(files, targetDir, true);
}

function signFiles(files: string[], targetDir: string, withExpiry: boolean): SignResult[] {
  const results: SignResult[] = [];
  const now = new Date();
  const signedBy = os.userInfo().username + '@opena2a-cli';

  for (const fullPath of files) {
    const relPath = path.relative(targetDir, fullPath);
    const raw = fs.readFileSync(fullPath, 'utf-8');
    const content = stripSignatureBlock(raw);
    const hash = 'sha256:' + createHash('sha256').update(content, 'utf-8').digest('hex');
    const signedAt = now.toISOString();
    const expiresAt = withExpiry ? new Date(now.getTime() + HEARTBEAT_EXPIRY_DAYS * 86400000).toISOString() : undefined;

    const block = buildSignatureBlock({ pinnedHash: hash, signedAt, signedBy, expiresAt });
    fs.writeFileSync(fullPath, content.trimEnd() + '\n\n' + block + '\n', 'utf-8');

    results.push({ filePath: relPath, hash, signedAt, signedBy, expiresAt });
  }
  return results;
}

// --- Verification ---

export async function verifySkillSignatures(targetDir: string): Promise<VerifyResult[]> {
  const files = findFiles(targetDir, SKILL_PATTERNS);
  return verifyFiles(files, targetDir, false);
}

export async function verifyHeartbeatSignatures(targetDir: string): Promise<VerifyResult[]> {
  const files = findFiles(targetDir, HEARTBEAT_PATTERNS);
  return verifyFiles(files, targetDir, true);
}

function verifyFiles(files: string[], targetDir: string, checkExpiry: boolean): VerifyResult[] {
  const results: VerifyResult[] = [];

  for (const fullPath of files) {
    const relPath = path.relative(targetDir, fullPath);
    const raw = fs.readFileSync(fullPath, 'utf-8');
    const parsed = parseSignatureBlock(raw);

    if (!parsed) {
      results.push({ filePath: relPath, status: 'unsigned' });
      continue;
    }

    const content = stripSignatureBlock(raw);
    const currentHash = 'sha256:' + createHash('sha256').update(content, 'utf-8').digest('hex');

    if (checkExpiry && parsed.expiresAt) {
      const expiry = new Date(parsed.expiresAt);
      if (expiry.getTime() < Date.now()) {
        results.push({ filePath: relPath, status: 'expired', currentHash, expectedHash: parsed.pinnedHash, expiresAt: parsed.expiresAt });
        continue;
      }
    }

    if (currentHash !== parsed.pinnedHash) {
      results.push({ filePath: relPath, status: 'tampered', currentHash, expectedHash: parsed.pinnedHash });
    } else {
      results.push({ filePath: relPath, status: 'pass', currentHash, expiresAt: parsed.expiresAt });
    }
  }
  return results;
}

// --- Signature block helpers ---

function buildSignatureBlock(sig: SignatureBlock): string {
  const lines = [SIG_BLOCK_START];
  lines.push(`pinned_hash: ${sig.pinnedHash}`);
  lines.push(`signed_at: ${sig.signedAt}`);
  lines.push(`signed_by: ${sig.signedBy}`);
  if (sig.expiresAt) lines.push(`expires_at: ${sig.expiresAt}`);
  lines.push(SIG_BLOCK_END);
  return lines.join('\n');
}

function parseSignatureBlock(content: string): SignatureBlock | null {
  const match = SIG_BLOCK_RE.exec(content);
  if (!match) return null;
  const body = match[1];
  const fields = new Map<string, string>();
  for (const line of body.split('\n')) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    fields.set(line.slice(0, idx).trim(), line.slice(idx + 1).trim());
  }
  const pinnedHash = fields.get('pinned_hash');
  const signedAt = fields.get('signed_at');
  const signedBy = fields.get('signed_by');
  if (!pinnedHash || !signedAt || !signedBy) return null;
  return { pinnedHash, signedAt, signedBy, expiresAt: fields.get('expires_at') };
}

function stripSignatureBlock(content: string): string {
  return content.replace(SIG_BLOCK_RE, '').trimEnd();
}

// --- File discovery ---

function findFiles(targetDir: string, patterns: string[]): string[] {
  const found: string[] = [];
  if (!fs.existsSync(targetDir)) return found;
  const entries = fs.readdirSync(targetDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    for (const pattern of patterns) {
      if (matchPattern(entry.name, pattern)) {
        found.push(path.join(targetDir, entry.name));
        break;
      }
    }
  }
  return found;
}

function matchPattern(filename: string, pattern: string): boolean {
  if (pattern.startsWith('*')) {
    return filename.toLowerCase().endsWith(pattern.slice(1).toLowerCase());
  }
  return filename === pattern;
}

// --- Testable internals ---

export const _internals = {
  findFiles, matchPattern, buildSignatureBlock, parseSignatureBlock,
  stripSignatureBlock, signFiles, verifyFiles,
  SKILL_PATTERNS, HEARTBEAT_PATTERNS, HEARTBEAT_EXPIRY_DAYS,
  SIG_BLOCK_RE,
};

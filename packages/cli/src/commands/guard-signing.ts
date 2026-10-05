/**
 * Skill.md and Heartbeat.md hash pinning for ConfigGuard.
 *
 * Pins SKILL.md / HEARTBEAT.md files with an inline HTML-comment block that
 * records a SHA-256 of the file's content. The digest is unkeyed and lives in
 * the file it covers, so anyone who can edit the file can recompute it: this
 * catches accidental or partial edits, it is not a signature and proves
 * nothing about who wrote the file. An AIM (Ed25519) signature is the
 * mechanism `scan` looks for; the vocabulary here (pin, pinned_by, unpinned,
 * changed) is kept distinct from it on purpose.
 */

import * as fs from 'node:fs';
import { signedByLabel } from '../util/signed-by.js';
import * as path from 'node:path';
import { createHash } from 'node:crypto';

// --- Types ---

export interface PinResult {
  filePath: string;
  hash: string;
  pinnedAt: string;
  pinnedBy: string;
  expiresAt?: string;
}

export interface VerifyResult {
  filePath: string;
  status: 'pass' | 'changed' | 'unpinned' | 'expired';
  currentHash?: string;
  expectedHash?: string;
  expiresAt?: string;
}

interface PinBlock {
  pinnedHash: string;
  pinnedAt: string;
  pinnedBy: string;
  expiresAt?: string;
}

// --- Constants ---

const SKILL_PATTERNS = ['SKILL.md', '*.skill.md'];
const HEARTBEAT_PATTERNS = ['HEARTBEAT.md', '*.heartbeat.md'];
const HEARTBEAT_EXPIRY_DAYS = 7;
const PIN_BLOCK_START = '<!-- opena2a-guard';
const PIN_BLOCK_END = '-->';
const PIN_BLOCK_RE = /<!-- opena2a-guard\n([\s\S]*?)-->/;

// --- Pinning ---

export async function pinSkillFiles(targetDir: string): Promise<PinResult[]> {
  const files = findFiles(targetDir, SKILL_PATTERNS);
  return pinFiles(files, targetDir, false);
}

export async function pinHeartbeatFiles(targetDir: string): Promise<PinResult[]> {
  const files = findFiles(targetDir, HEARTBEAT_PATTERNS);
  return pinFiles(files, targetDir, true);
}

function pinFiles(files: string[], targetDir: string, withExpiry: boolean): PinResult[] {
  const results: PinResult[] = [];
  const now = new Date();
  const pinnedBy = signedByLabel();

  for (const fullPath of files) {
    const relPath = path.relative(targetDir, fullPath);
    const raw = fs.readFileSync(fullPath, 'utf-8');
    const content = stripPinBlock(raw);
    const hash = 'sha256:' + createHash('sha256').update(content, 'utf-8').digest('hex');
    const pinnedAt = now.toISOString();
    const expiresAt = withExpiry ? new Date(now.getTime() + HEARTBEAT_EXPIRY_DAYS * 86400000).toISOString() : undefined;

    const block = buildPinBlock({ pinnedHash: hash, pinnedAt, pinnedBy, expiresAt });
    fs.writeFileSync(fullPath, content.trimEnd() + '\n\n' + block + '\n', 'utf-8');

    results.push({ filePath: relPath, hash, pinnedAt, pinnedBy, expiresAt });
  }
  return results;
}

// --- Verification ---

export async function verifySkillPins(targetDir: string): Promise<VerifyResult[]> {
  const files = findFiles(targetDir, SKILL_PATTERNS);
  return verifyFiles(files, targetDir, false);
}

export async function verifyHeartbeatPins(targetDir: string): Promise<VerifyResult[]> {
  const files = findFiles(targetDir, HEARTBEAT_PATTERNS);
  return verifyFiles(files, targetDir, true);
}

function verifyFiles(files: string[], targetDir: string, checkExpiry: boolean): VerifyResult[] {
  const results: VerifyResult[] = [];

  for (const fullPath of files) {
    const relPath = path.relative(targetDir, fullPath);
    const raw = fs.readFileSync(fullPath, 'utf-8');
    const parsed = parsePinBlock(raw);

    if (!parsed) {
      results.push({ filePath: relPath, status: 'unpinned' });
      continue;
    }

    const content = stripPinBlock(raw);
    const currentHash = 'sha256:' + createHash('sha256').update(content, 'utf-8').digest('hex');

    if (checkExpiry && parsed.expiresAt) {
      const expiry = new Date(parsed.expiresAt);
      if (expiry.getTime() < Date.now()) {
        results.push({ filePath: relPath, status: 'expired', currentHash, expectedHash: parsed.pinnedHash, expiresAt: parsed.expiresAt });
        continue;
      }
    }

    if (currentHash !== parsed.pinnedHash) {
      results.push({ filePath: relPath, status: 'changed', currentHash, expectedHash: parsed.pinnedHash });
    } else {
      results.push({ filePath: relPath, status: 'pass', currentHash, expiresAt: parsed.expiresAt });
    }
  }
  return results;
}

// --- Pin block helpers ---

function buildPinBlock(pin: PinBlock): string {
  const lines = [PIN_BLOCK_START];
  lines.push(`pinned_hash: ${pin.pinnedHash}`);
  lines.push(`pinned_at: ${pin.pinnedAt}`);
  lines.push(`pinned_by: ${pin.pinnedBy}`);
  if (pin.expiresAt) lines.push(`expires_at: ${pin.expiresAt}`);
  lines.push(PIN_BLOCK_END);
  return lines.join('\n');
}

function parsePinBlock(content: string): PinBlock | null {
  const match = PIN_BLOCK_RE.exec(content);
  if (!match) return null;
  const body = match[1];
  const fields = new Map<string, string>();
  for (const line of body.split('\n')) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    fields.set(line.slice(0, idx).trim(), line.slice(idx + 1).trim());
  }
  const pinnedHash = fields.get('pinned_hash');
  // Blocks written before the rename carry signed_at / signed_by. They hold
  // the same unkeyed digest, so they still verify and are rewritten with the
  // pinned_* names the next time the file is pinned.
  const pinnedAt = fields.get('pinned_at') ?? fields.get('signed_at');
  const pinnedBy = fields.get('pinned_by') ?? fields.get('signed_by');
  if (!pinnedHash || !pinnedAt || !pinnedBy) return null;
  return { pinnedHash, pinnedAt, pinnedBy, expiresAt: fields.get('expires_at') };
}

function stripPinBlock(content: string): string {
  return content.replace(PIN_BLOCK_RE, '').trimEnd();
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
  findFiles, matchPattern, buildPinBlock, parsePinBlock,
  stripPinBlock, pinFiles, verifyFiles,
  SKILL_PATTERNS, HEARTBEAT_PATTERNS, HEARTBEAT_EXPIRY_DAYS,
  PIN_BLOCK_RE,
};

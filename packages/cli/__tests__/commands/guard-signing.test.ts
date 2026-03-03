import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  signSkillFiles, signHeartbeatFiles,
  verifySkillSignatures, verifyHeartbeatSignatures,
  _internals,
} from '../../src/commands/guard-signing.js';

describe('guard-signing', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-guard-signing-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  // --- Skill file detection ---

  it('finds SKILL.md files', () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# My Skill');
    fs.writeFileSync(path.join(tempDir, 'auth.skill.md'), '# Auth Skill');
    fs.writeFileSync(path.join(tempDir, 'README.md'), '# Not a skill');

    const found = _internals.findFiles(tempDir, _internals.SKILL_PATTERNS);
    expect(found).toHaveLength(2);
    expect(found.map(f => path.basename(f)).sort()).toEqual(['SKILL.md', 'auth.skill.md']);
  });

  it('finds HEARTBEAT.md files', () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Status: alive');
    fs.writeFileSync(path.join(tempDir, 'health.heartbeat.md'), '# Health check');
    fs.writeFileSync(path.join(tempDir, 'notes.md'), '# Not a heartbeat');

    const found = _internals.findFiles(tempDir, _internals.HEARTBEAT_PATTERNS);
    expect(found).toHaveLength(2);
    expect(found.map(f => path.basename(f)).sort()).toEqual(['HEARTBEAT.md', 'health.heartbeat.md']);
  });

  // --- Skill signing ---

  it('signs SKILL.md and appends signature block', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# My Skill\n\nDoes something useful.');

    const results = await signSkillFiles(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].filePath).toBe('SKILL.md');
    expect(results[0].hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(results[0].signedBy).toContain('@opena2a-cli');
    expect(results[0].expiresAt).toBeUndefined();

    const content = fs.readFileSync(path.join(tempDir, 'SKILL.md'), 'utf-8');
    expect(content).toContain('<!-- opena2a-guard');
    expect(content).toContain('pinned_hash: sha256:');
    expect(content).toContain('signed_at:');
    expect(content).toContain('signed_by:');
    expect(content).not.toContain('expires_at:');
  });

  // --- Heartbeat signing ---

  it('signs HEARTBEAT.md with expires_at', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Alive\n\nAll systems operational.');

    const results = await signHeartbeatFiles(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].filePath).toBe('HEARTBEAT.md');
    expect(results[0].hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(results[0].expiresAt).toBeDefined();

    // Verify expiry is ~7 days from now
    const expiry = new Date(results[0].expiresAt!);
    const now = Date.now();
    const diff = expiry.getTime() - now;
    expect(diff).toBeGreaterThan(6 * 86400000);
    expect(diff).toBeLessThan(8 * 86400000);

    const content = fs.readFileSync(path.join(tempDir, 'HEARTBEAT.md'), 'utf-8');
    expect(content).toContain('expires_at:');
  });

  // --- Verification passes for clean files ---

  it('verification passes for clean skill files', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# Clean Skill');
    await signSkillFiles(tempDir);

    const results = await verifySkillSignatures(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
    expect(results[0].currentHash).toMatch(/^sha256:/);
  });

  it('verification passes for clean heartbeat files', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Alive');
    await signHeartbeatFiles(tempDir);

    const results = await verifyHeartbeatSignatures(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
    expect(results[0].expiresAt).toBeDefined();
  });

  // --- Verification fails for tampered files ---

  it('verification fails for tampered skill file', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# Original Skill');
    await signSkillFiles(tempDir);

    // Tamper: replace content but keep signature block
    const signed = fs.readFileSync(path.join(tempDir, 'SKILL.md'), 'utf-8');
    const tampered = signed.replace('# Original Skill', '# Tampered Skill');
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), tampered);

    const results = await verifySkillSignatures(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('tampered');
    expect(results[0].expectedHash).toBeDefined();
    expect(results[0].currentHash).toBeDefined();
    expect(results[0].currentHash).not.toBe(results[0].expectedHash);
  });

  it('verification fails for tampered heartbeat file', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Alive');
    await signHeartbeatFiles(tempDir);

    const signed = fs.readFileSync(path.join(tempDir, 'HEARTBEAT.md'), 'utf-8');
    const tampered = signed.replace('# Alive', '# Compromised');
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), tampered);

    const results = await verifyHeartbeatSignatures(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('tampered');
  });

  // --- Heartbeat expiry detection ---

  it('detects expired heartbeat', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Alive');
    await signHeartbeatFiles(tempDir);

    // Manually set expires_at to the past
    const content = fs.readFileSync(path.join(tempDir, 'HEARTBEAT.md'), 'utf-8');
    const expired = content.replace(/expires_at: .+/, 'expires_at: 2020-01-01T00:00:00.000Z');
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), expired);

    const results = await verifyHeartbeatSignatures(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('expired');
    expect(results[0].expiresAt).toBe('2020-01-01T00:00:00.000Z');
  });

  // --- Unsigned files ---

  it('detects unsigned skill files', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# Unsigned Skill\n\nNo signature here.');

    const results = await verifySkillSignatures(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('unsigned');
  });

  it('detects unsigned heartbeat files', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Unsigned Heartbeat');

    const results = await verifyHeartbeatSignatures(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('unsigned');
  });

  // --- No files found ---

  it('returns empty array when no skill files exist', async () => {
    const results = await signSkillFiles(tempDir);
    expect(results).toEqual([]);
  });

  it('returns empty array when no heartbeat files exist', async () => {
    const results = await signHeartbeatFiles(tempDir);
    expect(results).toEqual([]);
  });

  // --- Signature block parsing ---

  it('parseSignatureBlock extracts all fields', () => {
    const content = `# Skill

<!-- opena2a-guard
pinned_hash: sha256:abc123
signed_at: 2026-03-03T01:00:00Z
signed_by: user@opena2a-cli
expires_at: 2026-03-10T01:00:00Z
-->`;
    const parsed = _internals.parseSignatureBlock(content);
    expect(parsed).not.toBeNull();
    expect(parsed!.pinnedHash).toBe('sha256:abc123');
    expect(parsed!.signedAt).toBe('2026-03-03T01:00:00Z');
    expect(parsed!.signedBy).toBe('user@opena2a-cli');
    expect(parsed!.expiresAt).toBe('2026-03-10T01:00:00Z');
  });

  it('parseSignatureBlock returns null for no block', () => {
    expect(_internals.parseSignatureBlock('# Just a file')).toBeNull();
  });

  // --- Strip and re-sign idempotency ---

  it('re-signing produces consistent hash', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# Stable Skill');

    const first = await signSkillFiles(tempDir);
    const second = await signSkillFiles(tempDir);

    expect(first[0].hash).toBe(second[0].hash);
  });

  // --- matchPattern ---

  it('matchPattern handles exact and wildcard patterns', () => {
    expect(_internals.matchPattern('SKILL.md', 'SKILL.md')).toBe(true);
    expect(_internals.matchPattern('auth.skill.md', '*.skill.md')).toBe(true);
    expect(_internals.matchPattern('SKILL.md', '*.skill.md')).toBe(false);
    expect(_internals.matchPattern('readme.md', 'SKILL.md')).toBe(false);
  });
});

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createHash } from 'node:crypto';
import {
  pinSkillFiles, pinHeartbeatFiles,
  verifySkillPins, verifyHeartbeatPins,
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

  // --- Skill pinning ---

  it('pins SKILL.md and appends a pin block', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# My Skill\n\nDoes something useful.');

    const results = await pinSkillFiles(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].filePath).toBe('SKILL.md');
    expect(results[0].hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(results[0].pinnedBy).toMatch(/^opena2a-cli\/\d+\.\d+\.\d+/);
    expect(results[0].pinnedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(results[0].expiresAt).toBeUndefined();

    const content = fs.readFileSync(path.join(tempDir, 'SKILL.md'), 'utf-8');
    expect(content).toContain('<!-- opena2a-guard');
    expect(content).toContain('pinned_hash: sha256:');
    expect(content).toContain('pinned_at:');
    expect(content).toContain('pinned_by:');
    expect(content).not.toContain('expires_at:');
  });

  // #264: the block is an unkeyed digest stored in the file it covers. It must
  // not describe itself with signature vocabulary, which `scan` uses for the
  // AIM/Ed25519 signature it reports as missing on these same files.
  it('writes no signature vocabulary into the pin block (#264)', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# My Skill');
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Alive');
    await pinSkillFiles(tempDir);
    await pinHeartbeatFiles(tempDir);

    for (const name of ['SKILL.md', 'HEARTBEAT.md']) {
      const block = fs.readFileSync(path.join(tempDir, name), 'utf-8').match(_internals.PIN_BLOCK_RE)![0];
      expect(block).not.toMatch(/sign/i);
    }
  });

  // --- Heartbeat pinning ---

  it('pins HEARTBEAT.md with expires_at', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Alive\n\nAll systems operational.');

    const results = await pinHeartbeatFiles(tempDir);
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
    await pinSkillFiles(tempDir);

    const results = await verifySkillPins(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
    expect(results[0].currentHash).toMatch(/^sha256:/);
  });

  it('verification passes for clean heartbeat files', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Alive');
    await pinHeartbeatFiles(tempDir);

    const results = await verifyHeartbeatPins(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
    expect(results[0].expiresAt).toBeDefined();
  });

  // --- Verification fails for changed files ---

  it('verification fails for a changed skill file', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# Original Skill');
    await pinSkillFiles(tempDir);

    // Edit the content but keep the pin block
    const pinned = fs.readFileSync(path.join(tempDir, 'SKILL.md'), 'utf-8');
    const edited = pinned.replace('# Original Skill', '# Edited Skill');
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), edited);

    const results = await verifySkillPins(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('changed');
    expect(results[0].expectedHash).toBeDefined();
    expect(results[0].currentHash).toBeDefined();
    expect(results[0].currentHash).not.toBe(results[0].expectedHash);
  });

  it('verification fails for a changed heartbeat file', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Alive');
    await pinHeartbeatFiles(tempDir);

    const pinned = fs.readFileSync(path.join(tempDir, 'HEARTBEAT.md'), 'utf-8');
    const edited = pinned.replace('# Alive', '# Compromised');
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), edited);

    const results = await verifyHeartbeatPins(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('changed');
  });

  // The limit the vocabulary has to describe honestly: the digest is unkeyed
  // and lives in the file, so an edit that recomputes it verifies as pass.
  // This is why the mechanism is a pin that catches accidental edits and not
  // tamper detection (#264). If this ever fails, the pin became keyed and the
  // wording can be revisited.
  it('an edit that recomputes the in-file digest still verifies (#264)', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# Original Skill');
    await pinSkillFiles(tempDir);

    const raw = fs.readFileSync(path.join(tempDir, 'SKILL.md'), 'utf-8');
    const block = raw.match(_internals.PIN_BLOCK_RE)![0];
    const body = _internals.stripPinBlock(raw).replace('# Original Skill', '# Rewritten Skill');
    const digest = 'sha256:' + createHash('sha256').update(body, 'utf-8').digest('hex');
    fs.writeFileSync(
      path.join(tempDir, 'SKILL.md'),
      body + '\n\n' + block.replace(/pinned_hash: \S+/, `pinned_hash: ${digest}`) + '\n',
    );

    const results = await verifySkillPins(tempDir);
    expect(results[0].status).toBe('pass');
  });

  // --- Blocks written before the rename (#264) ---

  it('a block written with signed_at / signed_by still verifies (#264)', async () => {
    const body = '# Legacy Skill';
    const digest = 'sha256:' + createHash('sha256').update(body, 'utf-8').digest('hex');
    fs.writeFileSync(
      path.join(tempDir, 'SKILL.md'),
      `${body}\n\n<!-- opena2a-guard\npinned_hash: ${digest}\nsigned_at: 2026-03-03T01:00:00Z\nsigned_by: opena2a-cli/0.10.13\n-->\n`,
    );

    const results = await verifySkillPins(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');

    // Re-pinning rewrites the block with the pinned_* names and the same digest.
    const repinned = await pinSkillFiles(tempDir);
    expect(repinned[0].hash).toBe(digest);
    const content = fs.readFileSync(path.join(tempDir, 'SKILL.md'), 'utf-8');
    expect(content).toContain('pinned_by: ');
    expect(content).not.toContain('signed_by:');
    expect(content).not.toContain('signed_at:');
  });

  // --- Heartbeat expiry detection ---

  it('detects expired heartbeat', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Alive');
    await pinHeartbeatFiles(tempDir);

    // Manually set expires_at to the past
    const content = fs.readFileSync(path.join(tempDir, 'HEARTBEAT.md'), 'utf-8');
    const expired = content.replace(/expires_at: .+/, 'expires_at: 2020-01-01T00:00:00.000Z');
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), expired);

    const results = await verifyHeartbeatPins(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('expired');
    expect(results[0].expiresAt).toBe('2020-01-01T00:00:00.000Z');
  });

  // --- Unpinned files ---

  it('detects unpinned skill files', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# Unpinned Skill\n\nNo pin block here.');

    const results = await verifySkillPins(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('unpinned');
  });

  it('detects unpinned heartbeat files', async () => {
    fs.writeFileSync(path.join(tempDir, 'HEARTBEAT.md'), '# Unpinned Heartbeat');

    const results = await verifyHeartbeatPins(tempDir);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('unpinned');
  });

  // --- No files found ---

  it('returns empty array when no skill files exist', async () => {
    const results = await pinSkillFiles(tempDir);
    expect(results).toEqual([]);
  });

  it('returns empty array when no heartbeat files exist', async () => {
    const results = await pinHeartbeatFiles(tempDir);
    expect(results).toEqual([]);
  });

  // --- Pin block parsing ---

  it('parsePinBlock extracts all fields', () => {
    const content = `# Skill

<!-- opena2a-guard
pinned_hash: sha256:abc123
pinned_at: 2026-03-03T01:00:00Z
pinned_by: user@opena2a-cli
expires_at: 2026-03-10T01:00:00Z
-->`;
    const parsed = _internals.parsePinBlock(content);
    expect(parsed).not.toBeNull();
    expect(parsed!.pinnedHash).toBe('sha256:abc123');
    expect(parsed!.pinnedAt).toBe('2026-03-03T01:00:00Z');
    expect(parsed!.pinnedBy).toBe('user@opena2a-cli');
    expect(parsed!.expiresAt).toBe('2026-03-10T01:00:00Z');
  });

  it('parsePinBlock reads the signed_at / signed_by names written before #264', () => {
    const content = `# Skill

<!-- opena2a-guard
pinned_hash: sha256:abc123
signed_at: 2026-03-03T01:00:00Z
signed_by: user@opena2a-cli
-->`;
    const parsed = _internals.parsePinBlock(content);
    expect(parsed).not.toBeNull();
    expect(parsed!.pinnedAt).toBe('2026-03-03T01:00:00Z');
    expect(parsed!.pinnedBy).toBe('user@opena2a-cli');
  });

  it('parsePinBlock returns null for no block', () => {
    expect(_internals.parsePinBlock('# Just a file')).toBeNull();
  });

  // --- Strip and re-pin idempotency ---

  it('re-pinning produces consistent hash', async () => {
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# Stable Skill');

    const first = await pinSkillFiles(tempDir);
    const second = await pinSkillFiles(tempDir);

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

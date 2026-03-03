import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { guard } from '../../src/commands/guard.js';
import { _internals } from '../../src/commands/guard-snapshots.js';

function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  }) as any;

  return fn().then(exitCode => {
    process.stdout.write = origWrite;
    return { exitCode, output: chunks.join('') };
  }).catch(err => {
    process.stdout.write = origWrite;
    throw err;
  });
}

describe('guard-snapshots', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-guard-snap-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  // --- createSnapshot ---

  it('createSnapshot stores correct data', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"test"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const result = _internals.createSnapshot(tempDir);
    expect(result.id).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z$/);
    expect(result.fileCount).toBe(1);
    expect(fs.existsSync(result.path)).toBe(true);

    // Verify snapshot content matches store
    const snapshotContent = JSON.parse(fs.readFileSync(result.path, 'utf-8'));
    const storeContent = JSON.parse(fs.readFileSync(path.join(tempDir, '.opena2a/guard/signatures.json'), 'utf-8'));
    expect(snapshotContent).toEqual(storeContent);
  });

  it('createSnapshot throws when no store exists', () => {
    expect(() => _internals.createSnapshot(tempDir)).toThrow('No signature store found');
  });

  // --- listSnapshots ---

  it('listSnapshots returns sorted results (newest first)', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    // Create multiple snapshots with slight delay
    const snap1 = _internals.createSnapshot(tempDir);
    // Manually create a second snapshot with a different timestamp
    const snapshotsDir = path.join(tempDir, '.opena2a/guard/snapshots');
    const olderContent = fs.readFileSync(path.join(tempDir, '.opena2a/guard/signatures.json'), 'utf-8');
    fs.writeFileSync(path.join(snapshotsDir, '2020-01-01T00-00-00Z.json'), olderContent, 'utf-8');

    const snapshots = _internals.listSnapshots(tempDir);
    expect(snapshots.length).toBe(2);
    // Newest first
    expect(snapshots[0].id).toBe(snap1.id);
    expect(snapshots[1].id).toBe('2020-01-01T00-00-00Z');
  });

  it('listSnapshots returns empty when no snapshots dir', () => {
    const result = _internals.listSnapshots(tempDir);
    expect(result).toEqual([]);
  });

  // --- restoreSnapshot ---

  it('restoreSnapshot copies back correctly', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"original"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    // Record the original store content
    const storePath = path.join(tempDir, '.opena2a/guard/signatures.json');
    const originalStoreContent = fs.readFileSync(storePath, 'utf-8');
    const originalHash = JSON.parse(originalStoreContent).signatures[0].hash;

    // Manually create a snapshot with a known past ID to avoid timestamp collision
    const snapshotsDir = path.join(tempDir, '.opena2a/guard/snapshots');
    fs.mkdirSync(snapshotsDir, { recursive: true });
    const snapId = '2020-01-01T00-00-00Z';
    fs.writeFileSync(path.join(snapshotsDir, `${snapId}.json`), originalStoreContent, 'utf-8');

    // Modify and re-sign
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"modified","extra":true}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    // Store should now have a different hash
    const storeModified = JSON.parse(fs.readFileSync(storePath, 'utf-8'));
    expect(storeModified.signatures[0].hash).not.toBe(originalHash);

    // Restore the snapshot
    const result = _internals.restoreSnapshot(tempDir, snapId);
    expect(result.restored).toBe(true);
    expect(result.fileCount).toBe(1);
    expect(result.previousId).toBeTruthy(); // Safety snapshot was created

    // Store should now have the original hash again
    const storeAfterRestore = JSON.parse(fs.readFileSync(storePath, 'utf-8'));
    expect(storeAfterRestore.signatures[0].hash).toBe(originalHash);
  });

  it('restoreSnapshot throws for non-existent snapshot', () => {
    expect(() => _internals.restoreSnapshot(tempDir, 'non-existent')).toThrow('Snapshot not found');
  });

  // --- Snapshot pruning ---

  it('prunes snapshots at 20 limit', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const snapshotsDir = path.join(tempDir, '.opena2a/guard/snapshots');
    fs.mkdirSync(snapshotsDir, { recursive: true });
    const storeContent = fs.readFileSync(path.join(tempDir, '.opena2a/guard/signatures.json'), 'utf-8');

    // Create 25 snapshots manually
    for (let i = 0; i < 25; i++) {
      const id = `2026-01-${String(i + 1).padStart(2, '0')}T00-00-00Z`;
      fs.writeFileSync(path.join(snapshotsDir, `${id}.json`), storeContent, 'utf-8');
    }

    expect(fs.readdirSync(snapshotsDir).length).toBe(25);

    // Prune should remove the oldest 5
    _internals.pruneSnapshots(snapshotsDir);

    const remaining = fs.readdirSync(snapshotsDir);
    expect(remaining.length).toBe(20);
    // The oldest files (01-05) should be removed
    expect(remaining).not.toContain('2026-01-01T00-00-00Z.json');
    expect(remaining).not.toContain('2026-01-05T00-00-00Z.json');
    // The newest should remain
    expect(remaining).toContain('2026-01-25T00-00-00Z.json');
  });

  // --- Resign via guard CLI ---

  it('resign re-signs only changed files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"original"}');
    fs.writeFileSync(path.join(tempDir, 'tsconfig.json'), '{"compilerOptions":{}}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    // Tamper only package.json
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"modified"}');

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'resign',
      targetDir: tempDir,
      format: 'json',
      ci: true,
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.resigned).toBe(1);
    expect(result.files).toEqual(['package.json']);

    // Verify the store was updated -- verify should pass now
    const { exitCode: verifyExit } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
    }));
    expect(verifyExit).toBe(0);
  });

  it('resign creates safety snapshot first', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"original"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"modified"}');

    await captureStdout(() => guard({
      subcommand: 'resign',
      targetDir: tempDir,
      format: 'json',
      ci: true,
    }));

    // A snapshot should exist
    const snapshots = _internals.listSnapshots(tempDir);
    expect(snapshots.length).toBeGreaterThanOrEqual(1);
  });

  it('resign in CI mode auto-confirms', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"changed":true}');

    // CI mode should not prompt
    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'resign',
      targetDir: tempDir,
      format: 'json',
      ci: true,
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.resigned).toBe(1);
  });

  it('resign returns 0 when nothing changed', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'resign',
      targetDir: tempDir,
      format: 'json',
      ci: true,
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.resigned).toBe(0);
  });

  it('resign returns 1 when no store exists', async () => {
    const { exitCode } = await captureStdout(() => guard({
      subcommand: 'resign',
      targetDir: tempDir,
      format: 'json',
      ci: true,
    }));

    expect(exitCode).toBe(1);
  });

  // --- Snapshot via guard CLI ---

  it('snapshot create returns result', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'snapshot',
      targetDir: tempDir,
      format: 'json',
      args: ['create'],
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.id).toBeDefined();
    expect(result.fileCount).toBe(1);
  });

  it('snapshot list returns snapshots', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    _internals.createSnapshot(tempDir);

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'snapshot',
      targetDir: tempDir,
      format: 'json',
      args: ['list'],
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.snapshots.length).toBeGreaterThanOrEqual(1);
  });

  it('snapshot restore updates signatures.json', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"v":1}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    const snap = _internals.createSnapshot(tempDir);

    // Re-sign with different content
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"v":2}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'snapshot',
      targetDir: tempDir,
      format: 'json',
      args: ['restore', snap.id],
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.restored).toBe(true);
    expect(result.fileCount).toBe(1);
  });

  it('snapshot restore requires id', async () => {
    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'snapshot',
      targetDir: tempDir,
      format: 'json',
      args: ['restore'],
    }));

    expect(exitCode).toBe(1);
    const result = JSON.parse(output);
    expect(result.error).toContain('Snapshot ID required');
  });
});

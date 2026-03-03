import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { guard, verifyConfigIntegrity, _internals } from '../../src/commands/guard.js';

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

describe('guard', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-guard-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('sign creates signature store', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"test"}');
    fs.writeFileSync(path.join(tempDir, 'tsconfig.json'), '{"compilerOptions":{}}');

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'sign',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.signed).toBe(2);

    // Verify store file exists
    const storePath = path.join(tempDir, '.opena2a/guard/signatures.json');
    expect(fs.existsSync(storePath)).toBe(true);
    const store = JSON.parse(fs.readFileSync(storePath, 'utf-8'));
    expect(store.version).toBe(1);
    expect(store.signatures).toHaveLength(2);
  });

  it('verify detects tampering', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"original"}');

    // Sign
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    // Tamper with the file
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"tampered"}');

    // Verify
    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(1);
    const report = JSON.parse(output);
    expect(report.tampered).toBe(1);
    const tamperedFile = report.results.find((r: any) => r.status === 'tampered');
    expect(tamperedFile).toBeDefined();
    expect(tamperedFile.filePath).toBe('package.json');
  });

  it('verify passes for clean files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"clean"}');

    // Sign
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    // Verify without modification
    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const report = JSON.parse(output);
    expect(report.passed).toBe(1);
    expect(report.tampered).toBe(0);
  });

  it('status shows correct counts', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"test"}');
    fs.writeFileSync(path.join(tempDir, 'tsconfig.json'), '{}');
    fs.writeFileSync(path.join(tempDir, 'Dockerfile'), 'FROM node');

    // Sign only package.json
    await guard({ subcommand: 'sign', targetDir: tempDir, files: ['package.json'], format: 'json' });

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'status',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const status = JSON.parse(output);
    expect(status.signed).toBe(1);
    expect(status.unsigned).toBe(2); // tsconfig.json and Dockerfile
    expect(status.tampered).toBe(0);
  });

  it('sign with custom --files only signs specified files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    fs.writeFileSync(path.join(tempDir, 'tsconfig.json'), '{}');

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'sign',
      targetDir: tempDir,
      files: ['tsconfig.json'],
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.signed).toBe(1);
    expect(result.files).toContain('tsconfig.json');
    expect(result.files).not.toContain('package.json');
  });

  it('reports unsigned config files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    // Create an empty store (no signatures)
    const storeDir = path.join(tempDir, '.opena2a/guard');
    fs.mkdirSync(storeDir, { recursive: true });
    fs.writeFileSync(path.join(storeDir, 'signatures.json'), JSON.stringify({
      version: 1, signatures: [], updatedAt: new Date().toISOString(),
    }));

    const { output } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report.unsigned).toBeGreaterThan(0);
  });

  it('returns 1 when no store exists for verify', async () => {
    const { exitCode } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(1);
  });

  it('handles missing signed files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    // Delete the signed file
    fs.unlinkSync(path.join(tempDir, 'package.json'));

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report.missing).toBe(1);
  });

  // --- Enforce mode ---

  it('enforce mode returns exit code 3 on tampering', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"original"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"tampered"}');

    const { exitCode } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
      enforce: true,
    }));

    expect(exitCode).toBe(3);
  });

  it('enforce mode returns 0 when clean', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"clean"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const { exitCode } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
      enforce: true,
    }));

    expect(exitCode).toBe(0);
  });

  it('enforce mode returns 3 on missing files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.unlinkSync(path.join(tempDir, 'package.json'));

    const { exitCode } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
      enforce: true,
    }));

    expect(exitCode).toBe(3);
  });

  // --- Diff subcommand ---

  it('diff shows changes for tampered files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"before"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"after","extra":true}');

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'diff',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(1);
    const result = JSON.parse(output);
    expect(result.hasChanges).toBe(true);
    const changed = result.files.find((f: any) => f.status === 'changed');
    expect(changed).toBeDefined();
    expect(changed.filePath).toBe('package.json');
    expect(changed.diff).toBeDefined();
    expect(changed.diff.type).toBe('json');
  });

  it('diff returns 0 when no changes', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"stable"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'diff',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.hasChanges).toBe(false);
    expect(result.files[0].status).toBe('unchanged');
  });

  it('diff reports missing files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.unlinkSync(path.join(tempDir, 'package.json'));

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'diff',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(1);
    const result = JSON.parse(output);
    expect(result.files[0].status).toBe('missing');
  });

  it('diff filters by --files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    fs.writeFileSync(path.join(tempDir, 'tsconfig.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"changed":true}');
    fs.writeFileSync(path.join(tempDir, 'tsconfig.json'), '{"changed":true}');

    const { output } = await captureStdout(() => guard({
      subcommand: 'diff',
      targetDir: tempDir,
      files: ['package.json'],
      format: 'json',
    }));

    const result = JSON.parse(output);
    expect(result.files).toHaveLength(1);
    expect(result.files[0].filePath).toBe('package.json');
  });

  it('diff returns 1 when no store exists', async () => {
    const { exitCode } = await captureStdout(() => guard({
      subcommand: 'diff',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(1);
  });

  // --- Verify includes diff context ---

  it('verify includes diff info for tampered files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"original"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"modified","new":1}');

    const { output } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    const tampered = report.results.find((r: any) => r.status === 'tampered');
    expect(tampered.diff).toBeDefined();
    expect(tampered.diff.type).toBe('json');
    expect(typeof tampered.diff.sizeChange).toBe('number');
  });

  // --- verifyConfigIntegrity ---

  it('verifyConfigIntegrity returns unsigned when no store', () => {
    const result = verifyConfigIntegrity(tempDir);
    expect(result.signatureStatus).toBe('unsigned');
    expect(result.filesMonitored).toBe(0);
    expect(result.tamperedFiles).toEqual([]);
  });

  it('verifyConfigIntegrity returns valid when clean', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const result = verifyConfigIntegrity(tempDir);
    expect(result.signatureStatus).toBe('valid');
    expect(result.filesMonitored).toBe(1);
    expect(result.tamperedFiles).toEqual([]);
  });

  it('verifyConfigIntegrity detects tampering', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"hacked":true}');

    const result = verifyConfigIntegrity(tempDir);
    expect(result.signatureStatus).toBe('tampered');
    expect(result.tamperedFiles).toContain('package.json');
  });

  it('verifyConfigIntegrity detects missing files as tampered', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.unlinkSync(path.join(tempDir, 'package.json'));

    const result = verifyConfigIntegrity(tempDir);
    expect(result.signatureStatus).toBe('tampered');
    expect(result.tamperedFiles).toContain('package.json');
  });

  // --- Text output ---

  it('sign outputs text format correctly', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');

    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'sign',
      targetDir: tempDir,
      format: 'text',
    }));

    expect(exitCode).toBe(0);
    expect(output).toContain('Signed 1 config file');
    expect(output).toContain('package.json');
  });

  it('verify text format includes QUARANTINE label in enforce mode', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"tampered":true}');

    const { output } = await captureStdout(() => guard({
      subcommand: 'verify',
      targetDir: tempDir,
      format: 'text',
      enforce: true,
    }));

    expect(output).toContain('QUARANTINE');
  });

  it('status text format shows header', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const { output } = await captureStdout(() => guard({
      subcommand: 'status',
      targetDir: tempDir,
      format: 'text',
    }));

    expect(output).toContain('ConfigGuard Status');
    expect(output).toContain('Signed');
  });

  // --- Internal helpers ---

  it('resolveFiles returns only existing files', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    const files = _internals.resolveFiles(tempDir);
    expect(files).toContain('package.json');
    expect(files).not.toContain('tsconfig.json');
  });

  it('resolveFiles with custom list filters non-existent', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    const files = _internals.resolveFiles(tempDir, ['package.json', 'missing.json']);
    expect(files).toEqual(['package.json']);
  });

  it('loadStore returns null when no store', () => {
    expect(_internals.loadStore(tempDir)).toBeNull();
  });

  it('loadStore returns parsed store', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const store = _internals.loadStore(tempDir);
    expect(store).not.toBeNull();
    expect(store!.version).toBe(1);
    expect(store!.signatures).toHaveLength(1);
  });

  it('diffJsonKeys detects additions, removals, and modifications', () => {
    const original = { a: 1, b: 2, c: 3 };
    const current = { a: 1, b: 99, d: 4 };
    const diff = _internals.diffJsonKeys(original, current);
    expect(diff.added).toEqual(['d']);
    expect(diff.removed).toEqual(['c']);
    expect(diff.modified).toEqual(['b']);
  });

  it('flattenKeys handles nested objects', () => {
    const keys = _internals.flattenKeys({ a: { b: 1, c: { d: 2 } }, e: 3 });
    expect(keys).toContain('a.b');
    expect(keys).toContain('a.c.d');
    expect(keys).toContain('e');
  });

  it('flattenKeys handles null/primitives', () => {
    expect(_internals.flattenKeys(null)).toEqual(['(root)']);
    expect(_internals.flattenKeys(42)).toEqual(['(root)']);
  });

  // --- Error handling ---

  it('returns 1 for non-existent directory', async () => {
    const { exitCode } = await captureStdout(() => guard({
      subcommand: 'sign',
      targetDir: path.join(tempDir, 'nonexistent'),
      format: 'json',
    }));

    expect(exitCode).toBe(1);
  });

  it('returns 1 for unknown subcommand', async () => {
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;

    const exitCode = await guard({
      subcommand: 'invalid' as any,
      targetDir: tempDir,
      format: 'json',
    });

    process.stderr.write = origStderr;
    expect(exitCode).toBe(1);
    expect(stderrChunks.join('')).toContain('Unknown subcommand');
  });

  it('sign with no config files returns 0', async () => {
    // tempDir has no recognized config files
    const { exitCode, output } = await captureStdout(() => guard({
      subcommand: 'sign',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.signed).toBe(0);
  });

  it('signature store includes correct metadata', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"test"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const store = _internals.loadStore(tempDir)!;
    const sig = store.signatures[0];
    expect(sig.filePath).toBe('package.json');
    expect(sig.hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(sig.signedBy).toContain('@opena2a-cli');
    expect(sig.fileSize).toBeGreaterThan(0);
    expect(new Date(sig.signedAt).getTime()).not.toBeNaN();
  });
});

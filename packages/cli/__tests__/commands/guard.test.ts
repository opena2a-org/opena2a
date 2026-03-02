import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { guard } from '../../src/commands/guard.js';

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
});

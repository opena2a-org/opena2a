import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { _internals, guardHook } from '../../src/commands/guard-hooks.js';

const {
  HOOK_MARKER,
  HOOK_END_MARKER,
  getHookScript,
  installPreCommitHook,
  uninstallPreCommitHook,
  isHookInstalled,
} = _internals;

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

describe('guard-hooks', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-guard-hooks-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  // --- Hook script generation ---

  it('getHookScript contains the marker', () => {
    const script = getHookScript();
    expect(script).toContain(HOOK_MARKER);
    expect(script).toContain(HOOK_END_MARKER);
  });

  it('getHookScript runs guard verify', () => {
    const script = getHookScript();
    expect(script).toContain('npx opena2a guard verify --ci --format text');
  });

  it('getHookScript supports SKIP_GUARD_VERIFY bypass', () => {
    const script = getHookScript();
    expect(script).toContain('SKIP_GUARD_VERIFY');
    expect(script).toContain('skipping config integrity check');
  });

  it('getHookScript checks for signatures.json before running', () => {
    const script = getHookScript();
    expect(script).toContain('.opena2a/guard/signatures.json');
  });

  // --- Install ---

  it('install creates pre-commit hook with correct permissions', () => {
    const gitDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });

    const result = installPreCommitHook(tempDir);
    expect(result.installed).toBe(true);
    expect(result.appended).toBe(false);
    expect(result.path).toBe(path.join(tempDir, '.git', 'hooks', 'pre-commit'));
    expect(result.message).toContain('installed');

    const hookContent = fs.readFileSync(result.path, 'utf-8');
    expect(hookContent).toContain('#!/bin/bash');
    expect(hookContent).toContain(HOOK_MARKER);

    const stat = fs.statSync(result.path);
    // Check executable bit is set (owner execute = 0o100)
    expect(stat.mode & 0o111).toBeGreaterThan(0);
  });

  it('install appends to existing hook without overwriting', () => {
    const hooksDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });

    const existingHook = '#!/bin/bash\necho "existing hook"\n';
    fs.writeFileSync(path.join(hooksDir, 'pre-commit'), existingHook, 'utf-8');
    fs.chmodSync(path.join(hooksDir, 'pre-commit'), 0o755);

    const result = installPreCommitHook(tempDir);
    expect(result.installed).toBe(true);
    expect(result.appended).toBe(true);
    expect(result.message).toContain('appended');

    const hookContent = fs.readFileSync(result.path, 'utf-8');
    // Existing content preserved
    expect(hookContent).toContain('echo "existing hook"');
    // Our hook appended
    expect(hookContent).toContain(HOOK_MARKER);
  });

  it('install updates existing guard hook in place', () => {
    const hooksDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });

    // Install first time
    installPreCommitHook(tempDir);
    const firstContent = fs.readFileSync(path.join(hooksDir, 'pre-commit'), 'utf-8');

    // Install again (should update, not duplicate)
    const result = installPreCommitHook(tempDir);
    expect(result.installed).toBe(true);
    expect(result.appended).toBe(false);
    expect(result.message).toContain('updated');

    const secondContent = fs.readFileSync(result.path, 'utf-8');
    // Should only have one marker occurrence
    const markerCount = (secondContent.match(new RegExp(HOOK_MARKER.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
    expect(markerCount).toBe(1);
  });

  it('install returns error when no .git directory', () => {
    const result = installPreCommitHook(tempDir);
    expect(result.installed).toBe(false);
    expect(result.message).toContain('.git');
  });

  // --- Uninstall ---

  it('uninstall removes our section only', () => {
    const hooksDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });

    // Create hook with foreign content + our hook
    const foreignPart = '#!/bin/bash\necho "other hook"\n';
    const fullHook = foreignPart + '\n' + getHookScript();
    fs.writeFileSync(path.join(hooksDir, 'pre-commit'), fullHook, 'utf-8');

    const removed = uninstallPreCommitHook(tempDir);
    expect(removed).toBe(true);

    const remaining = fs.readFileSync(path.join(hooksDir, 'pre-commit'), 'utf-8');
    expect(remaining).toContain('echo "other hook"');
    expect(remaining).not.toContain(HOOK_MARKER);
  });

  it('uninstall removes file entirely when only our hook exists', () => {
    const hooksDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });

    installPreCommitHook(tempDir);
    expect(fs.existsSync(path.join(hooksDir, 'pre-commit'))).toBe(true);

    const removed = uninstallPreCommitHook(tempDir);
    expect(removed).toBe(true);
    expect(fs.existsSync(path.join(hooksDir, 'pre-commit'))).toBe(false);
  });

  it('uninstall returns false when no hook installed', () => {
    const hooksDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });

    expect(uninstallPreCommitHook(tempDir)).toBe(false);
  });

  // --- isHookInstalled ---

  it('isHookInstalled returns true when installed', () => {
    const hooksDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });

    installPreCommitHook(tempDir);
    expect(isHookInstalled(tempDir)).toBe(true);
  });

  it('isHookInstalled returns false when not installed', () => {
    expect(isHookInstalled(tempDir)).toBe(false);
  });

  // --- CLI handler (guardHook) ---

  it('guardHook install returns 0 on success', async () => {
    const hooksDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });

    const { exitCode, output } = await captureStdout(() => guardHook('install', tempDir));
    expect(exitCode).toBe(0);
    expect(output).toContain('installed');
  });

  it('guardHook uninstall returns 0', async () => {
    const hooksDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });

    const { exitCode } = await captureStdout(() => guardHook('uninstall', tempDir));
    expect(exitCode).toBe(0);
  });

  it('guardHook status reports installation state', async () => {
    const hooksDir = path.join(tempDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });

    // Not installed
    const { output: before } = await captureStdout(() => guardHook('status', tempDir));
    expect(before).toContain('not installed');

    // Install
    installPreCommitHook(tempDir);

    // Installed
    const { output: after } = await captureStdout(() => guardHook('status', tempDir));
    expect(after).toContain('installed');
  });

  it('guardHook returns 1 for unknown action', async () => {
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;

    const exitCode = await guardHook('invalid', tempDir);

    process.stderr.write = origStderr;
    expect(exitCode).toBe(1);
    expect(stderrChunks.join('')).toContain('Unknown hook action');
  });
});

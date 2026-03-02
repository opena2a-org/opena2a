import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as os from 'node:os';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { shield, _internals } from '../../src/commands/shield.js';
import type { ShieldOptions } from '../../src/shield/types.js';

function captureOutput(fn: () => Promise<number>): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const stdoutChunks: string[] = [];
  const stderrChunks: string[] = [];
  const origStdout = process.stdout.write;
  const origStderr = process.stderr.write;

  process.stdout.write = ((chunk: any) => { stdoutChunks.push(String(chunk)); return true; }) as any;
  process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;

  return fn().then(exitCode => {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
    return { exitCode, stdout: stdoutChunks.join(''), stderr: stderrChunks.join('') };
  }).catch(err => {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
    throw err;
  });
}

describe('shield dispatch', () => {
  let tempDir: string;
  let origHome: string | undefined;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shield-cmd-test-'));
    origHome = process.env.HOME;
    process.env.HOME = tempDir;
  });

  afterEach(() => {
    process.env.HOME = origHome;
    vi.restoreAllMocks();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('unknown subcommand returns exit code 1 with error message', async () => {
    const { exitCode, stderr } = await captureOutput(() =>
      shield({ subcommand: 'bogus' as any })
    );
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Unknown shield subcommand');
  });

  it('status returns exit code 0 with Shield Status header', async () => {
    const { exitCode, stdout } = await captureOutput(() =>
      shield({ subcommand: 'status' })
    );
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Shield Status');
  });

  it('log with no events returns exit code 0 with empty message', async () => {
    const { exitCode, stdout } = await captureOutput(() =>
      shield({ subcommand: 'log' })
    );
    expect(exitCode).toBe(0);
    expect(stdout).toContain('No events found');
  });

  it('selfcheck returns 0 or 1 and prints Self-Check header', async () => {
    const { exitCode, stdout } = await captureOutput(() =>
      shield({ subcommand: 'selfcheck' })
    );
    expect([0, 1]).toContain(exitCode);
    expect(stdout).toContain('Shield Self-Check');
  });

  it('recover without flags returns exit code 1 with usage message', async () => {
    const { exitCode, stderr } = await captureOutput(() =>
      shield({ subcommand: 'recover' })
    );
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Usage: opena2a shield recover');
  });

  it('log with json format returns valid JSON (empty array)', async () => {
    const { exitCode, stdout } = await captureOutput(() =>
      shield({ subcommand: 'log', format: 'json' })
    );
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(0);
  });
});

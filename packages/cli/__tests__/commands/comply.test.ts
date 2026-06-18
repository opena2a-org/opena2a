import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runComply, maskValue } from '../../src/commands/comply.js';

function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: unknown) => {
    chunks.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  return fn()
    .then((exitCode) => {
      process.stdout.write = origWrite;
      return { exitCode, output: chunks.join('') };
    })
    .catch((err) => {
      process.stdout.write = origWrite;
      throw err;
    });
}

function captureStderr(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stderr.write;
  process.stderr.write = ((chunk: unknown) => {
    chunks.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  return fn()
    .then((exitCode) => {
      process.stderr.write = origWrite;
      return { exitCode, output: chunks.join('') };
    })
    .catch((err) => {
      process.stderr.write = origWrite;
      throw err;
    });
}

const SSN = '123-45-6789';

describe('comply command', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'comply-test-'));
  });
  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function writeFile(name: string, content: string): string {
    const p = path.join(tmpDir, name);
    fs.writeFileSync(p, content);
    return p;
  }

  it('returns CLEAN (exit 0) for benign content and shows the observation block', async () => {
    const file = writeFile('clean.txt', 'hello world, nothing sensitive here');
    const { exitCode, output } = await captureStdout(() => runComply({ files: [file] }));
    expect(exitCode).toBe(0);
    expect(output).toContain('CLEAN');
    // CISO Rule 11: even a zero-finding verdict states which layers ran.
    expect(output).toContain('regex');
    expect(output).toContain('Verdict: CLEAN');
  });

  it('flags PII (exit 1) and NEVER prints the raw secret', async () => {
    const file = writeFile('pii.txt', `My SSN is ${SSN}`);
    const { exitCode, output } = await captureStdout(() => runComply({ files: [file] }));
    expect(exitCode).toBe(1);
    expect(output).toContain('VIOLATION');
    expect(output).toContain('SSN');
    // The full secret must never reach stdout.
    expect(output).not.toContain(SSN);
  });

  it('emits valid JSON with masked values and no raw secret', async () => {
    const file = writeFile('pii.txt', `SSN ${SSN}`);
    const { exitCode, output } = await captureStdout(() =>
      runComply({ files: [file], format: 'json' }),
    );
    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].verdict).toBe('VIOLATION');
    expect(parsed[0].findings.length).toBeGreaterThan(0);
    expect(parsed[0].findings[0].type).toBe('SSN');
    expect(output).not.toContain(SSN);
    // masked form is present
    expect(parsed[0].findings[0].maskedValue).toContain('•');
  });

  it('--quiet prints only the verdict line', async () => {
    const file = writeFile('pii.txt', `SSN ${SSN}`);
    const { exitCode, output } = await captureStdout(() =>
      runComply({ files: [file], quiet: true }),
    );
    expect(exitCode).toBe(1);
    expect(output.trim()).toBe('VIOLATION');
  });

  it('returns usage error (exit 2) for an unreadable path', async () => {
    const { exitCode, output } = await captureStderr(() =>
      runComply({ files: [path.join(tmpDir, 'nope.txt')] }),
    );
    expect(exitCode).toBe(2);
    expect(output).toContain('cannot read');
  });

  it('aggregates the worst verdict across multiple files', async () => {
    const clean = writeFile('a.txt', 'all good here');
    const dirty = writeFile('b.txt', `card 4111 1111 1111 1111`);
    const { exitCode, output } = await captureStdout(() =>
      runComply({ files: [clean, dirty], quiet: true }),
    );
    expect(exitCode).toBe(1);
    expect(['VIOLATION', 'DENY']).toContain(output.trim());
  });
});

describe('maskValue', () => {
  it('masks short values entirely', () => {
    expect(maskValue('ab')).toBe('••');
    expect(maskValue('')).toBe('•');
  });

  it('keeps a head and short tail but hides the middle, never the full value', () => {
    const secret = 'sk-1234567890abcdef';
    const masked = maskValue(secret);
    expect(masked.startsWith('sk-1')).toBe(true);
    expect(masked).toContain('•');
    expect(masked).not.toBe(secret);
    expect(masked).not.toContain('567890abc');
  });
});

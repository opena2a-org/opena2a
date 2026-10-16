/**
 * `benchmark` on a target it cannot scan must not print a rating.
 *
 * The HardeningScanner resolves on a missing directory instead of throwing, so
 * a mistyped path in a CI step used to print `Rating: Partial` and
 * `L1: 100%` and exit 0: a passing gate over a run that read nothing. A target
 * that does not exist, is not a directory or cannot be read is refused before
 * any scan, with exit 2 (a command error, distinct from findings) and no score
 * on either channel.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

const L1_IDS = ['CRED-002', 'CRED-003', 'CRED-004', 'PERM-001', 'PERM-002'];

const CATEGORIES = [
  {
    id: 5, name: 'Credential Protection', description: '',
    controls: [
      { id: 'C5a', name: 'x', category: 'cred', level: 'L1', scored: true, description: '', checkIds: ['CRED-002', 'CRED-003', 'CRED-004'] },
    ],
  },
  {
    id: 2, name: 'Capability & Authorization', description: '',
    controls: [{ id: 'C2', name: 'x', category: 'cap', level: 'L1', scored: true, description: '', checkIds: ['PERM-001', 'PERM-002'] }],
  },
];

/** Records every scan the command starts, so a refusal can prove none ran. */
const scanner = vi.hoisted(() => ({ scan: vi.fn(async () => ({ findings: [] as unknown[] })) }));
const credentialScan = vi.hoisted(() => ({ calls: 0 }));

vi.mock('hackmyagent', () => ({
  OASB_1_NAME: 'OASB-1',
  OASB_1_VERSION: '1.0',
  OASB_1_CATEGORIES: CATEGORIES,
  getControlsForLevel: (lvl: string) =>
    CATEGORIES.flatMap(c => c.controls).filter(c => (lvl === 'L1' ? c.level === 'L1' : true)),
  getCheckIdsForLevel: () => L1_IDS,
  calculateRating: (l1: number) => (l1 === 100 ? 'Certified' : l1 >= 90 ? 'Passing' : 'Not Passing'),
  HardeningScanner: class {
    scan = scanner.scan;
  },
}));

vi.mock('../../src/util/credential-patterns.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/credential-patterns.js')>();
  return {
    ...actual,
    quickCredentialScan: async () => {
      credentialScan.calls += 1;
      return [];
    },
  };
});

const { benchmark } = await import('../../src/commands/benchmark.js');

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

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(tmpdir(), 'bench-target-'));
  scanner.scan.mockClear();
  credentialScan.calls = 0;
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('benchmark refuses a target it cannot scan', () => {
  it('a missing directory exits 2, names the target and prints no score', async () => {
    const target = path.join(tmp, 'does-not-exist');
    const r = await captureOutput(() => benchmark({ targetDir: target }));

    expect(r.exitCode).toBe(2);
    expect(r.stderr).toBe(
      `opena2a benchmark: ${target} does not exist, so nothing was scanned.\n`
      + `  Verify: ls -ld ${target}\n`,
    );
    expect(r.stdout).not.toContain('Rating:');
    expect(r.stdout).not.toContain('%');
    expect(r.stderr).not.toContain('%');
    expect(scanner.scan).not.toHaveBeenCalled();
    expect(credentialScan.calls).toBe(0);
  });

  it('a relative missing target is shown resolved', async () => {
    const cwd = process.cwd();
    process.chdir(tmp);
    try {
      const r = await captureOutput(() => benchmark({ targetDir: 'typo-dir' }));
      expect(r.exitCode).toBe(2);
      const shown = path.join(process.cwd(), 'typo-dir');
      expect(r.stderr).toContain(`opena2a benchmark: ${shown} does not exist, so nothing was scanned.\n`);
    } finally {
      process.chdir(cwd);
    }
  });

  it('a file exits 2 with the not-a-directory line', async () => {
    const target = path.join(tmp, 'afile');
    fs.writeFileSync(target, 'not a directory\n');
    const r = await captureOutput(() => benchmark({ targetDir: target }));

    expect(r.exitCode).toBe(2);
    expect(r.stderr).toBe(
      `opena2a benchmark: ${target} is not a directory, so nothing was scanned.\n`
      + `  Verify: ls -ld ${target}\n`,
    );
    expect(r.stdout).toBe('');
    expect(scanner.scan).not.toHaveBeenCalled();
  });

  it('a path below a file exits 2 as missing', async () => {
    fs.writeFileSync(path.join(tmp, 'afile'), 'x');
    const target = path.join(tmp, 'afile', 'sub');
    const r = await captureOutput(() => benchmark({ targetDir: target }));

    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain(`opena2a benchmark: ${target} does not exist, so nothing was scanned.\n`);
    expect(scanner.scan).not.toHaveBeenCalled();
  });

  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)(
    'an unreadable directory exits 2 with the could-not-be-read line',
    async () => {
      const target = path.join(tmp, 'locked');
      fs.mkdirSync(target);
      fs.chmodSync(target, 0o000);
      try {
        const r = await captureOutput(() => benchmark({ targetDir: target }));
        expect(r.exitCode).toBe(2);
        expect(r.stderr).toBe(
          `opena2a benchmark: ${target} could not be read, so nothing was scanned.\n`
          + `  Verify: ls -ld ${target}\n`,
        );
        expect(r.stdout).toBe('');
        expect(scanner.scan).not.toHaveBeenCalled();
      } finally {
        fs.chmodSync(target, 0o700);
      }
    },
  );

  it('strips control characters from the target and quotes it in the Verify line', async () => {
    const target = path.join(tmp, 'my dir\x1b[31mx');
    const r = await captureOutput(() => benchmark({ targetDir: target }));

    expect(r.exitCode).toBe(2);
    expect(r.stderr).not.toContain('\x1b');
    const shown = path.join(tmp, 'my dir[31mx');
    expect(r.stderr).toBe(
      `opena2a benchmark: ${shown} does not exist, so nothing was scanned.\n`
      + `  Verify: ls -ld '${shown}'\n`,
    );
  });

  it("quotes an embedded single quote as '\\''", async () => {
    const target = path.join(tmp, "it's");
    const r = await captureOutput(() => benchmark({ targetDir: target }));

    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain(`  Verify: ls -ld '${tmp}/it'\\''s'\n`);
  });

  it('exit 2 does not depend on --ci or the CI environment', async () => {
    const target = path.join(tmp, 'does-not-exist');
    const prev = process.env.CI;
    process.env.CI = 'true';
    try {
      const r = await captureOutput(() => benchmark({ targetDir: target, ci: true }));
      expect(r.exitCode).toBe(2);
      expect(r.stdout).toBe('');
    } finally {
      if (prev === undefined) delete process.env.CI;
      else process.env.CI = prev;
    }
  });

  it('--format json with a missing target exits 2 and writes no stdout document', async () => {
    const target = path.join(tmp, 'does-not-exist');
    const r = await captureOutput(() => benchmark({ targetDir: target, format: 'json' }));

    expect(r.exitCode).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain(`opena2a benchmark: ${target} does not exist, so nothing was scanned.\n`);
    expect(r.stderr).not.toContain('%');
    expect(scanner.scan).not.toHaveBeenCalled();
  });

  it('positive control: an existing empty directory runs past the check', async () => {
    const r = await captureOutput(() => benchmark({ targetDir: tmp }));

    expect(scanner.scan).toHaveBeenCalledTimes(1);
    expect(scanner.scan).toHaveBeenCalledWith({ targetDir: tmp });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Rating:');
    expect(r.stderr).toBe('');
  });
});

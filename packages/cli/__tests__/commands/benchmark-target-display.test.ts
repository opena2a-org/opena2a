/**
 * `benchmark` shell-quotes the target in the commands it suggests and escapes
 * control, bidi and zero-width characters on the Target line and in JSON.
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
    scanCredentialsWithCoverage: async () => {
      credentialScan.calls += 1;
      return { matches: [], filesScanned: 0, placeholdersSkipped: 0, skippedDirs: [] };
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

describe('benchmark prints the target safely', () => {
  it('quotes a path with spaces in every suggested command', async () => {
    const target = path.join(tmp, 'my project');
    fs.mkdirSync(target);
    const r = await captureOutput(() => benchmark({ targetDir: target }));
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain(`Target:     ${target}\n`);
    expect(r.stdout).toContain(`opena2a scan '${target}' --deep`);
    expect(r.stdout).toContain(`opena2a benchmark '${target}' --verbose`);
  });

  it('keeps a plain path bare', async () => {
    const r = await captureOutput(() => benchmark({ targetDir: tmp }));
    expect(r.stdout).toContain(`opena2a benchmark ${tmp} --verbose`);
  });

  it('escapes bidi and control characters on the Target line and in JSON', async () => {
    const target = path.join(tmp, 'a\u202eb\u200bc');
    fs.mkdirSync(target);
    const text = await captureOutput(() => benchmark({ targetDir: target }));
    expect(text.stdout).not.toMatch(/[\u202e\u200b]/);
    expect(text.stdout).toContain('\\u202e');
    expect(text.stdout).toContain('opena2a benchmark <dir> --verbose');

    const json = await captureOutput(() => benchmark({ targetDir: target, format: 'json' }));
    expect(json.stdout).not.toMatch(/[\u202e\u200b]/);
    expect(JSON.parse(json.stdout).target).toBe(target);
  });
});

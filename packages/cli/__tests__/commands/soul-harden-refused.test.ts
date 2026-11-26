import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

async function capture(fn: () => Promise<number>): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const origStdout = process.stdout.write;
  const origStderr = process.stderr.write;
  process.stdout.write = ((chunk: any) => { out.push(String(chunk)); return true; }) as any;
  process.stderr.write = ((chunk: any) => { err.push(String(chunk)); return true; }) as any;
  try {
    const exitCode = await fn();
    return { exitCode, stdout: out.join(''), stderr: err.join('') };
  } finally {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
  }
}

const mockHardenSoul = vi.fn();
vi.mock('hackmyagent', () => ({
  SoulScanner: class {
    scanSoul = vi.fn();
    hardenSoul = mockHardenSoul;
  },
}));

const { hardenSoul } = await import('../../src/commands/soul.js');

describe('harden-soul when the governance write is refused', () => {
  let dir: string;

  beforeEach(() => {
    mockHardenSoul.mockReset();
    dir = mkdtempSync(join(tmpdir(), 'opena2a-soul-refused-'));
    return () => rmSync(dir, { recursive: true, force: true });
  });

  it('does not claim SOUL.md was written, prints Verify and Fix, and exits 1', async () => {
    mockHardenSoul.mockResolvedValue({
      file: 'SOUL.md',
      sectionsAdded: [],
      controlsAdded: 0,
      dryRun: false,
      content: '# SOUL\n',
      existedBefore: false,
      writeRefused: { path: 'SOUL.md', reason: `EACCES: permission denied, open '${dir}/SOUL.md'` },
    });
    const { exitCode, stdout, stderr } = await capture(() => hardenSoul({ targetDir: dir }));
    expect(exitCode).toBe(1);
    expect(stdout).not.toContain('Governance written to');
    expect(stderr).toContain('harden-soul did NOT write SOUL.md');
    expect(stderr).toContain('EACCES');
    expect(stderr).toContain('The file is unchanged');
    expect(stderr).toMatch(/Verify: +ls -ld '/);
    expect(stderr).toMatch(/Fix: +chmod u\+w '[^']*' && opena2a harden-soul '/);
  });

  it('points the chmod at an existing file that refused the append', async () => {
    writeFileSync(join(dir, 'SOUL.md'), '# SOUL\n');
    mockHardenSoul.mockResolvedValue({
      file: 'SOUL.md',
      sectionsAdded: [],
      controlsAdded: 0,
      dryRun: false,
      content: 'x',
      existedBefore: true,
      writeRefused: { path: 'SOUL.md', reason: 'EACCES: permission denied' },
    });
    const { exitCode, stderr } = await capture(() => hardenSoul({ targetDir: dir }));
    expect(exitCode).toBe(1);
    expect(stderr).toMatch(/Fix: +chmod u\+w '[^']*SOUL\.md' && /);
  });

  it('gives a link-replacing Fix when containment refused the write', async () => {
    mockHardenSoul.mockResolvedValue({
      file: 'SOUL.md',
      sectionsAdded: [],
      controlsAdded: 0,
      dryRun: false,
      content: 'x',
      existedBefore: true,
      writeRefused: { path: 'SOUL.md', reason: 'it is a symbolic link that points outside the scanned directory' },
    });
    const { exitCode, stderr } = await capture(() => hardenSoul({ targetDir: dir }));
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Verify:');
    expect(stderr).toMatch(/Fix: +replace '[^']*SOUL\.md' with a regular file/);
  });

  it('strips control characters from the refusal it echoes', async () => {
    mockHardenSoul.mockResolvedValue({
      file: 'SOUL.md',
      sectionsAdded: [],
      controlsAdded: 0,
      dryRun: false,
      content: 'x',
      existedBefore: false,
      writeRefused: { path: 'SOUL\x1b[2J.md', reason: 'EACCES\nGovernance written to: SOUL.md' },
    });
    const { stderr } = await capture(() => hardenSoul({ targetDir: dir }));
    expect(stderr).not.toContain('\x1b');
    expect(stderr).not.toMatch(/^Governance written to/m);
  });

  it('exits 1 in --format json too, with the refusal in the output', async () => {
    mockHardenSoul.mockResolvedValue({
      file: 'SOUL.md',
      sectionsAdded: [],
      controlsAdded: 0,
      dryRun: false,
      content: 'x',
      existedBefore: false,
      writeRefused: { path: 'SOUL.md', reason: 'EACCES' },
    });
    const { exitCode, stdout } = await capture(() => hardenSoul({ targetDir: dir, format: 'json' }));
    expect(exitCode).toBe(1);
    expect(JSON.parse(stdout).writeRefused.reason).toBe('EACCES');
  });

  it('still reports a successful write and exits 0', async () => {
    mockHardenSoul.mockResolvedValue({
      file: 'SOUL.md',
      sectionsAdded: ['Trust Hierarchy'],
      controlsAdded: 3,
      dryRun: false,
      content: 'x',
      existedBefore: false,
    });
    const { exitCode, stdout, stderr } = await capture(() => hardenSoul({ targetDir: dir }));
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Governance written to: SOUL.md');
    expect(stderr).toBe('');
  });
});

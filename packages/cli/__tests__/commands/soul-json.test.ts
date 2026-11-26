import { describe, it, expect, vi, beforeEach } from 'vitest';

async function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; stdout: string }> {
  const chunks: string[] = [];
  const origStdout = process.stdout.write;
  const origStderr = process.stderr.write;
  process.stdout.write = ((chunk: any) => { chunks.push(String(chunk)); return true; }) as any;
  process.stderr.write = (() => true) as any;
  try {
    const exitCode = await fn();
    return { exitCode, stdout: chunks.join('') };
  } finally {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
  }
}

const mockScanSoul = vi.fn();
vi.mock('hackmyagent', () => ({
  SoulScanner: class {
    scanSoul = mockScanSoul;
    hardenSoul = vi.fn();
  },
}));

const { scanSoul } = await import('../../src/commands/soul.js');

describe('scan-soul --json', () => {
  beforeEach(() => {
    mockScanSoul.mockReset();
    mockScanSoul.mockResolvedValue({
      file: 'SOUL.md',
      score: 82,
      grade: 'B',
      level: 'standard',
      conformance: 'standard',
      totalControls: 10,
      totalPassed: 8,
      domains: [],
    });
  });

  it('has no grade key', async () => {
    const { exitCode, stdout } = await captureStdout(() => scanSoul({ targetDir: '/tmp', format: 'json' }));
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    expect(parsed).not.toHaveProperty('grade');
  });

  it('keeps the score and maturity level', async () => {
    const { stdout } = await captureStdout(() => scanSoul({ targetDir: '/tmp', format: 'json' }));
    const parsed = JSON.parse(stdout);
    expect(parsed.score).toBe(82);
    expect(parsed.level).toBe('standard');
    expect(parsed.conformance).toBe('standard');
    expect(parsed.totalPassed).toBe(8);
  });

  it('text output does not fall back to a letter grade when level is absent', async () => {
    mockScanSoul.mockResolvedValue({ score: 82, grade: 'B', totalControls: 1, totalPassed: 1, domains: [] });
    const { stdout } = await captureStdout(() => scanSoul({ targetDir: '/tmp' }));
    expect(stdout).toContain('Governance Score: 82/100 [unknown]');
    expect(stdout).not.toContain('[B]');
  });
});

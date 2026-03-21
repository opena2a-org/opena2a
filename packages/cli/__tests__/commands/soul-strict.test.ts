import { describe, it, expect, vi, beforeEach } from 'vitest';

// Capture helpers
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

// Mock hackmyagent SoulScanner
const mockScanSoul = vi.fn();
vi.mock('hackmyagent', () => {
  return {
    SoulScanner: class {
      scanSoul = mockScanSoul;
    },
  };
});

// Import AFTER mock setup (vi.mock is hoisted)
const { scanSoul } = await import('../../src/commands/soul.js');

describe('scan-soul --strict', () => {
  beforeEach(() => {
    mockScanSoul.mockReset();
  });

  it('fails when critical control SOUL-IH-003 is missing', async () => {
    mockScanSoul.mockResolvedValue({
      score: 80,
      overallScore: 80,
      level: 'B',
      file: 'SOUL.md',
      agentTier: 'STANDARD',
      agentProfile: 'code-assistant',
      totalControls: 10,
      totalPassed: 8,
      domains: [
        {
          domain: 'Identity & Hardening',
          controls: [
            { id: 'SOUL-IH-001', passed: true },
            { id: 'SOUL-IH-002', passed: true },
            { id: 'SOUL-IH-003', passed: false },
          ],
        },
        {
          domain: 'Human Boundaries',
          controls: [
            { id: 'SOUL-HB-001', passed: true },
          ],
        },
      ],
    });

    const { exitCode, stderr } = await captureOutput(() =>
      scanSoul({ strict: true })
    );

    expect(exitCode).toBe(1);
    expect(stderr).toContain('SOUL-IH-003');
    expect(stderr).toContain('critical control(s) missing');
  });

  it('fails when critical control SOUL-HB-001 is missing', async () => {
    mockScanSoul.mockResolvedValue({
      score: 85,
      level: 'B',
      file: 'SOUL.md',
      agentTier: 'STANDARD',
      agentProfile: 'code-assistant',
      totalControls: 10,
      totalPassed: 9,
      domains: [
        {
          domain: 'Identity & Hardening',
          controls: [
            { id: 'SOUL-IH-003', passed: true },
          ],
        },
        {
          domain: 'Human Boundaries',
          controls: [
            { id: 'SOUL-HB-001', passed: false },
          ],
        },
      ],
    });

    const { exitCode, stderr } = await captureOutput(() =>
      scanSoul({ strict: true })
    );

    expect(exitCode).toBe(1);
    expect(stderr).toContain('SOUL-HB-001');
  });

  it('passes when all critical controls are present', async () => {
    mockScanSoul.mockResolvedValue({
      score: 90,
      level: 'A',
      file: 'SOUL.md',
      agentTier: 'STANDARD',
      agentProfile: 'code-assistant',
      totalControls: 10,
      totalPassed: 9,
      domains: [
        {
          domain: 'Identity & Hardening',
          controls: [
            { id: 'SOUL-IH-003', passed: true },
          ],
        },
        {
          domain: 'Human Boundaries',
          controls: [
            { id: 'SOUL-HB-001', passed: true },
          ],
        },
      ],
    });

    const { exitCode } = await captureOutput(() =>
      scanSoul({ strict: true })
    );

    expect(exitCode).toBe(0);
  });

  it('does not fail on missing critical controls without --strict', async () => {
    mockScanSoul.mockResolvedValue({
      score: 80,
      level: 'B',
      file: 'SOUL.md',
      agentTier: 'STANDARD',
      agentProfile: 'code-assistant',
      totalControls: 10,
      totalPassed: 8,
      domains: [
        {
          domain: 'Identity & Hardening',
          controls: [
            { id: 'SOUL-IH-003', passed: false },
          ],
        },
        {
          domain: 'Human Boundaries',
          controls: [
            { id: 'SOUL-HB-001', passed: false },
          ],
        },
      ],
    });

    const { exitCode } = await captureOutput(() =>
      scanSoul({ strict: false })
    );

    // Score is 80, above 60 threshold, so should pass
    expect(exitCode).toBe(0);
  });
});

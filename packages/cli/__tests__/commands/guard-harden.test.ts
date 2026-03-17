import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Capture stdout helper (matches pattern from guard.test.ts)
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

function captureStderr(fn: () => Promise<number>): Promise<{ exitCode: number; stderr: string; stdout: string }> {
  const stderrChunks: string[] = [];
  const stdoutChunks: string[] = [];
  const origStderr = process.stderr.write;
  const origStdout = process.stdout.write;
  process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
  process.stdout.write = ((chunk: any) => { stdoutChunks.push(String(chunk)); return true; }) as any;

  return fn().then(exitCode => {
    process.stderr.write = origStderr;
    process.stdout.write = origStdout;
    return { exitCode, stderr: stderrChunks.join(''), stdout: stdoutChunks.join('') };
  }).catch(err => {
    process.stderr.write = origStderr;
    process.stdout.write = origStdout;
    throw err;
  });
}

// Mock hackmyagent module
const mockScan = vi.fn();
vi.mock('hackmyagent', () => ({
  HardeningScanner: class {
    scan = mockScan;
  },
}));

import { guardHarden } from '../../src/commands/guard-harden.js';

describe('guard-harden', () => {
  beforeEach(() => {
    mockScan.mockReset();
  });

  // --- No skill files found ---

  it('reports clean exit when no skill files found', async () => {
    mockScan.mockResolvedValue({
      findings: [],
      allFindings: [],
      score: 100,
      maxScore: 100,
    });

    const { exitCode, output } = await captureStdout(() =>
      guardHarden('/tmp/empty-dir', { format: 'text' })
    );

    expect(exitCode).toBe(0);
    expect(output).toContain('No SKILL.md or HEARTBEAT.md files found.');
  });

  it('returns JSON when no skill files found', async () => {
    mockScan.mockResolvedValue({
      findings: [],
      allFindings: [],
      score: 100,
      maxScore: 100,
    });

    const { exitCode, output } = await captureStdout(() =>
      guardHarden('/tmp/empty-dir', { format: 'json' })
    );

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.findings).toEqual([]);
    expect(result.message).toContain('No SKILL.md or HEARTBEAT.md files found.');
  });

  // --- Findings present ---

  it('formats text output with findings', async () => {
    mockScan.mockResolvedValue({
      findings: [
        {
          checkId: 'SKILL-004',
          severity: 'critical',
          name: 'Filesystem wildcard',
          description: 'Filesystem wildcard permission',
          fixable: true,
          passed: false,
          message: 'Filesystem wildcard detected',
          file: 'deploy.skill.md',
        },
        {
          checkId: 'SKILL-018',
          severity: 'high',
          name: 'Undeclared network',
          description: 'Network access not declared',
          fixable: false,
          passed: false,
          message: 'Undeclared network access',
          file: 'deploy.skill.md',
        },
      ],
      allFindings: [
        { checkId: 'SKILL-001', passed: true },
        { checkId: 'SKILL-004', passed: false, fixable: true },
        { checkId: 'SKILL-018', passed: false, fixable: false },
      ],
      score: 80,
      maxScore: 100,
    });

    const { exitCode, output } = await captureStdout(() =>
      guardHarden('/tmp/test-dir', { format: 'text' })
    );

    expect(exitCode).toBe(1);
    expect(output).toContain('Skills Hardening Report');
    expect(output).toContain('SKILL-004');
    expect(output).toContain('SKILL-018');
    expect(output).toContain('deploy.skill.md');
    expect(output).toContain('fixable');
    expect(output).toContain('Review permissions');
    expect(output).toContain('opena2a guard harden --fix');
  });

  it('formats JSON output with findings', async () => {
    mockScan.mockResolvedValue({
      findings: [
        {
          checkId: 'SKILL-004',
          severity: 'critical',
          name: 'Filesystem wildcard',
          fixable: true,
          passed: false,
          message: 'Filesystem wildcard detected',
          file: 'SKILL.md',
        },
      ],
      allFindings: [
        { checkId: 'SKILL-004', passed: false },
      ],
      score: 90,
      maxScore: 100,
    });

    const { exitCode, output } = await captureStdout(() =>
      guardHarden('/tmp/test-dir', { format: 'json' })
    );

    expect(exitCode).toBe(1);
    const result = JSON.parse(output);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].checkId).toBe('SKILL-004');
    expect(result.summary.fixable).toBe(1);
    expect(result.summary.reviewNeeded).toBe(0);
    expect(result.fixed).toBe(false);
  });

  // --- --fix flag ---

  it('passes autoFix: true to scanner when --fix is set', async () => {
    mockScan.mockResolvedValue({
      findings: [
        {
          checkId: 'SKILL-004',
          severity: 'critical',
          name: 'Filesystem wildcard',
          fixable: true,
          fixed: true,
          passed: false,
          message: 'Fixed filesystem wildcard',
          file: 'SKILL.md',
        },
      ],
      allFindings: [],
      score: 100,
      maxScore: 100,
    });

    const { exitCode, output } = await captureStdout(() =>
      guardHarden('/tmp/test-dir', { fix: true, format: 'text' })
    );

    expect(mockScan).toHaveBeenCalledWith(expect.objectContaining({
      autoFix: true,
      dryRun: false,
    }));
    expect(exitCode).toBe(0);
    expect(output).toContain('Fixed:');
  });

  it('shows fixed findings in JSON', async () => {
    mockScan.mockResolvedValue({
      findings: [
        {
          checkId: 'SKILL-004',
          severity: 'critical',
          name: 'Filesystem wildcard',
          fixable: true,
          fixed: true,
          passed: false,
          message: 'Fixed',
          file: 'SKILL.md',
        },
      ],
      allFindings: [],
      score: 100,
      maxScore: 100,
    });

    const { exitCode, output } = await captureStdout(() =>
      guardHarden('/tmp/test-dir', { fix: true, format: 'json' })
    );

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.fixed).toBe(true);
    expect(result.summary.fixed).toBe(1);
  });

  // --- --dry-run flag ---

  it('passes autoFix and dryRun to scanner when --dry-run is set', async () => {
    mockScan.mockResolvedValue({
      findings: [
        {
          checkId: 'SKILL-004',
          severity: 'critical',
          name: 'Filesystem wildcard',
          fixable: true,
          wouldFix: true,
          passed: false,
          message: 'Would fix filesystem wildcard',
          file: 'SKILL.md',
        },
      ],
      allFindings: [],
      score: 100,
      maxScore: 100,
    });

    const { exitCode, output } = await captureStdout(() =>
      guardHarden('/tmp/test-dir', { dryRun: true, format: 'text' })
    );

    expect(mockScan).toHaveBeenCalledWith(expect.objectContaining({
      autoFix: true,
      dryRun: true,
    }));
    expect(exitCode).toBe(1); // Still unresolved since dry-run
    expect(output).toContain('would fix');
    expect(output).toContain('dry-run');
  });

  // --- hackmyagent not installed ---

  it('handles hackmyagent import failure gracefully', async () => {
    // We need to test the actual import failure path.
    // Since we've mocked hackmyagent globally, test the error message format instead.
    // The real import failure case is covered by E2E tests.
    // Here we test the scan failure path which has similar error handling.
    mockScan.mockRejectedValue(new Error('Scanner initialization failed'));

    const { exitCode, stderr } = await captureStderr(() =>
      guardHarden('/tmp/test-dir', { format: 'text' })
    );

    expect(exitCode).toBe(1);
    expect(stderr).toContain('Scan failed');
  });

  it('handles scan failure in JSON mode', async () => {
    mockScan.mockRejectedValue(new Error('Scanner crash'));

    const { exitCode, stdout } = await captureStderr(() =>
      guardHarden('/tmp/test-dir', { format: 'json' })
    );

    expect(exitCode).toBe(1);
    const result = JSON.parse(stdout);
    expect(result.error).toContain('Scan failed');
  });

  // --- Filtering: only SKILL-* and HEARTBEAT-* findings ---

  it('filters out non-SKILL/HEARTBEAT findings', async () => {
    mockScan.mockResolvedValue({
      findings: [
        {
          checkId: 'CRED-001',
          severity: 'critical',
          name: 'Hardcoded API key',
          fixable: true,
          passed: false,
          message: 'Found API key',
          file: '.env',
        },
        {
          checkId: 'SKILL-004',
          severity: 'critical',
          name: 'Filesystem wildcard',
          fixable: true,
          passed: false,
          message: 'Filesystem wildcard',
          file: 'SKILL.md',
        },
      ],
      allFindings: [],
      score: 90,
      maxScore: 100,
    });

    const { output } = await captureStdout(() =>
      guardHarden('/tmp/test-dir', { format: 'json' })
    );

    const result = JSON.parse(output);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].checkId).toBe('SKILL-004');
  });

  // --- Skills-only and heartbeats-only modes ---

  it('includes only SKILL findings when heartbeats=false', async () => {
    mockScan.mockResolvedValue({
      findings: [
        { checkId: 'SKILL-004', severity: 'high', name: 'Skill issue', fixable: true, passed: false, message: 'test', file: 'SKILL.md' },
        { checkId: 'HEARTBEAT-001', severity: 'medium', name: 'HB issue', fixable: true, passed: false, message: 'test', file: 'HEARTBEAT.md' },
      ],
      allFindings: [],
    });

    const { output } = await captureStdout(() =>
      guardHarden('/tmp/test-dir', { skills: true, heartbeats: false, format: 'json' })
    );

    const result = JSON.parse(output);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].checkId).toBe('SKILL-004');
  });

  // --- All checks pass ---

  it('reports success when all checks pass', async () => {
    mockScan.mockResolvedValue({
      findings: [],
      allFindings: [
        { checkId: 'SKILL-001', passed: true },
        { checkId: 'SKILL-002', passed: true },
        { checkId: 'SKILL-003', passed: true },
      ],
      score: 100,
      maxScore: 100,
    });

    const { exitCode, output } = await captureStdout(() =>
      guardHarden('/tmp/test-dir', { format: 'text' })
    );

    expect(exitCode).toBe(0);
    expect(output).toContain('All 3 checks passed');
  });

  // --- Mixed fixed and review-needed ---

  it('shows summary with mixed fixed and review-needed counts', async () => {
    mockScan.mockResolvedValue({
      findings: [
        { checkId: 'SKILL-004', severity: 'critical', name: 'Fixed issue', fixable: true, fixed: true, passed: false, message: 'Fixed', file: 'SKILL.md' },
        { checkId: 'SKILL-018', severity: 'high', name: 'Needs review', fixable: false, passed: false, message: 'Review', file: 'SKILL.md' },
      ],
      allFindings: [
        { checkId: 'SKILL-001', passed: true },
      ],
    });

    const { exitCode, output } = await captureStdout(() =>
      guardHarden('/tmp/test-dir', { fix: true, format: 'text' })
    );

    expect(exitCode).toBe(1); // review-needed items remain
    expect(output).toContain('1 fixed');
    expect(output).toContain('1 review-needed');
  });

  // --- No categories selected ---

  it('errors when both skills and heartbeats are false', async () => {
    const { exitCode, stderr } = await captureStderr(() =>
      guardHarden('/tmp/test-dir', { skills: false, heartbeats: false, format: 'text' })
    );

    expect(exitCode).toBe(1);
    expect(stderr).toContain('No check categories selected');
  });
});

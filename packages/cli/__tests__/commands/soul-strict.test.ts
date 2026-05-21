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

describe('scan-soul partial-scope disclosure (#136)', () => {
  beforeEach(() => {
    mockScanSoul.mockReset();
  });

  it('downgrades [hardened] to [partial-hardened] when domains were skipped', async () => {
    mockScanSoul.mockResolvedValue({
      score: 100,
      level: 'hardened',
      file: 'SOUL.md',
      agentTier: 'TOOL-USING',
      agentProfile: 'conversational',
      totalControls: 26,
      totalPassed: 26,
      skippedDomains: ['Trust Hierarchy', 'Capability Boundaries', 'Data Handling', 'Agentic Safety', 'Human Oversight'],
      domains: [
        { domain: 'Trust Hierarchy', controls: [], skippedByProfile: true },
        { domain: 'Capability Boundaries', controls: [], skippedByProfile: true },
        { domain: 'Injection Hardening', controls: [{ id: 'SOUL-IH-001', passed: true }] },
        { domain: 'Data Handling', controls: [], skippedByProfile: true },
        { domain: 'Hardcoded Behaviors', controls: [{ id: 'SOUL-HB-001', passed: true }] },
        { domain: 'Agentic Safety', controls: [], skippedByProfile: true },
        { domain: 'Honesty and Transparency', controls: [{ id: 'SOUL-HT-001', passed: true }] },
        { domain: 'Human Oversight', controls: [], skippedByProfile: true },
        { domain: 'Harm Avoidance', controls: [{ id: 'SOUL-HA-001', passed: true }] },
      ],
    });

    const { exitCode, stdout } = await captureOutput(() => scanSoul({ strict: false }));

    expect(exitCode).toBe(0);
    expect(stdout).not.toContain('[hardened]');
    expect(stdout).toContain('[partial-hardened]');
    expect(stdout).toContain('Scope:');
    expect(stdout).toContain('4 of 9 domains evaluated');
    expect(stdout).toContain('5 skipped');
    expect(stdout).toContain('Trust Hierarchy');
    expect(stdout).toContain('Capability Boundaries');
  });

  it('surfaces profile-mismatch as HIGH SOUL-PROFILE-MISMATCH finding', async () => {
    mockScanSoul.mockResolvedValue({
      score: 100,
      level: 'hardened',
      file: 'SOUL.md',
      agentTier: 'TOOL-USING',
      agentProfile: 'conversational',
      totalControls: 26,
      totalPassed: 26,
      skippedDomains: ['Trust Hierarchy', 'Capability Boundaries'],
      profileMismatch: {
        declaredProfile: 'conversational',
        inferredProfile: 'autonomous',
        signals: ['"Agentic Safety" heading', '"Capability Boundaries" heading', 'tool execution verb'],
        skippedDomains: ['Trust Hierarchy', 'Capability Boundaries'],
      },
      domains: [],
    });

    const { stdout } = await captureOutput(() => scanSoul({ strict: false }));

    // Severity + checkId match HMA's direct render so the wrapper signal
    // strength matches `hackmyagent scan-soul` direct.
    expect(stdout).toContain('HIGH');
    expect(stdout).toContain('SOUL-PROFILE-MISMATCH');
    expect(stdout).toContain('Declared profile=conversational');
    expect(stdout).toContain('body suggests profile=autonomous');
    expect(stdout).toContain('Signals:');
    expect(stdout).toContain('Skipped domains: Trust Hierarchy, Capability Boundaries');
    expect(stdout).toContain('remove the <!-- soul:profile=conversational --> marker');
  });

  it('#136 C1: detects partial scope from domains[].skippedByProfile when skippedDomains is empty', async () => {
    // Bypass class: an HMA build that populates per-domain skippedByProfile
    // flags but does NOT populate the top-level `skippedDomains` array
    // would still get [hardened] under the v1 gate. The fix derives from
    // BOTH sources.
    mockScanSoul.mockResolvedValue({
      score: 100,
      level: 'hardened',
      file: 'SOUL.md',
      agentTier: 'TOOL-USING',
      agentProfile: 'conversational',
      totalControls: 26,
      totalPassed: 26,
      // Top-level array intentionally empty/missing.
      domains: [
        { domain: 'Trust Hierarchy', controls: [], skippedByProfile: true },
        { domain: 'Capability Boundaries', controls: [], skippedByProfile: true },
        { domain: 'Injection Hardening', controls: [{ id: 'SOUL-IH-001', passed: true }] },
      ],
    });

    const { stdout } = await captureOutput(() => scanSoul({ strict: false }));

    expect(stdout).toContain('[partial-hardened]');
    expect(stdout).toContain('Trust Hierarchy');
    expect(stdout).toContain('Capability Boundaries');
  });

  it('#136 H1: downgrades uppercase / mixed-case level labels', async () => {
    mockScanSoul.mockResolvedValue({
      score: 100,
      level: 'HARDENED',
      file: 'SOUL.md',
      agentTier: 'TOOL-USING',
      agentProfile: 'conversational',
      totalControls: 26,
      totalPassed: 26,
      skippedDomains: ['Trust Hierarchy'],
      domains: [{ domain: 'Trust Hierarchy', controls: [], skippedByProfile: true }],
    });

    const { stdout } = await captureOutput(() => scanSoul({ strict: false }));
    expect(stdout).toContain('[partial-hardened]');
    expect(stdout).not.toContain('[HARDENED]');
  });

  it('#136 H1: downgrades other absolute labels (standard, developing) on partial scope', async () => {
    mockScanSoul.mockResolvedValue({
      score: 75,
      level: 'standard',
      file: 'SOUL.md',
      agentTier: 'TOOL-USING',
      agentProfile: 'conversational',
      totalControls: 26,
      totalPassed: 20,
      skippedDomains: ['Trust Hierarchy'],
      domains: [{ domain: 'Trust Hierarchy', controls: [], skippedByProfile: true }],
    });

    const { stdout } = await captureOutput(() => scanSoul({ strict: false }));
    expect(stdout).toContain('[partial-standard]');
    expect(stdout).not.toContain('[standard]');
  });

  it('#136: does NOT downgrade non-assertive labels (initial / not-started)', async () => {
    mockScanSoul.mockResolvedValue({
      score: 0,
      level: 'not-started',
      file: 'SOUL.md',
      agentTier: 'TOOL-USING',
      agentProfile: 'conversational',
      totalControls: 26,
      totalPassed: 0,
      skippedDomains: ['Trust Hierarchy'],
      domains: [{ domain: 'Trust Hierarchy', controls: [], skippedByProfile: true }],
    });

    const { stdout } = await captureOutput(() => scanSoul({ strict: false }));
    expect(stdout).toContain('[not-started]');
    expect(stdout).not.toContain('[partial-not-started]');
  });

  it('#136 M2: defends against negative evaluated count when domains array is empty', async () => {
    mockScanSoul.mockResolvedValue({
      score: 100,
      level: 'hardened',
      file: 'SOUL.md',
      agentTier: 'TOOL-USING',
      agentProfile: 'conversational',
      totalControls: 26,
      totalPassed: 26,
      skippedDomains: ['Trust Hierarchy', 'Capability Boundaries'],
      domains: [],
    });

    const { stdout } = await captureOutput(() => scanSoul({ strict: false }));
    // Total domains falls back to max(skipped.length, 9). evaluated = max(0, total-skipped).
    expect(stdout).toMatch(/Scope:\s+\d+ of \d+ domains evaluated/);
    expect(stdout).not.toMatch(/-\d+ of/);
  });

  it('keeps unconditional [hardened] when no domains were skipped (no regression)', async () => {
    mockScanSoul.mockResolvedValue({
      score: 100,
      level: 'hardened',
      file: 'SOUL.md',
      agentTier: 'STANDARD',
      agentProfile: 'custom',
      totalControls: 29,
      totalPassed: 29,
      domains: [
        { domain: 'Trust Hierarchy', controls: [{ id: 'SOUL-TH-001', passed: true }] },
      ],
    });

    const { stdout } = await captureOutput(() => scanSoul({ strict: false }));

    expect(stdout).toContain('[hardened]');
    expect(stdout).not.toContain('[partial-hardened]');
    expect(stdout).not.toContain('Scope:');
    expect(stdout).not.toContain('WARNING');
  });
});

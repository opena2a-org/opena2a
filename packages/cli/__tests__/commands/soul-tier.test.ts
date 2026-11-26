import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

async function capture(fn: () => Promise<number>): Promise<{ exitCode: number; stderr: string }> {
  const chunks: string[] = [];
  const origStdout = process.stdout.write;
  const origStderr = process.stderr.write;
  process.stdout.write = (() => true) as any;
  process.stderr.write = ((chunk: any) => { chunks.push(String(chunk)); return true; }) as any;
  try {
    const exitCode = await fn();
    return { exitCode, stderr: chunks.join('') };
  } finally {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
  }
}

const mockScanSoul = vi.fn();
const mockHardenSoul = vi.fn();
vi.mock('hackmyagent', () => ({
  SoulScanner: class {
    scanSoul = mockScanSoul;
    hardenSoul = mockHardenSoul;
  },
}));

const { scanSoul, hardenSoul, SOUL_TIERS } = await import('../../src/commands/soul.js');

describe('scan-soul / harden-soul --tier', () => {
  beforeEach(() => {
    mockScanSoul.mockReset();
    mockHardenSoul.mockReset();
    mockScanSoul.mockResolvedValue({ score: 80, totalControls: 1, totalPassed: 1, domains: [] });
    mockHardenSoul.mockResolvedValue({});
  });

  it('knows exactly the engine tiers', () => {
    expect([...SOUL_TIERS]).toEqual(['BASIC', 'TOOL-USING', 'AGENTIC', 'MULTI-AGENT']);
  });

  it('rejects an unknown tier before scanning, with a nonzero exit', async () => {
    const { exitCode, stderr } = await capture(() => scanSoul({ targetDir: '/tmp', tier: 'STANDARD' }));
    expect(exitCode).toBe(1);
    expect(stderr).toContain('unknown tier "STANDARD"');
    expect(stderr).toContain('BASIC, TOOL-USING, AGENTIC, MULTI-AGENT');
    expect(mockScanSoul).not.toHaveBeenCalled();
  });

  it('rejects an unknown tier for harden-soul too', async () => {
    const { exitCode } = await capture(() => hardenSoul({ targetDir: '/tmp', tier: 'STANDARD' }));
    expect(exitCode).toBe(1);
    expect(mockHardenSoul).not.toHaveBeenCalled();
  });

  it.each(['BASIC', 'TOOL-USING', 'AGENTIC', 'MULTI-AGENT'])('passes the engine tier %s through', async (tier) => {
    const { exitCode } = await capture(() => scanSoul({ targetDir: '/tmp', tier }));
    expect(exitCode).toBe(0);
    expect(mockScanSoul).toHaveBeenCalledWith('/tmp', expect.objectContaining({ tier }));
  });

  it('accepts a tier in any case and passes it upper-cased', async () => {
    await capture(() => scanSoul({ targetDir: '/tmp', tier: 'tool-using' }));
    expect(mockScanSoul).toHaveBeenCalledWith('/tmp', expect.objectContaining({ tier: 'TOOL-USING' }));
  });

  it('leaves the tier to detection when --tier is not given', async () => {
    await capture(() => scanSoul({ targetDir: '/tmp' }));
    expect(mockScanSoul).toHaveBeenCalledWith('/tmp', expect.objectContaining({ tier: undefined }));
  });

  it('--help lists the four engine tiers and not STANDARD', () => {
    const src = readFileSync(resolve(__dirname, '../../src/index.ts'), 'utf-8');
    const tierOptions = src.match(/\.option\('--tier <level>', '[^']*'\)/g) ?? [];
    expect(tierOptions.length).toBeGreaterThanOrEqual(2);
    for (const opt of tierOptions) {
      expect(opt).toContain('BASIC|TOOL-USING|AGENTIC|MULTI-AGENT');
      expect(opt).not.toContain('STANDARD');
    }
  });

  it('help texts name the governance spec by one acronym, ABGS', () => {
    const src = readFileSync(resolve(__dirname, '../../src/index.ts'), 'utf-8');
    expect(src).toContain('(ABGS)');
    expect(src).not.toMatch(/\bAGS\b/);
  });
});

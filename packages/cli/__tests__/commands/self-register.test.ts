import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { TOOL_MANIFEST, checkPackageExists, selfRegister } from '../../src/commands/self-register.js';
import type { SelfRegisterOptions } from '../../src/commands/self-register.js';

// Mock global fetch
const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('TOOL_MANIFEST', () => {
  it('contains all 11 tools with required fields', () => {
    expect(TOOL_MANIFEST).toHaveLength(11);

    const names = TOOL_MANIFEST.map(t => t.name);
    expect(new Set(names).size).toBe(11); // no duplicates

    for (const tool of TOOL_MANIFEST) {
      expect(tool.name).toBeTruthy();
      expect(tool.displayName).toBeTruthy();
      expect(tool.description).toBeTruthy();
      expect(['ai_tool', 'mcp_server', 'a2a_agent']).toContain(tool.packageType);
      expect(tool.version).toMatch(/^\d+\.\d+\.\d+/);
      expect(tool.repositoryUrl).toMatch(/^https:\/\//);
      expect(tool.license).toBeTruthy();
      expect(Array.isArray(tool.tags)).toBe(true);
      expect(tool.tags.length).toBeGreaterThan(0);
      expect(typeof tool.scannable).toBe('boolean');
    }
  });

  it('has 6 scannable and 5 non-scannable tools', () => {
    const scannable = TOOL_MANIFEST.filter(t => t.scannable);
    const nonScannable = TOOL_MANIFEST.filter(t => !t.scannable);

    expect(scannable).toHaveLength(6);
    expect(nonScannable).toHaveLength(5);
  });

  it('scannable tools have npmPackage field', () => {
    for (const tool of TOOL_MANIFEST.filter(t => t.scannable)) {
      expect(tool.npmPackage).toBeTruthy();
    }
  });
});

describe('checkPackageExists', () => {
  it('returns exists: true when registry returns 200', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: 'pkg-123' }),
    });

    const result = await checkPackageExists('https://test-registry.example.com', TOOL_MANIFEST[0]);

    expect(result.exists).toBe(true);
    expect(result.packageId).toBe('pkg-123');
    expect(mockFetch).toHaveBeenCalledOnce();
  });

  it('returns exists: false when registry returns 404', async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 404,
    });

    const result = await checkPackageExists('https://test-registry.example.com', TOOL_MANIFEST[0]);

    expect(result.exists).toBe(false);
    expect(result.packageId).toBeUndefined();
  });

  it('returns exists: false on network error', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));

    const result = await checkPackageExists('https://test-registry.example.com', TOOL_MANIFEST[0]);

    expect(result.exists).toBe(false);
  });
});

describe('selfRegister', () => {
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

  it('dry-run mode produces output without HTTP requests', async () => {
    const options: SelfRegisterOptions = {
      dryRun: true,
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => selfRegister(options));

    expect(exitCode).toBe(0);
    expect(mockFetch).not.toHaveBeenCalled();

    const report = JSON.parse(output);
    expect(report.total).toBe(11);
    expect(report.tools).toHaveLength(11);
  });

  it('--only filters to specified tools', async () => {
    const options: SelfRegisterOptions = {
      dryRun: true,
      ci: true,
      format: 'json',
      only: ['hackmyagent', 'dvaa'],
    };

    const { exitCode, output } = await captureStdout(() => selfRegister(options));

    expect(exitCode).toBe(0);

    const report = JSON.parse(output);
    expect(report.total).toBe(2);
    expect(report.tools).toHaveLength(2);

    const names = report.tools.map((t: any) => t.name);
    expect(names).toContain('hackmyagent');
    expect(names).toContain('dvaa');
  });

  it('CI JSON output produces valid JSON with all fields', async () => {
    const options: SelfRegisterOptions = {
      dryRun: true,
      ci: true,
      format: 'json',
    };

    const { output } = await captureStdout(() => selfRegister(options));

    const report = JSON.parse(output);
    expect(report).toHaveProperty('registryUrl');
    expect(report).toHaveProperty('timestamp');
    expect(report).toHaveProperty('total');
    expect(report).toHaveProperty('scanned');
    expect(report).toHaveProperty('metadataOnly');
    expect(report).toHaveProperty('errors');
    expect(report).toHaveProperty('tools');
    expect(typeof report.registryUrl).toBe('string');
    expect(typeof report.timestamp).toBe('string');
  });

  it('--skip-scan skips HMA and registers metadata only', async () => {
    // Mock successful token + submit for all tools
    mockFetch.mockImplementation(async (url: string) => {
      if (String(url).includes('by-name')) {
        return { ok: false, status: 404 };
      }
      if (String(url).includes('request-scan-token')) {
        return { ok: true, json: async () => ({ scanToken: 'tok-123' }) };
      }
      if (String(url).includes('scan-result')) {
        return { ok: true, json: async () => ({ status: 'accepted' }) };
      }
      return { ok: false, status: 500 };
    });

    const options: SelfRegisterOptions = {
      skipScan: true,
      ci: true,
      format: 'json',
      only: ['hackmyagent'],
    };

    const { output } = await captureStdout(() => selfRegister(options));

    const report = JSON.parse(output);
    const tool = report.tools[0];
    expect(tool.scanStatus).toBe('skipped');
    expect(tool.publishType).toBe('metadata');
  });

  it('individual tool failure does not stop processing', async () => {
    let callCount = 0;
    mockFetch.mockImplementation(async (url: string) => {
      callCount++;
      if (String(url).includes('by-name')) {
        // First tool errors, second succeeds
        if (callCount === 1) throw new Error('Network timeout');
        return { ok: false, status: 404 };
      }
      if (String(url).includes('request-scan-token')) {
        return { ok: true, json: async () => ({ scanToken: 'tok-123' }) };
      }
      if (String(url).includes('scan-result')) {
        return { ok: true, json: async () => ({ status: 'accepted' }) };
      }
      return { ok: false, status: 500 };
    });

    const options: SelfRegisterOptions = {
      skipScan: true,
      ci: true,
      format: 'json',
      only: ['hackmyagent', 'dvaa'],
    };

    const { output } = await captureStdout(() => selfRegister(options));

    const report = JSON.parse(output);
    expect(report.tools).toHaveLength(2);
    // Both tools should be processed even if one had an error during existence check
    // (checkPackageExists handles errors gracefully, returning exists: false)
  });

  it('returns 1 when --only specifies unknown tools', async () => {
    const options: SelfRegisterOptions = {
      ci: true,
      format: 'json',
      only: ['nonexistent-tool'],
    };

    const { exitCode, output } = await captureStdout(() => selfRegister(options));

    expect(exitCode).toBe(1);
    const result = JSON.parse(output);
    expect(result.error).toBeTruthy();
  });
});

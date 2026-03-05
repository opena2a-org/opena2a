import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { verify, _internals } from '../../src/commands/verify.js';
import type { VerifyOptions } from '../../src/commands/verify.js';

// Mock global fetch
const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

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

describe('verify', () => {
  it('returns 0 when registry reports verified', async () => {
    vi.spyOn(_internals, 'resolvePackagePath').mockReturnValue({
      mainFile: __filename,
      version: '0.7.2',
    });

    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        contentVerification: { status: 'verified' },
      }),
    });

    const options: VerifyOptions = {
      packageName: 'hackmyagent',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => verify(options));

    expect(exitCode).toBe(0);
    const report = JSON.parse(output);
    expect(report.packages).toHaveLength(1);
    expect(report.packages[0].registryStatus).toBe('verified');
    expect(report.verified).toBe(1);
  });

  it('returns 1 when registry reports tamper_detected', async () => {
    vi.spyOn(_internals, 'resolvePackagePath').mockReturnValue({
      mainFile: __filename,
      version: '0.7.2',
    });

    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        contentVerification: { status: 'tamper_detected' },
      }),
    });

    const options: VerifyOptions = {
      packageName: 'hackmyagent',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => verify(options));

    expect(exitCode).toBe(1);
    const report = JSON.parse(output);
    expect(report.packages[0].registryStatus).toBe('tamper_detected');
    expect(report.tamperDetected).toBe(1);
  });

  it('gracefully handles package not installed locally', async () => {
    vi.spyOn(_internals, 'resolvePackagePath').mockImplementation(() => {
      throw new Error('Cannot find module');
    });

    const options: VerifyOptions = {
      packageName: 'nonexistent-package',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => verify(options));

    expect(exitCode).toBe(0);
    const report = JSON.parse(output);
    expect(report.packages[0].registryStatus).toBe('not_installed');
    expect(report.notInstalled).toBe(1);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('produces valid JSON output with all fields', async () => {
    vi.spyOn(_internals, 'resolvePackagePath').mockReturnValue({
      mainFile: __filename,
      version: '0.7.2',
    });

    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        contentVerification: { status: 'verified' },
      }),
    });

    const options: VerifyOptions = {
      packageName: 'hackmyagent',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { output } = await captureStdout(() => verify(options));

    const report = JSON.parse(output);
    expect(report).toHaveProperty('registryUrl');
    expect(report).toHaveProperty('timestamp');
    expect(report).toHaveProperty('total');
    expect(report).toHaveProperty('verified');
    expect(report).toHaveProperty('tamperDetected');
    expect(report).toHaveProperty('noData');
    expect(report).toHaveProperty('notInstalled');
    expect(report).toHaveProperty('packages');
    expect(typeof report.registryUrl).toBe('string');
    expect(typeof report.timestamp).toBe('string');

    const pkg = report.packages[0];
    expect(pkg).toHaveProperty('packageName');
    expect(pkg).toHaveProperty('version');
    expect(pkg).toHaveProperty('localHash');
    expect(pkg).toHaveProperty('registryStatus');
  });

  it('returns no_data when registry returns non-200', async () => {
    vi.spyOn(_internals, 'resolvePackagePath').mockReturnValue({
      mainFile: __filename,
      version: '0.7.2',
    });

    mockFetch.mockResolvedValue({
      ok: false,
      status: 404,
    });

    const options: VerifyOptions = {
      packageName: 'hackmyagent',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => verify(options));

    expect(exitCode).toBe(0);
    const report = JSON.parse(output);
    expect(report.packages[0].registryStatus).toBe('no_data');
  });
});

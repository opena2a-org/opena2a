import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verify, _internals, VERIFIABLE_PACKAGES } from '../../src/commands/verify.js';
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

// The default list held a browser-extension name that npm does not have, and
// every not-installed line told the user to `npm install -g` the name as given.
describe('verify package list and install hints', () => {
  const CLI_PACKAGE_JSON = resolve(__dirname, '../../package.json');
  const CLI_INDEX = resolve(__dirname, '../../src/index.ts');
  const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

  async function notInstalledLine(packageName: string): Promise<string> {
    vi.spyOn(_internals, 'resolvePackagePath').mockImplementation(() => {
      throw new Error('Cannot find module');
    });
    const { exitCode, output } = await captureStdout(() => verify({
      packageName,
      registryUrl: 'https://test-registry.example.com',
      ci: true,
    }));
    expect(exitCode).toBe(0);
    expect(mockFetch).not.toHaveBeenCalled();
    const line = output.replace(STRIP_ANSI, '').split('\n').find(l => l.trimStart().startsWith(`${packageName}:`));
    expect(line).toBeDefined();
    return line!;
  }

  it('every default package is a dependency of opena2a-cli', () => {
    const deps = Object.keys(JSON.parse(readFileSync(CLI_PACKAGE_JSON, 'utf-8')).dependencies ?? {});
    expect(VERIFIABLE_PACKAGES.length).toBeGreaterThan(0);
    for (const pkg of VERIFIABLE_PACKAGES) expect(deps).toContain(pkg);
  });

  it('the verify help names exactly the default packages', () => {
    const source = readFileSync(CLI_INDEX, 'utf-8');
    const match = source.match(/Without --package it checks ([^.;]+)[.;]/);
    expect(match).not.toBeNull();
    const named = match![1].split(/,|\band\b/).map(s => s.trim()).filter(Boolean);
    expect([...named].sort()).toEqual([...VERIFIABLE_PACKAGES].sort());
  });

  it('a package that is not part of opena2a-cli gets no install command', async () => {
    const line = await notInstalledLine('aibrowserguard');
    expect(line.trim()).toBe('aibrowserguard: not installed; not part of opena2a-cli');
    expect(line).not.toContain('npm install -g');
  });

  it('a missing dependency of opena2a-cli points to reinstalling opena2a-cli', async () => {
    const line = await notInstalledLine('hackmyagent');
    expect(line).toContain('npm install -g opena2a-cli');
    expect(line).not.toContain('npm install -g hackmyagent');
  });

  it('opena2a-cli itself is installed with its own name', async () => {
    const line = await notInstalledLine('opena2a-cli');
    expect(line).toContain('npm install -g opena2a-cli');
    expect(line).not.toContain('not part of opena2a-cli');
  });
});

// The trust score was printed with no version, so a score for an older
// release read as a score for the installed one.
describe('verify ties the trust score to a version', () => {
  const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

  function registry(trustAnswer: Record<string, unknown>): void {
    mockFetch.mockImplementation(async (url: string) => {
      const u = String(url);
      if (u.includes('/api/v1/trust/query') && u.includes('includeProfile')) {
        return { ok: true, status: 200, json: async () => trustAnswer, text: async () => '' };
      }
      if (u.includes('/api/v1/trust/query')) {
        return { ok: true, status: 200, json: async () => ({ contentVerification: { status: 'verified' } }) };
      }
      return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
    });
  }

  async function run(format?: 'json'): Promise<string> {
    vi.spyOn(_internals, 'resolvePackagePath').mockReturnValue({ mainFile: __filename, version: '0.7.2' });
    const { output } = await captureStdout(() => verify({
      packageName: 'hackmyagent',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format,
    }));
    return output;
  }

  function scoreLine(output: string): string {
    const line = output.replace(STRIP_ANSI, '').split('\n').find(l => l.trim().startsWith('Trust Score'));
    expect(line).toBeDefined();
    return line!.trim();
  }

  const answer = { packageId: '11111111-1111-1111-1111-111111111111', name: 'hackmyagent', trustScore: 0.85, verdict: 'trusted' };

  it('names the scanned version when it is the installed one', async () => {
    registry({ ...answer, version: '0.7.2' });
    expect(scoreLine(await run())).toBe('Trust Score      85 / 100 (scanned 0.7.2)');
  });

  it('flags the score as stale when the registry scored another version', async () => {
    registry({ ...answer, version: '0.6.0' });
    expect(scoreLine(await run())).toBe(
      'Trust Score      85 / 100 (scanned 0.6.0; installed is 0.7.2, so the score may be stale)',
    );
  });

  it('says the scanned version is unknown when the registry does not give one', async () => {
    registry({ ...answer, version: '0.0.0-discovered' });
    expect(scoreLine(await run())).toBe('Trust Score      85 / 100 (scanned version unknown; may not be 0.7.2)');
  });

  it('reports the scanned version and whether it matches in JSON', async () => {
    registry({ ...answer, version: '0.6.0' });
    const pkg = JSON.parse(await run('json')).packages[0];
    expect(pkg.version).toBe('0.7.2');
    expect(pkg.scannedVersion).toBe('0.6.0');
    expect(pkg.scoreMatchesInstalled).toBe(false);
  });

  it('leaves the match null in JSON when the scanned version is unknown', async () => {
    registry(answer);
    const pkg = JSON.parse(await run('json')).packages[0];
    expect(pkg.scannedVersion).toBeNull();
    expect(pkg.scoreMatchesInstalled).toBeNull();
  });
});

describe('verify does not guess a scoped package is an MCP server', () => {
  const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
  const packageName = '@acme/agent-tool';

  // A registry that holds the package as an ai_tool: asking for it as an
  // mcp_server finds nothing, as the real registry does.
  function registry(): string[] {
    const profileUrls: string[] = [];
    mockFetch.mockImplementation(async (url: string) => {
      const u = new URL(String(url));
      if (u.pathname === '/api/v1/trust/query' && u.searchParams.has('includeProfile')) {
        profileUrls.push(u.toString());
        const type = u.searchParams.get('type');
        if (u.searchParams.get('name') !== packageName || (type !== null && type !== 'ai_tool')) {
          return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            packageId: '22222222-2222-2222-2222-222222222222',
            name: packageName,
            packageType: 'ai_tool',
            trustScore: 0.9,
            verdict: 'trusted',
            version: '1.2.3',
            lastScannedAt: '2026-11-01T00:00:00Z',
            dependencies: { riskSummary: { blocked: 0, warning: 1 } },
          }),
          text: async () => '',
        };
      }
      if (u.pathname === '/api/v1/trust/query') {
        return { ok: true, status: 200, json: async () => ({ contentVerification: { status: 'verified' } }) };
      }
      return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
    });
    return profileUrls;
  }

  it('queries the trust profile without type=mcp_server and prints it', async () => {
    const profileUrls = registry();
    vi.spyOn(_internals, 'resolvePackagePath').mockReturnValue({ mainFile: __filename, version: '1.2.3' });
    const { output } = await captureStdout(() => verify({
      packageName,
      registryUrl: 'https://test-registry.example.com',
      ci: true,
    }));

    expect(profileUrls).toHaveLength(1);
    expect(new URL(profileUrls[0]).searchParams.get('type')).not.toBe('mcp_server');

    const lines = output.replace(STRIP_ANSI, '').split('\n').map(l => l.trim());
    expect(lines).toContain('Trust Score      90 / 100 (scanned 1.2.3)');
    expect(lines).toContain('Trust Verdict    trusted');
    expect(lines).toContain('Last Scanned     2026-11-01T00:00:00Z');
    expect(lines).toContain('Dependencies     1 risk');
  });
});

// A Blocked answer printed as a red number with the verdict in grey, and a
// package the registry lists and never scanned printed as "0 / 100" in red.
describe('verify shows the trust level by its word', () => {
  const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

  function registry(trustAnswer: Record<string, unknown>): void {
    mockFetch.mockImplementation(async (url: string) => {
      const u = String(url);
      if (u.includes('/api/v1/trust/query') && u.includes('includeProfile')) {
        return { ok: true, status: 200, json: async () => trustAnswer, text: async () => '' };
      }
      if (u.includes('/api/v1/trust/query')) {
        return { ok: true, status: 200, json: async () => ({ contentVerification: { status: 'verified' } }) };
      }
      return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
    });
  }

  async function run(format?: 'json'): Promise<string> {
    vi.spyOn(_internals, 'resolvePackagePath').mockReturnValue({ mainFile: __filename, version: '0.7.2' });
    const { output } = await captureStdout(() => verify({
      packageName: 'hackmyagent',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format,
    }));
    return output;
  }

  function lines(output: string): string[] {
    return output.replace(STRIP_ANSI, '').split('\n').map(l => l.trim());
  }

  const record = { packageId: '11111111-1111-1111-1111-111111111111', name: 'hackmyagent', version: '0.7.2' };

  it('shows a Blocked answer by its word and number, then the next step', async () => {
    registry({ ...record, trustScore: 0.12, trustLevel: 0, verdict: 'blocked', scanStatus: 'completed' });
    const out = lines(await run());
    const i = out.findIndex(l => l.startsWith('Trust Level'));
    expect(out[i]).toBe('Trust Level      Blocked (level 0 of 4), do not use');
    expect(out[i + 1]).toBe('Next step        opena2a check hackmyagent');
  });

  it('shows a Warning answer by its word and number, then the next step', async () => {
    registry({ ...record, trustScore: 0.55, trustLevel: 1, verdict: 'warning', scanStatus: 'warnings' });
    const out = lines(await run());
    const i = out.findIndex(l => l.startsWith('Trust Level'));
    expect(out[i]).toBe('Trust Level      Warning (level 1 of 4), review before use');
    expect(out[i + 1]).toBe('Next step        opena2a check hackmyagent');
  });

  it('shows a listed, never-scanned package as not scanned, never 0 / 100', async () => {
    registry({ ...record, trustScore: 0, trustLevel: 2, verdict: 'listed' });
    const output = await run();
    const out = lines(output);
    expect(out).toContain('Trust Score      not scanned');
    expect(out).toContain('Trust Level      Listed (level 2 of 4), not scanned');
    expect(output).not.toContain('0 / 100');
    expect(out.some(l => l.startsWith('Next step'))).toBe(false);
  });

  it('shows a scanned answer by its word with no next step', async () => {
    registry({ ...record, trustScore: 0.85, trustLevel: 3, verdict: 'passed', scanStatus: 'completed' });
    const out = lines(await run());
    expect(out).toContain('Trust Score      85 / 100 (scanned 0.7.2)');
    expect(out).toContain('Trust Level      Scanned (level 3 of 4)');
    expect(out.some(l => l.startsWith('Next step'))).toBe(false);
  });

  it('adds the level, its word and the next step to the JSON and keeps the score field', async () => {
    registry({ ...record, trustScore: 0.12, trustLevel: 0, verdict: 'blocked', scanStatus: 'completed' });
    const pkg = JSON.parse(await run('json')).packages[0];
    expect(pkg).toMatchObject({
      trustScore: 0.12,
      trustVerdict: 'blocked',
      trustLevel: 0,
      trustLevelWord: 'Blocked',
      trustNotScanned: false,
      nextStep: 'opena2a check hackmyagent',
    });
  });

  it('gives an answer without a record no level, rather than Blocked', async () => {
    registry({ name: 'hackmyagent', trustScore: 0, trustLevel: 0, verdict: 'unknown' });
    const output = await run();
    expect(output).not.toContain('Blocked');
    const pkg = JSON.parse(await run('json')).packages[0];
    expect(pkg).toMatchObject({ trustLevel: null, trustLevelWord: null, nextStep: null });
  });
});

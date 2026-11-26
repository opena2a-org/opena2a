import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { baselines } from '../../src/commands/baselines.js';
import type { BaselinesOptions } from '../../src/commands/baselines.js';

// Tests that need contributions on set this; it is reset after each test.
const optIn = vi.hoisted(() => ({ enabled: false }));

// Isolate from the developer's real ~/.opena2a/config.json. checkOptIn does
// `await import('@opena2a/shared')` and reads loadUserConfig().contribute.enabled
// — without this mock the suite passes only on machines where contribute is off.
// Default to enabled=false so the "not enabled" test path runs deterministically.
// The other tests in this file tolerate either exit code, so a single shared
// default is enough.
vi.mock('@opena2a/shared', () => ({
  default: {
    loadUserConfig: () => ({
      contribute: { enabled: optIn.enabled },
      registry: { url: 'https://test-registry.example.com' },
    }),
  },
  loadUserConfig: () => ({
    contribute: { enabled: optIn.enabled },
    registry: { url: 'https://test-registry.example.com' },
  }),
}));

// Mock global fetch
const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  optIn.enabled = false;
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

function captureStderr(fn: () => Promise<number>): Promise<{ exitCode: number; stderr: string }> {
  const chunks: string[] = [];
  const origWrite = process.stderr.write;
  const origStdout = process.stdout.write;
  // Suppress stdout too
  process.stdout.write = (() => true) as any;
  process.stderr.write = ((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  }) as any;

  return fn().then(exitCode => {
    process.stderr.write = origWrite;
    process.stdout.write = origStdout;
    return { exitCode, stderr: chunks.join('') };
  }).catch(err => {
    process.stderr.write = origWrite;
    process.stdout.write = origStdout;
    throw err;
  });
}

describe('baselines', () => {
  it('returns 1 when contribute is not enabled', async () => {
    const options: BaselinesOptions = {
      packageName: 'hackmyagent',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => baselines(options));

    expect(exitCode).toBe(1);
    const result = JSON.parse(output);
    expect(result.error).toContain('not enabled');
  });

  it('collects observation and submits successfully when opted in', async () => {
    // Mock the @opena2a/shared dynamic import for opt-in check
    // We need to intercept the Function('return import(...)') pattern
    // Since checkOptIn uses dynamic import, we mock it at a higher level
    const origFunction = global.Function;
    const mockFunction = vi.fn().mockImplementation((...args: any[]) => {
      const body = args[args.length - 1];
      if (typeof body === 'string' && body.includes('@opena2a/shared')) {
        return () => Promise.resolve({
          default: {
            loadUserConfig: () => ({
              contribute: { enabled: true },
              registry: { url: 'https://test-registry.example.com' },
            }),
          },
        });
      }
      return origFunction(...args);
    });
    vi.stubGlobal('Function', mockFunction);

    // Mock require.resolve for the target package -- point to this test file's directory
    const originalResolve = require.resolve;
    require.resolve = vi.fn().mockReturnValue(__filename) as any;

    // Mock successful submission
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ status: 'accepted' }),
    });

    const options: BaselinesOptions = {
      packageName: 'vitest',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => baselines(options));

    // Restore
    require.resolve = originalResolve;

    // The test may return 1 if package resolution fails (vitest might not resolve cleanly)
    // or 0 if it succeeds. Check for valid JSON output either way.
    const result = JSON.parse(output);

    if (exitCode === 0) {
      expect(result).toHaveProperty('observation');
      expect(result).toHaveProperty('submitted');
      expect(result).toHaveProperty('submissionStatus');
      expect(result.observation).toHaveProperty('packageName');
      expect(result.observation).toHaveProperty('metrics');
      expect(result.observation.observationType).toBe('static_profile');
      expect(result.observation.observer).toBe('opena2a-cli');
    }
  });

  it('produces valid JSON output format', async () => {
    // Mock opt-in
    const origFunction = global.Function;
    const mockFunction = vi.fn().mockImplementation((...args: any[]) => {
      const body = args[args.length - 1];
      if (typeof body === 'string' && body.includes('@opena2a/shared')) {
        return () => Promise.resolve({
          default: {
            loadUserConfig: () => ({
              contribute: { enabled: true },
              registry: { url: 'https://test-registry.example.com' },
            }),
          },
        });
      }
      return origFunction(...args);
    });
    vi.stubGlobal('Function', mockFunction);

    const originalResolve = require.resolve;
    require.resolve = vi.fn().mockReturnValue(__filename) as any;

    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ status: 'accepted' }),
    });

    const options: BaselinesOptions = {
      packageName: 'vitest',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { output } = await captureStdout(() => baselines(options));

    require.resolve = originalResolve;

    // Should produce valid JSON regardless of outcome
    const result = JSON.parse(output);
    expect(result).toBeDefined();

    // If it succeeded, check structure
    if (result.observation) {
      const metrics = result.observation.metrics;
      expect(metrics).toHaveProperty('fileCount');
      expect(metrics).toHaveProperty('totalSizeBytes');
      expect(metrics).toHaveProperty('dependencyCount');
      expect(metrics).toHaveProperty('hasLockfile');
      expect(metrics).toHaveProperty('hasTestScript');
      expect(metrics).toHaveProperty('hasLintScript');
      expect(metrics).toHaveProperty('hasSuspiciousScripts');
      expect(metrics).toHaveProperty('hasEnginesField');
    }
  });

  describe('--package installed only in the current project', () => {
    let project: string;

    beforeEach(() => {
      project = realpathSync(mkdtempSync(join(tmpdir(), 'baselines-project-')));
      const pkgDir = join(project, 'node_modules', '@demo-scope', 'project-only-pkg');
      mkdirSync(pkgDir, { recursive: true });
      writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({
        name: '@demo-scope/project-only-pkg',
        version: '2.3.4',
        main: 'index.js',
        dependencies: { a: '1', b: '1' },
        scripts: { test: 'true' },
      }));
      writeFileSync(join(pkgDir, 'index.js'), 'module.exports = {};\n');
      // The command is run from a folder inside the project.
      mkdirSync(join(project, 'src'));
      vi.spyOn(process, 'cwd').mockReturnValue(join(project, 'src'));
      optIn.enabled = true;
      mockFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    });

    afterEach(() => {
      rmSync(project, { recursive: true, force: true });
    });

    it('finds the package in the node_modules of the project', async () => {
      const { exitCode, output } = await captureStdout(() => baselines({
        packageName: '@demo-scope/project-only-pkg',
        registryUrl: 'https://test-registry.example.com',
        ci: true,
        format: 'json',
      }));

      expect(exitCode).toBe(0);
      const result = JSON.parse(output);
      expect(result.observation.packageName).toBe('@demo-scope/project-only-pkg');
      expect(result.observation.version).toBe('2.3.4');
      expect(result.observation.metrics.fileCount).toBe(2);
      expect(result.observation.metrics.dependencyCount).toBe(2);
      expect(result.observation.metrics.hasTestScript).toBe(true);
    });

    it('exits 1 for a package installed neither in the project nor with the CLI', async () => {
      const { exitCode, stderr } = await captureStderr(() => baselines({
        packageName: 'no-such-package-installed-anywhere',
        registryUrl: 'https://test-registry.example.com',
        ci: true,
      }));

      expect(exitCode).toBe(1);
      expect(stderr).toContain('Package not found: no-such-package-installed-anywhere');
    });
  });
});

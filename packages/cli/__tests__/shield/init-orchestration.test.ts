import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// ---------------------------------------------------------------------------

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

// Mock external optional dependencies to test graceful degradation
vi.mock('secretless-ai', () => {
  throw new Error('Cannot find module secretless-ai');
});

vi.mock('@opena2a/aim-core', () => {
  throw new Error('Cannot find module @opena2a/aim-core');
});

// Mock the heavy internal modules to isolate init orchestration
vi.mock('../../src/shield/detect.js', () => ({
  detectEnvironment: vi.fn(() => ({
    timestamp: new Date().toISOString(),
    hostname: 'test-host',
    platform: 'darwin',
    shell: '/bin/zsh',
    clis: [],
    assistants: [
      { name: 'Claude Code', detected: true, method: 'env', detail: 'test', configPaths: [] },
    ],
    mcpServers: [],
    oauthSessions: [],
    projectType: 'node',
    projectName: 'test-project',
  })),
}));

vi.mock('../../src/shield/policy.js', () => ({
  generatePolicyFromScan: vi.fn(() => ({
    version: 1,
    mode: 'adaptive',
    default: {
      credentials: { allow: [], deny: [] },
      processes: { allow: ['git', 'npm'], deny: ['aws'] },
      network: { allow: [], deny: [] },
      filesystem: { allow: [], deny: [] },
      mcpServers: { allow: [], deny: [] },
      supplyChain: { requireTrustScore: 0, blockAdvisories: false },
    },
    agents: {},
  })),
  savePolicy: vi.fn(),
}));

vi.mock('../../src/shield/events.js', () => ({
  writeEvent: vi.fn(),
  getShieldDir: vi.fn(() => path.join(_mockHomeDir, '.opena2a', 'shield')),
}));

vi.mock('../../src/shield/integrity.js', () => ({
  recordPolicyHash: vi.fn(),
  getExpectedHookContent: vi.fn(() => '# shield hook\n'),
}));

vi.mock('../../src/shield/signing.js', () => ({
  signAllArtifacts: vi.fn(),
}));

vi.mock('../../src/util/credential-patterns.js', () => ({
  quickCredentialScan: vi.fn(() => []),
}));

vi.mock('../../src/commands/guard.js', () => ({
  guard: vi.fn(),
}));

vi.mock('../../src/commands/runtime.js', () => ({
  runtime: vi.fn(),
}));

vi.mock('../../src/util/colors.js', () => ({
  bold: (s: string) => s,
  dim: (s: string) => s,
  green: (s: string) => s,
  yellow: (s: string) => s,
  red: (s: string) => s,
  cyan: (s: string) => s,
}));

vi.mock('../../src/util/spinner.js', () => ({
  Spinner: vi.fn().mockImplementation(() => ({
    start: vi.fn(),
    stop: vi.fn(),
  })),
}));

const { shieldInit } = await import('../../src/shield/init.js');

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-init-orch-'));
  _mockHomeDir = tempDir;

  // Create shield directory
  const shieldDir = path.join(tempDir, '.opena2a', 'shield');
  fs.mkdirSync(shieldDir, { recursive: true });

  // Suppress stdout during tests
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('shield init orchestration', () => {
  it('completes all 11 steps and returns InitResult', async () => {
    const { exitCode, result } = await shieldInit({
      targetDir: tempDir,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0);
    expect(result.steps).toHaveLength(11);
    expect(result.steps.map(s => s.name)).toEqual([
      'Environment scan',
      'Credential audit',
      'Credential protection',
      'Agent identity',
      'Config signing',
      'Policy generation',
      'Shell integration',
      'ARP init',
      'AI tool config',
      'Browser Guard',
      'Summary',
    ]);
  });

  it('gracefully degrades when secretless-ai is not installed', async () => {
    const { result } = await shieldInit({
      targetDir: tempDir,
      ci: true,
      format: 'json',
    });

    expect(result.secretlessConfigured).toBe(false);
    const step = result.steps.find(s => s.name === 'Credential protection');
    expect(step?.status).toBe('skipped');
  });

  it('gracefully degrades when aim-core is not installed', async () => {
    const { result } = await shieldInit({
      targetDir: tempDir,
      ci: true,
      format: 'json',
    });

    expect(result.identityCreated).toBe(false);
    const step = result.steps.find(s => s.name === 'Agent identity');
    expect(step?.status).toBe('skipped');
  });

  it('skips AI tool config in CI mode', async () => {
    const { result } = await shieldInit({
      targetDir: tempDir,
      ci: true,
      format: 'json',
    });

    expect(result.aiToolsConfigured).toBe(false);
    const step = result.steps.find(s => s.name === 'AI tool config');
    expect(step?.status).toBe('skipped');
  });

  it('configures AI tools in non-CI mode', async () => {
    const { result } = await shieldInit({
      targetDir: tempDir,
      ci: false,
      format: 'json',
    });

    // AI tool config should run (Claude Code always configured)
    expect(result.aiToolsConfigured).toBe(true);
    const step = result.steps.find(s => s.name === 'AI tool config');
    expect(step?.status).toBe('done');

    // CLAUDE.md should have shield marker
    const claudeMd = path.join(tempDir, 'CLAUDE.md');
    expect(fs.existsSync(claudeMd)).toBe(true);
    expect(fs.readFileSync(claudeMd, 'utf-8')).toContain('<!-- opena2a-shield:managed -->');
  });

  it('returns exit code 1 when credentials are found', async () => {
    // Override the mock to return findings
    const { quickCredentialScan } = await import('../../src/util/credential-patterns.js');
    vi.mocked(quickCredentialScan).mockReturnValueOnce([
      { severity: 'critical', title: 'API Key', filePath: 'test.js', line: 1, value: 'sk-test', pattern: 'test' },
    ] as any);

    const { exitCode, result } = await shieldInit({
      targetDir: tempDir,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(1);
    const step = result.steps.find(s => s.name === 'Credential audit');
    expect(step?.status).toBe('warn');
  });
});

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

// The credential audit runs the real scanner unless a test overrides it, so
// the files-read count it reports is the walker's own.
vi.mock('../../src/util/credential-patterns.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/credential-patterns.js')>();
  return {
    quickCredentialScan: vi.fn(() => []),
    scanCredentialsWithCoverage: vi.fn(actual.scanCredentialsWithCoverage),
  };
});

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
  Spinner: class {
    start = vi.fn();
    stop = vi.fn();
  },
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

  it('skips AI tool config when --ai-tools is not passed', async () => {
    const { result } = await shieldInit({
      targetDir: tempDir,
      ci: false,
      format: 'json',
    });

    expect(result.aiToolsConfigured).toBe(false);
    const step = result.steps.find(s => s.name === 'AI tool config');
    expect(step?.status).toBe('skipped');
  });

  it('configures AI tools when --ai-tools is passed', async () => {
    const { result } = await shieldInit({
      targetDir: tempDir,
      ci: false,
      format: 'json',
      aiTools: true,
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
    const { scanCredentialsWithCoverage } = await import('../../src/util/credential-patterns.js');
    vi.mocked(scanCredentialsWithCoverage).mockResolvedValueOnce({
      matches: [
        { severity: 'critical', title: 'API Key', filePath: 'test.js', line: 1, value: 'sk-test', pattern: 'test' },
      ],
      filesScanned: 1,
    } as any);

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

describe('shield init credential audit over a directory it reads no file in', () => {
  function textOutput(): string {
    return vi.mocked(process.stdout.write).mock.calls.map(c => String(c[0])).join('');
  }

  function auditSection(out: string): string {
    const start = out.indexOf('Step 2: Credential Audit');
    const end = out.indexOf('Step 3:');
    return out.slice(start, end);
  }

  it('does not call a directory of skipped files clean', async () => {
    // Every entry is a file type or folder the credential walk skips.
    const project = path.join(tempDir, 'assets-only');
    fs.mkdirSync(path.join(project, 'node_modules', 'pkg'), { recursive: true });
    fs.writeFileSync(path.join(project, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    fs.writeFileSync(path.join(project, 'guide.pdf'), '%PDF-1.4\n');
    fs.writeFileSync(path.join(project, 'yarn.lock'), '# yarn lockfile v1\n');
    fs.writeFileSync(path.join(project, '.npmrc'), 'fund=false\n');
    fs.writeFileSync(path.join(project, 'node_modules', 'pkg', 'index.js'), 'module.exports = 1;\n');

    const { exitCode, result } = await shieldInit({ targetDir: project, format: 'text' });

    const audit = auditSection(textOutput());
    expect(audit).not.toContain('No hardcoded credentials found');
    expect(audit).toContain('No files were scanned for credentials, so this is not a clean result.');
    expect(audit).toContain('opena2a shield init --dir <project-dir>');
    expect(result.credentialFilesScanned).toBe(0);
    // Status and exit code are unchanged: only the wording moves.
    expect(result.steps.find(s => s.name === 'Credential audit')?.status).toBe('done');
    expect(exitCode).toBe(0);
  });

  it('still reports no credentials found when it read a file', async () => {
    const project = path.join(tempDir, 'with-code');
    fs.mkdirSync(project, { recursive: true });
    fs.writeFileSync(path.join(project, 'index.js'), 'console.log("hello");\n');

    const { exitCode, result } = await shieldInit({ targetDir: project, format: 'text' });

    const audit = auditSection(textOutput());
    expect(audit).toContain('No hardcoded credentials found');
    expect(audit).not.toContain('No files were scanned for credentials');
    expect(result.credentialFilesScanned).toBe(1);
    expect(exitCode).toBe(0);
  });

  it('carries the files-read count in --json', async () => {
    const project = path.join(tempDir, 'json-empty');
    fs.mkdirSync(project, { recursive: true });
    fs.writeFileSync(path.join(project, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));

    await shieldInit({ targetDir: project, ci: true, format: 'json' });

    const out = textOutput();
    const json = JSON.parse(out.slice(out.indexOf('{')));
    expect(json.credentialFilesScanned).toBe(0);
  });
});

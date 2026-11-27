/**
 * With OPENA2A_HOME set, `shield init` hands aim-core
 * $OPENA2A_HOME/aim-core as its data directory and prints that path on the
 * Storage line, and nothing is created under ~/.opena2a/aim-core.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

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

const aimCalls: Array<{ agentName: string; dataDir?: string }> = [];

vi.mock('@opena2a/aim-core', () => ({
  getOrCreateIdentity: (opts: { agentName: string; dataDir?: string }) => {
    aimCalls.push(opts);
    return { publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
  },
  logEvent: () => ({}),
}));

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

// ARP init runs for real so a second init finds the arp.yaml the first wrote.
vi.mock('../../src/commands/runtime.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/commands/runtime.js')>();
  return { ...actual, runtime: vi.fn() };
});

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

let tempHome: string;
let opena2aHome: string;
let projectDir: string;
let savedEnv: string | undefined;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-init-aim-home-'));
  opena2aHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-init-aim-opena2a-'));
  projectDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-init-aim-project-'));
  _mockHomeDir = tempHome;
  savedEnv = process.env.OPENA2A_HOME;
  process.env.OPENA2A_HOME = opena2aHome;
  aimCalls.length = 0;
  fs.mkdirSync(path.join(tempHome, '.opena2a', 'shield'), { recursive: true });
});

afterEach(() => {
  vi.restoreAllMocks();
  if (savedEnv === undefined) delete process.env.OPENA2A_HOME;
  else process.env.OPENA2A_HOME = savedEnv;
  for (const dir of [tempHome, opena2aHome, projectDir]) fs.rmSync(dir, { recursive: true, force: true });
});

describe('shield init agent identity', () => {
  it('uses $OPENA2A_HOME/aim-core and prints it on the Storage line', async () => {
    let out = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      out += String(chunk);
      return true;
    });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    const { result } = await shieldInit({ targetDir: projectDir, ci: false, format: 'text' });

    expect(result.identityCreated).toBe(true);
    expect(aimCalls).toEqual([{ agentName: 'shield', dataDir: path.join(opena2aHome, 'aim-core') }]);
    expect(out).toContain(`Storage: ${path.join(opena2aHome, 'aim-core')}${path.sep}\n`);
    expect(out).not.toContain('~/.opena2a/aim-core');
    expect(fs.existsSync(path.join(tempHome, '.opena2a', 'aim-core'))).toBe(false);
  });
});

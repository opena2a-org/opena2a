import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

import {
  matchesPattern,
  getDefaultPolicyRules,
  createDefaultPolicy,
  generatePolicyFromScan,
  loadPolicy,
  savePolicy,
  loadPolicyCache,
  savePolicyCache,
  evaluatePolicy,
} from '../../src/shield/policy.js';

import type {
  EnvironmentScan,
  ShieldPolicy,
} from '../../src/shield/types.js';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// vi.mock hoists automatically in vitest; the factory receives the real module.
// ---------------------------------------------------------------------------

let _mockHomeDir: string | null = null;

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => {
      if (_mockHomeDir !== null) {
        return _mockHomeDir;
      }
      return actual.homedir();
    },
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMinimalScan(overrides: Partial<EnvironmentScan> = {}): EnvironmentScan {
  return {
    timestamp: new Date().toISOString(),
    hostname: 'test-host',
    platform: 'darwin',
    shell: '/bin/zsh',
    clis: [],
    assistants: [],
    mcpServers: [],
    oauthSessions: [],
    projectType: 'unknown',
    projectName: null,
    ...overrides,
  };
}

function makePolicy(overrides: Partial<ShieldPolicy> = {}): ShieldPolicy {
  return {
    version: 1,
    mode: 'enforce',
    default: getDefaultPolicyRules(),
    agents: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// matchesPattern
// ---------------------------------------------------------------------------

describe('matchesPattern', () => {
  it('returns true for an exact match', () => {
    expect(matchesPattern('git', 'git')).toBe(true);
  });

  it('returns false when value does not match the pattern', () => {
    expect(matchesPattern('git', 'npm')).toBe(false);
  });

  it('matches everything with wildcard *', () => {
    expect(matchesPattern('anything', '*')).toBe(true);
  });

  it('matches glob patterns with a single wildcard', () => {
    expect(matchesPattern('~/.ssh/id_rsa', '~/.ssh/*')).toBe(true);
  });

  it('rejects glob patterns that do not match', () => {
    expect(matchesPattern('~/.aws/creds', '~/.ssh/*')).toBe(false);
  });

  it('matches path prefix patterns ending with /', () => {
    expect(matchesPattern('~/.ssh/id_rsa', '~/.ssh/')).toBe(true);
  });

  it('matches the exact directory name for path prefix patterns', () => {
    // pattern "~/.ssh/" should match "~/.ssh" (the dir itself without trailing content)
    expect(matchesPattern('~/.ssh', '~/.ssh/')).toBe(true);
  });

  it('matches multi-wildcard glob patterns', () => {
    expect(matchesPattern('foo.bar.baz', 'foo.*.baz')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// getDefaultPolicyRules
// ---------------------------------------------------------------------------

describe('getDefaultPolicyRules', () => {
  it('returns processes.deny containing cloud CLIs', () => {
    const rules = getDefaultPolicyRules();
    expect(rules.processes.deny).toContain('aws');
    expect(rules.processes.deny).toContain('kubectl');
  });

  it('returns processes.allow containing common dev tools', () => {
    const rules = getDefaultPolicyRules();
    expect(rules.processes.allow).toContain('git');
    expect(rules.processes.allow).toContain('npm');
    expect(rules.processes.allow).toContain('node');
  });

  it('returns credentials.deny with SSH directory pattern', () => {
    const rules = getDefaultPolicyRules();
    expect(rules.credentials.deny).toContain('~/.ssh/*');
  });

  it('returns network.allow with localhost', () => {
    const rules = getDefaultPolicyRules();
    expect(rules.network.allow).toContain('localhost');
  });
});

// ---------------------------------------------------------------------------
// createDefaultPolicy
// ---------------------------------------------------------------------------

describe('createDefaultPolicy', () => {
  it('returns version 1 with adaptive mode by default', () => {
    const policy = createDefaultPolicy();
    expect(policy.version).toBe(1);
    expect(policy.mode).toBe('adaptive');
  });

  it('uses default rules and empty agents map', () => {
    const policy = createDefaultPolicy();
    expect(policy.default).toEqual(getDefaultPolicyRules());
    expect(policy.agents).toEqual({});
  });

  it('respects an explicit mode parameter', () => {
    const policy = createDefaultPolicy('enforce');
    expect(policy.mode).toBe('enforce');
  });
});

// ---------------------------------------------------------------------------
// generatePolicyFromScan
// ---------------------------------------------------------------------------

describe('generatePolicyFromScan', () => {
  it('adds detected CLIs to processes.deny', () => {
    const scan = makeMinimalScan({
      clis: [
        {
          name: 'docker',
          path: '/usr/local/bin/docker',
          version: '24.0',
          configDir: '~/.docker',
          hasCredentials: false,
        },
      ],
    });
    const policy = generatePolicyFromScan(scan);
    expect(policy.default.processes.deny).toContain('docker');
  });

  it('adds detected MCP servers to mcpServers.allow', () => {
    const scan = makeMinimalScan({
      mcpServers: [
        {
          name: 'my-server',
          source: 'config',
          command: 'node',
          args: ['server.js'],
          env: {},
          tools: ['read', 'write'],
        },
      ],
    });
    const policy = generatePolicyFromScan(scan);
    expect(policy.default.mcpServers.allow).toContain('my-server');
  });

  it('adds node tools to processes.allow for node projects', () => {
    const scan = makeMinimalScan({ projectType: 'node' });
    const policy = generatePolicyFromScan(scan);
    expect(policy.default.processes.allow).toContain('node');
    expect(policy.default.processes.allow).toContain('npm');
    expect(policy.default.processes.allow).toContain('npx');
    expect(policy.default.processes.allow).toContain('tsc');
  });

  it('sets mode to adaptive', () => {
    const scan = makeMinimalScan();
    const policy = generatePolicyFromScan(scan);
    expect(policy.mode).toBe('adaptive');
  });
});

// ---------------------------------------------------------------------------
// evaluatePolicy - deny takes precedence
// ---------------------------------------------------------------------------

describe('evaluatePolicy - deny takes precedence', () => {
  it('blocks in enforce mode when target matches deny even if also in allow', () => {
    const policy = makePolicy({
      mode: 'enforce',
      default: {
        ...getDefaultPolicyRules(),
        processes: { deny: ['aws'], allow: ['aws'] },
      },
    });
    const decision = evaluatePolicy(policy, null, 'process.spawn', 'aws');
    expect(decision.allowed).toBe(false);
    expect(decision.outcome).toBe('blocked');
  });

  it('monitors in adaptive mode when target matches deny even if also in allow', () => {
    const policy = makePolicy({
      mode: 'adaptive',
      default: {
        ...getDefaultPolicyRules(),
        processes: { deny: ['aws'], allow: ['aws'] },
      },
    });
    const decision = evaluatePolicy(policy, null, 'process.spawn', 'aws');
    expect(decision.allowed).toBe(true);
    expect(decision.outcome).toBe('monitored');
  });
});

// ---------------------------------------------------------------------------
// evaluatePolicy - allow list
// ---------------------------------------------------------------------------

describe('evaluatePolicy - allow list', () => {
  it('allows a target that matches the allow list', () => {
    const policy = makePolicy({
      mode: 'enforce',
      default: {
        ...getDefaultPolicyRules(),
        processes: { deny: [], allow: ['git'] },
      },
    });
    const decision = evaluatePolicy(policy, null, 'process.spawn', 'git');
    expect(decision.allowed).toBe(true);
    expect(decision.outcome).toBe('allowed');
  });

  it('implicitly allows an unknown target with a no-match rule', () => {
    const policy = makePolicy({
      mode: 'enforce',
      default: {
        ...getDefaultPolicyRules(),
        processes: { deny: [], allow: ['git'] },
      },
    });
    const decision = evaluatePolicy(policy, null, 'process.spawn', 'unknown');
    expect(decision.allowed).toBe(true);
    expect(decision.outcome).toBe('allowed');
    expect(decision.rule).toContain('no-match');
  });
});

// ---------------------------------------------------------------------------
// evaluatePolicy - agent-specific overrides
// ---------------------------------------------------------------------------

describe('evaluatePolicy - agent-specific overrides', () => {
  it('allows a target for an agent with an override that permits it', () => {
    const policy = makePolicy({
      mode: 'enforce',
      default: {
        ...getDefaultPolicyRules(),
        processes: { deny: ['aws'], allow: [] },
      },
      agents: {
        'claude-code': {
          processes: { allow: ['aws'], deny: [] },
        },
      },
    });
    const decision = evaluatePolicy(policy, 'claude-code', 'process.spawn', 'aws');
    expect(decision.allowed).toBe(true);
    expect(decision.outcome).toBe('allowed');
  });

  it('monitors a denied target for an agent without overrides in adaptive mode', () => {
    const policy = makePolicy({
      mode: 'adaptive',
      default: {
        ...getDefaultPolicyRules(),
        processes: { deny: ['aws'], allow: [] },
      },
      agents: {
        'claude-code': {
          processes: { allow: ['aws'], deny: [] },
        },
      },
    });
    const decision = evaluatePolicy(policy, 'other', 'process.spawn', 'aws');
    expect(decision.allowed).toBe(true);
    expect(decision.outcome).toBe('monitored');
  });
});

// ---------------------------------------------------------------------------
// evaluatePolicy - credential category with homedir expansion
// ---------------------------------------------------------------------------

describe('evaluatePolicy - credential category with homedir expansion', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-policy-cred-'));
    _mockHomeDir = tempDir;
  });

  afterEach(() => {
    _mockHomeDir = null;
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('matches an expanded home path against a ~ credential deny pattern', () => {
    const policy = makePolicy({
      mode: 'enforce',
      default: {
        ...getDefaultPolicyRules(),
        credentials: { deny: ['~/.ssh/*'], allow: [] },
      },
    });
    const target = path.join(tempDir, '.ssh', 'id_rsa');
    const decision = evaluatePolicy(policy, null, 'credential.read', target);
    expect(decision.allowed).toBe(false);
    expect(decision.outcome).toBe('blocked');
  });
});

// ---------------------------------------------------------------------------
// savePolicy + loadPolicy round-trip
// ---------------------------------------------------------------------------

describe('savePolicy + loadPolicy round-trip', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-policy-test-'));
    _mockHomeDir = tempDir;
  });

  afterEach(() => {
    _mockHomeDir = null;
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('saves and loads a policy from a project-level directory', () => {
    const policy = createDefaultPolicy('enforce');
    const policyPath = path.join(tempDir, '.opena2a', 'shield', 'policy.yaml');

    savePolicy(policy, policyPath);

    const loaded = loadPolicy(tempDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.version).toBe(1);
    expect(loaded!.mode).toBe('enforce');
    expect(loaded!.default).toEqual(policy.default);
    expect(loaded!.agents).toEqual({});
  });

  it('saves and loads a policy from the user-level directory', () => {
    const policy = createDefaultPolicy('adaptive');
    const policyPath = path.join(tempDir, '.opena2a', 'shield', 'policy.yaml');

    savePolicy(policy, policyPath);

    // loadPolicy with no targetDir falls through to user-level (~/.opena2a/shield/)
    const loaded = loadPolicy();
    expect(loaded).not.toBeNull();
    expect(loaded!.mode).toBe('adaptive');
  });

  it('returns null when no policy file exists', () => {
    const loaded = loadPolicy(tempDir);
    expect(loaded).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// savePolicyCache + loadPolicyCache round-trip
// ---------------------------------------------------------------------------

describe('savePolicyCache + loadPolicyCache', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-policy-cache-'));
    _mockHomeDir = tempDir;
  });

  afterEach(() => {
    _mockHomeDir = null;
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('returns null when no cache exists', () => {
    expect(loadPolicyCache()).toBeNull();
  });

  it('round-trips a policy through the cache', () => {
    const policy = createDefaultPolicy('enforce');
    savePolicyCache(policy);

    const loaded = loadPolicyCache();
    expect(loaded).not.toBeNull();
    expect(loaded!.mode).toBe('enforce');
    expect(loaded!.default).toEqual(policy.default);
  });
});

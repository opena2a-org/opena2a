/**
 * Each config directory the generated shield policy denies is listed with a
 * trailing `/`, the form the default `filesystem.deny` entries use. The entry
 * covers the directory and every file inside it, and no sibling path that
 * only shares the directory's name as a prefix.
 *
 * Every directory is created at run time under an `mkdtemp` root that stands
 * in for HOME. PATH holds only an empty scratch directory, so no CLI is found
 * or started. No network.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { EnvironmentScan, PolicyMode, ShieldPolicy } from '../../src/shield/types.js';

let root: string;
let home: string;
let project: string;
let originalCwd: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'shield-policy-dir-files-'));
  home = join(root, 'home');
  project = join(root, 'project');
  const emptyPathDir = join(root, 'path');
  for (const dir of [home, project, emptyPathDir]) mkdirSync(dir, { recursive: true });
  originalCwd = process.cwd();
  process.chdir(project);
  vi.stubEnv('HOME', home);
  vi.stubEnv('PATH', emptyPathDir);
  vi.resetModules();
});

afterEach(() => {
  process.chdir(originalCwd);
  vi.unstubAllEnvs();
  vi.resetModules();
  rmSync(root, { recursive: true, force: true });
});

/** The policy `shield init` would generate for the scratch HOME and project. */
async function generatedPolicy(mode?: PolicyMode): Promise<ShieldPolicy> {
  const { detectEnvironment } = await import('../../src/shield/detect.js');
  const { generatePolicyFromScan } = await import('../../src/shield/policy.js');
  const policy = generatePolicyFromScan(detectEnvironment(project));
  return mode ? { ...policy, mode } : policy;
}

/** The outcome and the rule of evaluating a `file.access` of the target. */
async function fileAccess(policy: ShieldPolicy, target: string): Promise<{ outcome: string; rule: string }> {
  const { evaluatePolicy } = await import('../../src/shield/policy.js');
  const { outcome, rule } = evaluatePolicy(policy, null, 'file.access', target);
  return { outcome, rule };
}

/** A scan that names one config directory through both a known and a detected CLI. */
function scanNaming(configDir: string): EnvironmentScan {
  return {
    timestamp: new Date(0).toISOString(),
    hostname: 'test-host',
    platform: 'test',
    shell: 'sh',
    clis: [{ name: 'gh', path: join(root, 'path', 'gh'), version: null, configDir, hasCredentials: false }],
    knownClis: [{ name: 'gh', configDir, configDirExists: true }],
    assistants: [],
    mcpServers: [],
    oauthSessions: [],
    projectType: 'generic',
    projectName: null,
  };
}

describe('a generated config-directory deny entry covers the files inside the directory', () => {
  it('lists each existing config directory once, in the trailing-slash form the defaults use', async () => {
    const ghDir = join(home, '.config', 'gh');
    const vercelDir = join(home, '.vercel');
    mkdirSync(ghDir, { recursive: true });
    mkdirSync(vercelDir, { recursive: true });

    const deny = (await generatedPolicy()).default.filesystem.deny;

    expect(deny.filter((p) => p === `${ghDir}/`), JSON.stringify(deny)).toHaveLength(1);
    expect(deny.filter((p) => p === `${vercelDir}/`), JSON.stringify(deny)).toHaveLength(1);
    expect(deny).not.toContain(ghDir);
    expect(deny).not.toContain(vercelDir);
    expect(deny.every((p) => p.endsWith('/')), JSON.stringify(deny)).toBe(true);
  });

  for (const [mode, outcome] of [['adaptive', 'monitored'], ['enforce', 'blocked']] as const) {
    it(`a file inside an existing config directory is ${outcome} under ${mode} mode`, async () => {
      const ghDir = join(home, '.config', 'gh');
      mkdirSync(ghDir, { recursive: true });
      const policy = await generatedPolicy(mode);

      expect(await fileAccess(policy, join(ghDir, 'hosts.yml'))).toEqual({ outcome, rule: `filesystem.deny:${ghDir}/` });
    });

    it(`the config directory itself, with or without a trailing slash, is ${outcome} under ${mode} mode`, async () => {
      const ghDir = join(home, '.config', 'gh');
      mkdirSync(ghDir, { recursive: true });
      const policy = await generatedPolicy(mode);

      for (const target of [ghDir, `${ghDir}/`]) {
        expect(await fileAccess(policy, target), target).toEqual({ outcome, rule: `filesystem.deny:${ghDir}/` });
      }
    });

    it(`a sibling path that only shares the directory's name as a prefix is allowed under ${mode} mode`, async () => {
      const ghDir = join(home, '.config', 'gh');
      const ghostDir = join(home, '.config', 'ghost');
      mkdirSync(ghDir, { recursive: true });
      mkdirSync(ghostDir, { recursive: true });
      const policy = await generatedPolicy(mode);

      for (const target of [ghostDir, join(ghostDir, 'hosts.yml')]) {
        expect(await fileAccess(policy, target), target).toEqual({ outcome: 'allowed', rule: 'filesystem:no-match' });
      }
    });
  }

  it('lists no config directory that does not exist', async () => {
    const vercelDir = join(home, '.vercel');
    mkdirSync(join(home, '.config', 'gh'), { recursive: true });

    const policy = await generatedPolicy('enforce');
    const deny = policy.default.filesystem.deny;

    expect(deny).not.toContain(vercelDir);
    expect(deny).not.toContain(`${vercelDir}/`);
    expect(await fileAccess(policy, join(vercelDir, 'project.json'))).toEqual({ outcome: 'allowed', rule: 'filesystem:no-match' });
  });

  it('lists a directory named by both a known and a detected CLI once, with a trailing slash', async () => {
    const ghDir = join(home, '.config', 'gh');
    mkdirSync(ghDir, { recursive: true });
    const { generatePolicyFromScan } = await import('../../src/shield/policy.js');

    const deny = generatePolicyFromScan(scanNaming(ghDir)).default.filesystem.deny;

    expect(deny.filter((p) => p === ghDir || p === `${ghDir}/`), JSON.stringify(deny)).toEqual([`${ghDir}/`]);
  });

  it('keeps a single trailing slash on a config directory given with one', async () => {
    const ghDir = join(home, '.config', 'gh');
    mkdirSync(ghDir, { recursive: true });
    const { generatePolicyFromScan } = await import('../../src/shield/policy.js');

    const deny = generatePolicyFromScan(scanNaming(`${ghDir}/`)).default.filesystem.deny;

    expect(deny.filter((p) => p.startsWith(ghDir)), JSON.stringify(deny)).toEqual([`${ghDir}/`]);
  });
});

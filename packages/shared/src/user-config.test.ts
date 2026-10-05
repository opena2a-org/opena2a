import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, existsSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, tmpdir } from 'node:os';
import {
  isStaleRegistryUrl,
  STALE_REGISTRY_HOSTS,
  CANONICAL_REGISTRY_URL,
  getUserConfigDir,
  getUserConfigPath,
  getProjectStoreKey,
  getProjectStoreDir,
} from './user-config.js';

describe('isStaleRegistryUrl', () => {
  it('returns true for each documented stale host', () => {
    for (const host of STALE_REGISTRY_HOSTS) {
      expect(isStaleRegistryUrl(host)).toBe(true);
    }
  });

  it('returns true for stale host with trailing slash', () => {
    expect(isStaleRegistryUrl('https://registry.opena2a.org/')).toBe(true);
  });

  it('returns true for stale host with path suffix', () => {
    expect(isStaleRegistryUrl('https://registry.opena2a.org/api/v1/trust')).toBe(true);
  });

  it('returns true for stale host regardless of case', () => {
    expect(isStaleRegistryUrl('HTTPS://REGISTRY.OPENA2A.ORG')).toBe(true);
  });

  it('returns false for the current canonical URL', () => {
    expect(isStaleRegistryUrl(CANONICAL_REGISTRY_URL)).toBe(false);
  });

  it('returns false for a third-party URL that happens to share a suffix', () => {
    expect(isStaleRegistryUrl('https://not-registry.opena2a.org')).toBe(false);
  });

  it('returns false for empty or undefined input', () => {
    expect(isStaleRegistryUrl('')).toBe(false);
    expect(isStaleRegistryUrl('   ')).toBe(false);
    expect(isStaleRegistryUrl(undefined)).toBe(false);
    expect(isStaleRegistryUrl(null)).toBe(false);
  });

  it('returns false for a user-provided self-hosted registry', () => {
    expect(isStaleRegistryUrl('https://my-internal-registry.example.com')).toBe(false);
  });
});

describe('user home and project store', () => {
  let saved: string | undefined;
  let tmp: string;

  beforeEach(() => {
    saved = process.env.OPENA2A_HOME;
    delete process.env.OPENA2A_HOME;
    tmp = realpathSync.native(mkdtempSync(join(tmpdir(), 'opena2a-store-')));
  });

  afterEach(() => {
    if (saved === undefined) delete process.env.OPENA2A_HOME;
    else process.env.OPENA2A_HOME = saved;
    rmSync(tmp, { recursive: true, force: true });
  });

  it('defaults the user home to ~/.opena2a', () => {
    expect(getUserConfigDir()).toBe(join(homedir(), '.opena2a'));
    process.env.OPENA2A_HOME = '   ';
    expect(getUserConfigDir()).toBe(join(homedir(), '.opena2a'));
  });

  it('honours OPENA2A_HOME as the user home itself', () => {
    process.env.OPENA2A_HOME = join(tmp, 'home');
    expect(getUserConfigDir()).toBe(join(tmp, 'home'));
    expect(getUserConfigPath()).toBe(join(tmp, 'home', 'config.json'));
  });

  it('pins the cross-implementation conformance vector', () => {
    expect(getProjectStoreKey('/srv/example-project')).toBe('2550ea6e13e5f88a');
  });

  it('places the store under <user home>/projects/<key> without creating it', () => {
    process.env.OPENA2A_HOME = join(tmp, 'home');
    const project = join(tmp, 'project');
    mkdirSync(project);
    const dir = getProjectStoreDir(project);
    expect(dir).toBe(join(tmp, 'home', 'projects', getProjectStoreKey(project)));
    expect(getProjectStoreKey(project)).toMatch(/^[0-9a-f]{16}$/);
    expect(existsSync(dir)).toBe(false);
  });

  it('gives a symlinked and a relative spelling of one directory the same key', () => {
    const project = join(tmp, 'project');
    mkdirSync(project);
    const link = join(tmp, 'link');
    symlinkSync(project, link);
    expect(getProjectStoreKey(link)).toBe(getProjectStoreKey(project));
    expect(getProjectStoreKey(join(project, 'sub', '..'))).toBe(getProjectStoreKey(project));
  });

  it('gives one key to every case spelling on a case-insensitive filesystem', () => {
    const project = join(tmp, 'MixedCase');
    mkdirSync(project);
    const lower = join(tmp, 'mixedcase');
    if (!existsSync(lower)) return; // case-sensitive filesystem: two directories, two keys is correct
    expect(getProjectStoreKey(lower)).toBe(getProjectStoreKey(project));
  });
});

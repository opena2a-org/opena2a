/**
 * `opena2a scan <package>` runs the check flow instead of treating the name
 * as a directory.
 *
 * The scan adapter runs `hackmyagent secure <directory>`, which reads its
 * argument as a path: `opena2a scan express` exited 1 with "Directory
 * '.../express' does not exist". A target that is not an existing path and
 * names a package, GitHub repo, MCP server or skill now goes to
 * `hackmyagent check`; a real directory still goes to the scan adapter.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

interface Captured { bin: string; args: string[] }
const spawnCalls: Captured[] = [];
const adapterRuns: string[][] = [];

vi.mock('node:child_process', () => ({
  spawn: vi.fn((bin: string, args: string[]) => {
    spawnCalls.push({ bin, args });
    return {
      on: vi.fn((event: string, handler: (code: number) => void) => {
        if (event === 'close') setTimeout(() => handler(0), 0);
      }),
    };
  }),
  execFileSync: vi.fn(() => { throw new Error('not found'); }),
}));

vi.mock('../../src/util/hma-version.js', () => ({ checkMinHmaVersion: vi.fn() }));

vi.mock('../../src/util/report-submission.js', () => ({
  isContributeEnabled: vi.fn(async () => false),
  getRegistryUrl: vi.fn(async () => ''),
  submitScanReport: vi.fn(async () => undefined),
  normalizeGovernanceReport: vi.fn(() => null),
  recordScanAndMaybePrompt: vi.fn(async () => undefined),
}));

vi.mock('../../src/adapters/index.js', async () => {
  const { ADAPTER_REGISTRY } = await import('../../src/adapters/registry.js');
  return {
    createAdapter: (name: string) => {
      const config = ADAPTER_REGISTRY[name];
      if (!config) return null;
      return {
        config,
        isAvailable: async () => true,
        run: async (opts: { args: string[] }) => {
          adapterRuns.push(opts.args);
          return { exitCode: 0, stdout: '', stderr: '' };
        },
      };
    },
  };
});

const { dispatchCommand, scanCheckTarget, isGitHubRepoTarget } = await import('../../src/router.js');

let dir: string;

beforeEach(() => {
  spawnCalls.length = 0;
  adapterRuns.length = 0;
  dir = mkdtempSync(join(tmpdir(), 'opena2a-scan-target-'));
  mkdirSync(join(dir, 'project'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('scanCheckTarget', () => {
  it('routes package, repo, MCP server and skill names that are not paths', () => {
    for (const target of ['express', '@scope/pkg', 'owner/repo', 'https://github.com/org/repo', 'mcp:@modelcontextprotocol/server-filesystem', 'skill:opena2a/code-review-skill']) {
      expect(scanCheckTarget([target], dir), target).toBe(target);
    }
  });

  it('reads the target after an explicit secure', () => {
    expect(scanCheckTarget(['secure', 'express'], dir)).toBe('express');
  });

  it('keeps local paths, existing names, flags and no target on the scan', () => {
    expect(scanCheckTarget([], dir)).toBeNull();
    expect(scanCheckTarget(['.'], dir)).toBeNull();
    expect(scanCheckTarget(['./missing'], dir)).toBeNull();
    expect(scanCheckTarget(['/no/such/dir'], dir)).toBeNull();
    expect(scanCheckTarget(['project'], dir)).toBeNull();
    expect(scanCheckTarget(['--format', 'json'], dir)).toBeNull();
    expect(scanCheckTarget(['express', '--help'], dir)).toBeNull();
    expect(scanCheckTarget(['SOUL.md'], dir)).toBeNull();
  });

  it('isGitHubRepoTarget accepts repos only', () => {
    expect(isGitHubRepoTarget('owner/repo')).toBe(true);
    expect(isGitHubRepoTarget('src/lib/x')).toBe(false);
    expect(isGitHubRepoTarget('example.com/x')).toBe(false);
  });
});

describe('dispatchCommand scan', () => {
  it('runs hackmyagent check for a package name, not secure', async () => {
    const code = await dispatchCommand('scan', ['express', '--rescan'], { cwd: dir });
    expect(code).toBe(0);
    expect(adapterRuns).toHaveLength(0);
    expect(spawnCalls).toHaveLength(1);
    expect(spawnCalls[0].bin).toBe('hackmyagent');
    expect(spawnCalls[0].args).toEqual(['check', 'express', '--rescan']);
  });

  it('drops an explicit secure before the check', async () => {
    await dispatchCommand('scan', ['secure', 'owner/repo'], { cwd: dir, format: 'json' });
    expect(spawnCalls[0].args).toEqual(['check', 'owner/repo', '--json']);
  });

  it('still scans a real directory with secure', async () => {
    const code = await dispatchCommand('scan', ['project'], { cwd: dir });
    expect(code).toBe(0);
    expect(spawnCalls).toHaveLength(0);
    expect(adapterRuns).toEqual([['secure', 'project']]);
  });

  it('still scans the current directory with no target', async () => {
    await dispatchCommand('scan', [], { cwd: dir });
    expect(spawnCalls).toHaveLength(0);
    expect(adapterRuns).toEqual([['secure']]);
  });

  it('passes --verbose to the directory scan so it lists more than the default', async () => {
    await dispatchCommand('scan', ['project'], { cwd: dir, verbose: true });
    expect(adapterRuns).toEqual([['secure', 'project', '--verbose']]);
    adapterRuns.length = 0;
    await dispatchCommand('scan', ['project'], { cwd: dir });
    expect(adapterRuns).toEqual([['secure', 'project']]);
  });

  it('does not repeat --verbose the user already typed', async () => {
    await dispatchCommand('scan', ['project', '--verbose'], { cwd: dir, verbose: true });
    expect(adapterRuns).toEqual([['secure', 'project', '--verbose']]);
  });
});

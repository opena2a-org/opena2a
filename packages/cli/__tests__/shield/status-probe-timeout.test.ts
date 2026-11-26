/**
 * `getShieldStatus` (reached from `opena2a review`, `init`, `status` and
 * `shield status`) starts `secretless-ai --version` and, when no workspace
 * hackmyagent resolves, `hackmyagent --version`. A helper that never answers
 * must not hold the command: the probe is stopped after the version probe
 * timeout and the helper is listed as installed with no version.
 *
 * The timeout is shortened for the hung-helper case by mocking the shared
 * constant; the other cases run with the real one. The stubs are written at
 * run time into an `mkdtemp` directory and use only shell builtins. PATH holds only that directory, so no tool installed on the
 * test machine is started. No network.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SHORT_TIMEOUT_MS = 1_000;

let root: string;
let originalCwd: string;

function writeExecutable(filePath: string, body: string): void {
  writeFileSync(filePath, body);
  chmodSync(filePath, 0o755);
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'shield-status-timeout-'));
  originalCwd = process.cwd();
  vi.resetModules();
});

/** Shorten the shared version probe timeout for the next import of status.ts. */
function shortenProbeTimeout(): void {
  vi.doMock('../../src/shield/detect.js', async (importOriginal) => ({
    ...(await importOriginal<typeof import('../../src/shield/detect.js')>()),
    VERSION_PROBE_TIMEOUT_MS: SHORT_TIMEOUT_MS,
  }));
}

afterEach(() => {
  process.chdir(originalCwd);
  vi.doUnmock('../../src/shield/detect.js');
  vi.unstubAllEnvs();
  vi.resetModules();
  rmSync(root, { recursive: true, force: true });
});

describe('shield status helper version probes time out', () => {
  it('lists a hung secretless-ai as installed with no version once the timeout passes', async () => {
    const bin = join(root, 'bin');
    const home = join(root, 'home');
    const project = join(root, 'project');
    for (const dir of [bin, home, project]) mkdirSync(dir, { recursive: true });
    writeExecutable(join(bin, 'secretless-ai'), '#!/bin/sh\nwhile :; do :; done\n');
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', bin);
    shortenProbeTimeout();

    const { getShieldStatus } = await import('../../src/shield/status.js');
    const started = Date.now();
    const status = getShieldStatus();
    const elapsed = Date.now() - started;

    const secretless = status.tools.find((t) => t.name === 'Secretless')!;
    expect(secretless.installed).toBe(true);
    expect(secretless.version).toBeNull();
    // One hung probe at most, plus the rest of the status work.
    expect(elapsed, `getShieldStatus took ${elapsed} ms`).toBeLessThan(SHORT_TIMEOUT_MS * 2 + 4_000);
  });

  it('still lists a helper that answers with its version', async () => {
    const bin = join(root, 'bin');
    const home = join(root, 'home');
    const project = join(root, 'project');
    for (const dir of [bin, home, project]) mkdirSync(dir, { recursive: true });
    writeExecutable(join(bin, 'secretless-ai'), "#!/bin/sh\necho '9.9.9'\n");
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', bin);

    const { getShieldStatus } = await import('../../src/shield/status.js');
    const secretless = getShieldStatus().tools.find((t) => t.name === 'Secretless')!;
    expect(secretless.installed).toBe(true);
    expect(secretless.version).toBe('9.9.9');
  });

  it('lists a helper whose probe fails as not installed', async () => {
    const bin = join(root, 'bin');
    const home = join(root, 'home');
    const project = join(root, 'project');
    for (const dir of [bin, home, project]) mkdirSync(dir, { recursive: true });
    writeExecutable(join(bin, 'secretless-ai'), '#!/bin/sh\nexit 3\n');
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', bin);

    const { getShieldStatus } = await import('../../src/shield/status.js');
    const secretless = getShieldStatus().tools.find((t) => t.name === 'Secretless')!;
    expect(secretless.installed).toBe(false);
    expect(secretless.version).toBeNull();
  });
});

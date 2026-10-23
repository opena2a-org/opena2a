/**
 * The policy `opena2a shield init` generates denies each known CLI's config
 * directory whenever that directory exists, and lists each known CLI's name in
 * `processes.deny`, whether or not the CLI was found on PATH.
 *
 * Detection still decides what is started: a CLI is found only in PATH's
 * absolute directories, so one an agent reaches through `npx` or only through
 * a relative PATH entry is not listed as detected. Its credentials live in the
 * same config directory either way, so the deny lists do not depend on it.
 *
 * Every directory and stub is created at run time under an `mkdtemp` root
 * that stands in for HOME. No CLI installed on the test machine is started:
 * PATH holds only scratch directories. No network.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, isAbsolute, join } from 'node:path';

/** Every CLI the detection table covers, in its order. */
const KNOWN_CLIS = ['aws', 'az', 'gcloud', 'vercel', 'gh', 'kubectl', 'terraform'];

let root: string;
let originalCwd: string;

function layout(): { absoluteDir: string; home: string; project: string } {
  const absoluteDir = join(root, 'absolute');
  const home = join(root, 'home');
  const project = join(root, 'project');
  for (const dir of [absoluteDir, home, project]) mkdirSync(dir, { recursive: true });
  return { absoluteDir, home, project };
}

async function scanAndPolicy(targetDir: string) {
  const { detectEnvironment } = await import('../../src/shield/detect.js');
  const { generatePolicyFromScan } = await import('../../src/shield/policy.js');
  const scan = detectEnvironment(targetDir);
  return { scan, policy: generatePolicyFromScan(scan) };
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'shield-policy-dirs-'));
  originalCwd = process.cwd();
  vi.resetModules();
});

afterEach(() => {
  process.chdir(originalCwd);
  vi.unstubAllEnvs();
  vi.resetModules();
  rmSync(root, { recursive: true, force: true });
});

describe('the generated shield policy covers every known CLI, found or not', () => {
  // (e) gh and vercel are not found on PATH, but their config directories
  // exist: the policy denies both directories and both names.
  it('denies the config directories and names of CLIs that are not found but whose config directories exist', async () => {
    const { absoluteDir, home, project } = layout();
    const ghDir = join(home, '.config', 'gh');
    const vercelDir = join(home, '.vercel');
    mkdirSync(ghDir, { recursive: true });
    mkdirSync(vercelDir, { recursive: true });
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', absoluteDir);

    const { scan, policy } = await scanAndPolicy(project);

    expect(scan.clis.map((c) => c.name), 'neither CLI is detected').toEqual([]);
    expect(policy.default.filesystem.deny).toContain(ghDir);
    expect(policy.default.filesystem.deny).toContain(vercelDir);
    expect(policy.default.processes.deny).toContain('gh');
    expect(policy.default.processes.deny).toContain('vercel');
  });

  it('records every known CLI in the scan with whether its config directory exists', async () => {
    const { absoluteDir, home, project } = layout();
    mkdirSync(join(home, '.kube'), { recursive: true });
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', absoluteDir);

    const { scan, policy } = await scanAndPolicy(project);

    expect(scan.knownClis.map((c) => c.name)).toEqual(KNOWN_CLIS);
    const present = scan.knownClis.filter((c) => c.configDirExists).map((c) => c.name);
    expect(present).toEqual(['kubectl']);
    // Every known name is denied; only a directory that exists is listed.
    for (const name of KNOWN_CLIS) expect(policy.default.processes.deny, name).toContain(name);
    expect(policy.default.filesystem.deny).toContain(join(home, '.kube'));
    expect(policy.default.filesystem.deny).not.toContain(join(home, '.terraform.d'));
    expect(policy.default.filesystem.deny).not.toContain(join(home, '.vercel'));
  });

  // A CLI reachable only through a relative PATH entry is not started and not
  // detected, and its config directory is still denied.
  it('denies the config directory of a CLI found only through a relative PATH entry, without starting it', async () => {
    const { absoluteDir, home, project } = layout();
    const ghDir = join(home, '.config', 'gh');
    mkdirSync(ghDir, { recursive: true });
    mkdirSync(join(project, 'bin'));
    const marker = join(root, 'gh-ran.marker');
    writeFileSync(join(project, 'bin', 'gh'), `#!/bin/sh\necho ran > '${marker}'\necho 'gh version 2.99.0'\n`);
    chmodSync(join(project, 'bin', 'gh'), 0o755);
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', `${absoluteDir}${delimiter}bin`);

    const { scan, policy } = await scanAndPolicy(project);

    expect(existsSync(marker), 'the planted gh must not run').toBe(false);
    expect(scan.clis.map((c) => c.name)).not.toContain('gh');
    expect(policy.default.filesystem.deny).toContain(ghDir);
    expect(policy.default.processes.deny).toContain('gh');
  });

  // Control: a CLI found in an absolute PATH directory keeps its existing
  // entries, listed once.
  it('lists a detected CLI\'s config directory and name once', async () => {
    const { absoluteDir, home, project } = layout();
    const ghDir = join(home, '.config', 'gh');
    mkdirSync(ghDir, { recursive: true });
    writeFileSync(join(absoluteDir, 'gh'), "#!/bin/sh\necho 'gh version 2.99.0'\n");
    chmodSync(join(absoluteDir, 'gh'), 0o755);
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', absoluteDir);

    const { scan, policy } = await scanAndPolicy(project);

    expect(scan.clis.map((c) => c.name)).toEqual(['gh']);
    expect(policy.default.filesystem.deny.filter((d) => d === ghDir)).toHaveLength(1);
    expect(policy.default.processes.deny.filter((n) => n === 'gh')).toHaveLength(1);
  });

  // With HOME empty, a config path is relative and would name a directory in
  // the tree the command was started in; it is not taken as a CLI's config
  // directory, so every directory the policy adds is absolute.
  it('adds no relative directory when HOME is empty', async () => {
    const { absoluteDir, project } = layout();
    mkdirSync(join(project, '.vercel'));
    process.chdir(project);
    vi.stubEnv('HOME', '');
    vi.stubEnv('PATH', absoluteDir);

    const { scan, policy } = await scanAndPolicy(project);

    expect(scan.knownClis.every((c) => !c.configDirExists)).toBe(true);
    expect(policy.default.filesystem.deny.every((d) => isAbsolute(d) || d.startsWith('~/')), JSON.stringify(policy.default.filesystem.deny)).toBe(true);
    for (const name of KNOWN_CLIS) expect(policy.default.processes.deny, name).toContain(name);
  });
});

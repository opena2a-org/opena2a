/**
 * A cloud CLI whose version command does not finish cannot hold up
 * environment detection, the first step of `opena2a shield init`.
 *
 * detectClis ran each detected CLI's version command (`az --version`,
 * `gcloud --version`, ...) and waited until it exited. On a CI runner with
 * several cloud CLIs installed, `opena2a shield init` in a fresh HOME was
 * stopped by the help-examples test's 30-second limit with nothing printed
 * past its `Shield Init` header, and a CLI that never exits held the command
 * at that step for good.
 *
 * Two stand-ins on a PATH of their own, so no CLI installed on the machine
 * running the test is started: `az` prints a version and then does not exit
 * for 30 seconds, `gh` prints a version and exits. Detection lists both, `gh`
 * with its version and `az` with none, and the `az` probe is no longer
 * running when detection returns.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, isAbsolute, join } from 'node:path';

let root: string;
let bin: string;
let azPidFile: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'shield-detect-probe-'));
  bin = join(root, 'bin');
  azPidFile = join(root, 'az.pid');
  for (const dir of [bin, join(root, 'home'), join(root, 'project')]) mkdirSync(dir);
  // detectClis looks each CLI up in PATH's absolute directories (it starts no
  // `which`); `bin` below is absolute, so the two stand-ins are found there.
  // The `which` link is kept only so the PATH matches a real operator's.
  const which = (process.env.PATH ?? '')
    .split(delimiter)
    .filter((dir) => isAbsolute(dir))
    .map((dir) => join(dir, 'which'))
    .find((file) => existsSync(file));
  expect(which, 'no `which` on PATH').toBeDefined();
  symlinkSync(which!, join(bin, 'which'));
  writeFileSync(join(bin, 'az'), `#!/bin/sh\necho $$ > '${azPidFile}'\necho 'azure-cli 2.99.0'\nexec /bin/sleep 30\n`);
  writeFileSync(join(bin, 'gh'), "#!/bin/sh\necho 'gh version 2.99.0'\n");
  chmodSync(join(bin, 'az'), 0o755);
  chmodSync(join(bin, 'gh'), 0o755);
  vi.stubEnv('PATH', bin);
  // The assistant and MCP server lookups read under HOME; keep them off the real one.
  vi.stubEnv('HOME', join(root, 'home'));
});

afterAll(() => {
  vi.unstubAllEnvs();
  rmSync(root, { recursive: true, force: true });
});

describe('environment detection with a CLI whose version command does not finish', () => {
  it('lists that CLI without a version, stops its probe and reads the next CLI', async () => {
    const { detectEnvironment } = await import('../../src/shield/detect.js');
    const scan = detectEnvironment(join(root, 'project'));

    expect(scan.clis.map((c) => [c.name, c.path, c.version])).toEqual([
      ['az', join(bin, 'az'), null],
      ['gh', join(bin, 'gh'), 'gh version 2.99.0'],
    ]);
    // The stand-in replaced its shell with `sleep`, so this pid is the probe.
    const pid = Number(readFileSync(azPidFile, 'utf-8').trim());
    expect(() => process.kill(pid, 0)).toThrow(/ESRCH/);
  }, 60_000);
});

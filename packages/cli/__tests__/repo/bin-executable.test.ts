import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// The README's from-source steps run `./packages/cli/dist/index.js` straight
// after `npm run build`. tsc writes its output without the execute bit, so
// that line failed with `permission denied` and exit 126 (#436). An install
// from the registry was never affected: npm sets the mode of a package's
// `bin` targets when it links them. The build now sets it too, and this test
// runs the built entry the way the README does, with no `node` in front.

const CLI_ROOT = path.resolve(__dirname, '..', '..');
const pkg = JSON.parse(fs.readFileSync(path.join(CLI_ROOT, 'package.json'), 'utf-8')) as {
  bin: Record<string, string>;
  scripts: Record<string, string>;
};
const binTargets = Object.values(pkg.bin);

let xdgConfigHome: string;

beforeAll(() => {
  xdgConfigHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-bin-test-'));
});

afterAll(() => {
  fs.rmSync(xdgConfigHome, { recursive: true, force: true });
});

describe('from-source bin entry (#436)', () => {
  it('the build script sets the execute bit on every bin target', () => {
    const steps = pkg.scripts.build.split('&&').map((s) => s.trim());
    for (const target of binTargets) {
      expect(steps, `build script does not run \`chmod +x ${target}\``).toContain(`chmod +x ${target}`);
    }
  });

  it.skipIf(process.platform === 'win32').each(binTargets)('%s runs directly after a build', (target) => {
    const entry = path.join(CLI_ROOT, target);
    expect(fs.existsSync(entry), `${target} is missing: run \`npm run build\` in packages/cli first`).toBe(true);

    const res = spawnSync(entry, ['--version'], {
      cwd: CLI_ROOT,
      encoding: 'utf8',
      timeout: 20000,
      env: {
        ...process.env,
        NODE_OPTIONS: '',
        NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off',
        XDG_CONFIG_HOME: xdgConfigHome,
      },
    });
    expect(res.error, String(res.error)).toBeUndefined();
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toMatch(/^opena2a \d+\.\d+\.\d+/);
  });
});

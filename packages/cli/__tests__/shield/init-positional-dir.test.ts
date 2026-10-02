/**
 * Issue #268 — `shield init <dir>` hardens <dir>.
 *
 * The positional was discarded: `shield init /tmp/target` run from another
 * directory wrote arp.yaml, .opena2a/, .claude/settings.json and CLAUDE.md
 * into the CURRENT directory, signed its package.json, and reported success
 * for the target it never touched. The end-to-end case asserts both
 * directions, because a test that only checks the target would pass on a
 * build that writes to both.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

import { resolveInitTarget } from '../../src/commands/shield.js';

const CLI_PATH = path.resolve(__dirname, '../../dist/index.js');
const HARDENING_ARTIFACTS = ['arp.yaml', '.opena2a', 'CLAUDE.md', '.claude'];

let scratch: string;

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(tmpdir(), 'shield-init-positional-'));
});

afterEach(() => {
  fs.rmSync(scratch, { recursive: true, force: true });
});

function mkdir(name: string): string {
  const dir = path.join(scratch, name);
  fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name }) + '\n');
  return dir;
}

describe('resolveInitTarget (#268)', () => {
  it('uses the positional directory, resolved', () => {
    const target = mkdir('target');
    const rel = path.relative(process.cwd(), target);
    expect(resolveInitTarget({ args: [rel] })).toEqual({ targetDir: target });
  });

  it('uses --dir, resolved', () => {
    const target = mkdir('target');
    expect(resolveInitTarget({ dir: target })).toEqual({ targetDir: target });
  });

  it('accepts the positional and --dir when they name the same directory', () => {
    const target = mkdir('target');
    expect(resolveInitTarget({ args: [target], dir: `${target}/` })).toEqual({ targetDir: target });
  });

  it('leaves the target unset with no directory argument (shieldInit defaults to cwd)', () => {
    expect(resolveInitTarget({ args: [] })).toEqual({});
    expect(resolveInitTarget({})).toEqual({});
  });

  it('refuses two different directories instead of picking one', () => {
    const a = mkdir('a');
    const b = mkdir('b');
    const { targetDir, error } = resolveInitTarget({ args: [a], dir: b });
    expect(targetDir).toBeUndefined();
    expect(error).toContain('two different directories');
    expect(error).toContain('Fix: ');
  });

  it('refuses more than one positional', () => {
    const a = mkdir('a');
    const b = mkdir('b');
    const { error } = resolveInitTarget({ args: [a, b] });
    expect(error).toContain('takes one directory, got 2');
  });

  it('refuses a path that is not a directory', () => {
    const missing = path.join(scratch, 'missing');
    expect(resolveInitTarget({ args: [missing] }).error).toContain(`${missing} is not a directory`);
    const file = path.join(mkdir('proj'), 'package.json');
    expect(resolveInitTarget({ dir: file }).error).toContain('is not a directory');
  });
});

describe('opena2a shield init <dir> end to end (#268)', () => {
  function runInit(args: string[], cwd: string): { status: number | null; stderr: string } {
    const home = path.join(scratch, 'home');
    fs.mkdirSync(home, { recursive: true });
    const res = spawnSync(process.execPath, [CLI_PATH, 'shield', 'init', ...args, '--ci'], {
      cwd,
      encoding: 'utf8',
      timeout: 60000,
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: path.join(home, '.config'),
        NODE_OPTIONS: '',
        NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off',
      },
    });
    return { status: res.status, stderr: res.stderr };
  }

  it('dist/index.js exists (run `npm run build` first)', () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);
  });

  it('hardens the named directory and leaves the current directory untouched', () => {
    const cwd = mkdir('unrelated-cwd');
    const target = mkdir('intended-target');

    const { status } = runInit([target], cwd);
    expect(status).toBe(0);

    for (const artifact of HARDENING_ARTIFACTS) {
      expect(fs.existsSync(path.join(target, artifact)), `${artifact} in target`).toBe(true);
      expect(fs.existsSync(path.join(cwd, artifact)), `${artifact} in cwd`).toBe(false);
    }
  }, 90000);

  it('exits 1 and writes nothing when the positional is not a directory', () => {
    const cwd = mkdir('unrelated-cwd');
    const missing = path.join(scratch, 'does-not-exist');

    const { status, stderr } = runInit([missing], cwd);
    expect(status).toBe(1);
    expect(stderr).toContain('is not a directory');
    for (const artifact of HARDENING_ARTIFACTS) {
      expect(fs.existsSync(path.join(cwd, artifact)), `${artifact} in cwd`).toBe(false);
    }
  }, 90000);
});

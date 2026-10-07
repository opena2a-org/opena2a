/**
 * `opena2a --quiet review` reaches review() with quiet set (#388).
 *
 * review.test.ts calls review() directly, so it cannot see the global
 * `--quiet` being dropped between the option parser and the command. This
 * runs the built `dist/index.js`.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

const CLI_PATH = path.resolve(__dirname, '../../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let scratch: string;

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(tmpdir(), 'review-global-quiet-'));
});

afterEach(() => {
  fs.rmSync(scratch, { recursive: true, force: true });
});

function runCli(args: string[]): { status: number | null; stdout: string } {
  // A fresh home, so the Shield event log and config of the host stay out.
  const home = path.join(scratch, 'home');
  fs.mkdirSync(home);
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
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
  return { status: res.status, stdout: (res.stdout ?? '').replace(STRIP_ANSI, '') };
}

describe('opena2a --quiet review', () => {
  it('dist/index.js exists', () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);
  });

  it('prints the score, the finding counts and the report path only', () => {
    const project = path.join(scratch, 'project');
    fs.mkdirSync(project);
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'quiet-cli' }));
    fs.writeFileSync(path.join(project, '.gitignore'), '.env\n');
    const reportPath = path.join(scratch, 'report.html');

    const { status, stdout } = runCli([
      '--quiet', 'review', project, '--skip-hma', '--no-open', '--report', reportPath,
    ]);

    expect(status).toBe(0);
    const lines = stdout.split('\n').filter(l => l.trim() !== '');
    expect(lines).toHaveLength(3);
    expect(lines[0]).toMatch(/^ {2}Score: \d+\/100/);
    expect(lines[1]).toMatch(/^ {2}\d+ findings \(\d+ critical, \d+ high, \d+ medium\)$/);
    expect(lines[2]).toBe(`  Report: ${reportPath}`);
    expect(fs.existsSync(reportPath)).toBe(true);
  });
});

/**
 * `opena2a broker --help` prints the broker's own usage.
 *
 * The broker adapter runs `secretless-ai broker`, and secretless-ai answers
 * `broker --help` with its top-level help: every `secretless-ai` verb,
 * rebranded to `opena2a secrets ...` lines, and nothing about the broker.
 * The broker's usage is now printed by opena2a and --help is not passed on.
 * Exercises the built `dist/index.js`, because the help is printed by the
 * command's action.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let root: string;
let env: NodeJS.ProcessEnv;

function run(args: string[]): { status: number | null; stdout: string } {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: root,
    encoding: 'utf8',
    timeout: 60_000,
    env,
  });
  return { status: res.status, stdout: (res.stdout ?? '').replace(STRIP_ANSI, '') };
}

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'opena2a-broker-help-'));
  const home = join(root, 'home');
  mkdirSync(home);
  env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: 'off',
    CI: '1',
  };
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('opena2a broker --help', () => {
  for (const args of [['broker', '--help'], ['broker', '-h'], ['broker', 'start', '--help']]) {
    it(`${args.join(' ')} prints the broker usage and no secrets usage`, () => {
      const { status, stdout } = run(args);
      expect(status).toBe(0);
      expect(stdout).toContain('Usage: opena2a broker <start|stop|status>');
      expect(stdout).toMatch(/^ {2}start +Start the credential broker daemon/m);
      expect(stdout).toMatch(/^ {2}stop +Stop the running broker daemon/m);
      expect(stdout).toMatch(/^ {2}status +Show broker daemon status/m);
      expect(stdout).toMatch(/^ {2}--aim-url <url> /m);
      expect(stdout).toMatch(/^ {2}--port <port> /m);
      expect(stdout).not.toContain('opena2a secrets');
      expect(stdout).not.toContain('secretless-ai init');
      expect(stdout).not.toContain('Usage: opena2a broker [args...]');
    });
  }
});

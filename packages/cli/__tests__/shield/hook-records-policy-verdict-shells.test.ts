/**
 * (f) The installed hook in real interactive shells.
 *
 * For zsh and bash with default options, bash with `shopt -s extdebug`, zsh
 * with `setopt ERR_EXIT` and bash with `set -e` in turn: a scratch HOME under
 * `env -i` with telemetry off; the rc file holds the case's option line, if
 * any, then the hook text `shield init --shell-hook` writes; the policy is
 * the default under `mode: enforce`, which denies `aws`; PATH holds only a
 * stub `aws` that appends a line to a marker file and an `opena2a` that runs
 * this build (dist/index.js). Typing `aws s3 ls`:
 *   - prints the MONITORED line that states the verdict, and
 *   - leaves, as the last event, the monitored record of the deny with no
 *     field about whether the command ran, the same record cell (a) asserts
 *     in-process.
 * With default options zsh and bash run the stub. The hook returns non-zero
 * when `evaluate` exits 1, and the other cases act on that: in bash with
 * extdebug set the stub does not run, because bash skips a command when the
 * DEBUG trap returns non-zero; with errexit the shell exits with a non-zero
 * status before the stub runs and before `echo AFTER`. The record and the
 * line are the same in each case, which is why neither claims the command
 * ran.
 *
 * Before the cell types the command, a guard run in the same shell form
 * checks that `aws` resolves to the stub and that errexit and, in bash,
 * extdebug are in the state the cell expects. PATH holds nothing else, so
 * `aws` can resolve to the stub or to nothing.
 *
 * A shell not installed where the suite runs is reported as a skipped case,
 * never as a pass. dist/index.js must exist (`npm run build`).
 */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { describe, it, expect } from 'vitest';
import { getExpectedHookContent } from '../../src/shield/integrity.js';
import { createDefaultPolicy, savePolicy } from '../../src/shield/policy.js';
import { SHIELD_DIR, SHIELD_EVENTS_FILE, SHIELD_POLICY_FILE } from '../../src/shield/types.js';

const CLI_PATH = path.resolve(__dirname, '../../dist/index.js');
const ENV_BIN = '/usr/bin/env';

const ENFORCE_HOOK_LINE =
  'MONITORED  rule=processes.deny:aws  mode=enforce  Recorded; by default zsh and bash still run the command.';

const ANSI = new RegExp(String.fromCharCode(27) + '\\[[0-9;]*m', 'g');
const plain = (text: string): string => text.replace(ANSI, '');

/** The first executable `name` in the usual system locations, or null. */
function findShell(name: 'zsh' | 'bash'): string | null {
  for (const dir of ['/bin', '/usr/bin', '/usr/local/bin', '/opt/homebrew/bin']) {
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // Not in this location.
    }
  }
  return null;
}

interface ShellCase {
  name: 'zsh' | 'bash';
  path: string | null;
  rc: string;
  /** The shell option line that precedes the hook text in the rc file; null for the default options. */
  option: 'shopt -s extdebug' | 'setopt ERR_EXIT' | 'set -e' | null;
  /**
   * What the shell does with the denied command after the hook returns 1:
   * runs it, skips it (bash with extdebug), or exits before running it
   * (errexit).
   */
  then: 'runs' | 'skips' | 'exits';
}

const CASES: ShellCase[] = [
  { name: 'zsh', path: findShell('zsh'), rc: '.zshrc', option: null, then: 'runs' },
  { name: 'bash', path: findShell('bash'), rc: '.bashrc', option: null, then: 'runs' },
  { name: 'bash', path: findShell('bash'), rc: '.bashrc', option: 'shopt -s extdebug', then: 'skips' },
  { name: 'zsh', path: findShell('zsh'), rc: '.zshrc', option: 'setopt ERR_EXIT', then: 'exits' },
  { name: 'bash', path: findShell('bash'), rc: '.bashrc', option: 'set -e', then: 'exits' },
];

const OUTCOME: Record<ShellCase['then'], string> = {
  runs: 'the command runs',
  skips: 'bash skips the command',
  exits: 'the shell exits before the command',
};

interface LoggedEvent {
  action: string;
  outcome: string;
  severity: string;
  target: string;
  detail: Record<string, unknown>;
}

describe('(f) the installed hook in a real interactive shell, mode: enforce', () => {
  for (const shell of CASES) {
    const label = shell.option ? `${shell.name} -i with ${shell.option}` : `${shell.name} -i`;
    it.skipIf(shell.path === null)(
      `${label}: typing aws s3 ls prints the MONITORED line, ${OUTCOME[shell.then]}, and the deny is recorded as monitored with no field about whether the command ran`,
      () => {
        expect(fs.existsSync(CLI_PATH), `${CLI_PATH} is missing: run npm run build`).toBe(true);
        const shellPath = shell.path as string;
        const home = fs.mkdtempSync(path.join(tmpdir(), `shield-hook-${shell.name}-`));
        try {
          const bin = path.join(home, 'bin');
          const marker = path.join(home, 'aws-ran.txt');
          fs.mkdirSync(bin);
          for (const p of [process.execPath, CLI_PATH, marker]) {
            // The stub scripts single-quote these paths.
            if (p.includes("'")) throw new Error(`path carries a single quote: ${p}`);
          }
          fs.writeFileSync(
            path.join(bin, 'opena2a'),
            `#!/bin/sh\nexec '${process.execPath}' '${CLI_PATH}' "$@"\n`,
            { mode: 0o755 },
          );
          fs.writeFileSync(path.join(bin, 'aws'), `#!/bin/sh\nprintf 'ran %s\\n' "$*" >> '${marker}'\n`, {
            mode: 0o755,
          });

          const policy = createDefaultPolicy('enforce');
          expect(policy.default.processes.deny).toContain('aws');
          savePolicy(policy, path.join(home, SHIELD_DIR, SHIELD_POLICY_FILE));
          // What `shield init --shell-hook` appends to the rc file, after the
          // shell option the case sets.
          const rcPrefix = shell.option ? `${shell.option}\n` : '';
          fs.writeFileSync(path.join(home, shell.rc), '\n' + rcPrefix + getExpectedHookContent(shell.name) + '\n', {
            mode: 0o600,
          });

          const typeInto = (input: string) =>
            spawnSync(
              ENV_BIN,
              [
                '-i',
                `HOME=${home}`,
                `PATH=${bin}`,
                'OPENA2A_TELEMETRY=off',
                'DO_NOT_TRACK=1',
                'OPENA2A_AUTH_FORCE_FILE=1',
                'HARNESS_NO_LIVE_TRANSPORT=1',
                shellPath,
                '-i',
              ],
              { cwd: home, input, encoding: 'utf-8', timeout: 30_000 },
            );

          // Guard: in this shell form, `aws` is the stub, and errexit and, in
          // bash, extdebug are in the state the case expects. Each state is
          // printed from an `if`, so a false test does not end an errexit
          // shell before the next line.
          const guardLines = ['command -v aws', "if [[ -o errexit ]]; then echo 'errexit on'; else echo 'errexit off'; fi"];
          if (shell.name === 'bash') {
            guardLines.push("if shopt -q extdebug; then echo 'extdebug on'; else echo 'extdebug off'; fi");
          }
          const guard = typeInto([...guardLines, 'exit', ''].join('\n'));
          expect(guard.error).toBeUndefined();
          const guardOut = guard.stdout.split('\n');
          expect(guardOut).toContain(path.join(bin, 'aws'));
          expect(guardOut).toContain(`errexit ${shell.then === 'exits' ? 'on' : 'off'}`);
          if (shell.name === 'bash') {
            expect(guardOut).toContain(`extdebug ${shell.option === 'shopt -s extdebug' ? 'on' : 'off'}`);
          }
          expect(fs.existsSync(marker)).toBe(false);

          const result = typeInto('aws s3 ls\necho AFTER\nexit\n');
          expect(result.error).toBeUndefined();
          if (shell.then === 'exits') {
            // errexit: the shell exits on the hook's non-zero return.
            // toBeGreaterThan fails on a null status, so a shell ended by a
            // signal does not pass.
            expect(result.status).toBeGreaterThan(0);
          } else {
            expect(result.status).toBe(0);
          }
          expect(result.stdout + result.stderr).not.toContain('refused: HARNESS_NO_LIVE_TRANSPORT');

          if (shell.then === 'runs') {
            // With default options the shell still runs the command.
            expect(fs.readFileSync(marker, 'utf-8')).toBe('ran s3 ls\n');
          } else {
            // bash with extdebug skips the command after the trap returns 1;
            // with errexit the shell exits before running it.
            expect(fs.existsSync(marker)).toBe(false);
          }

          const events = fs
            .readFileSync(path.join(home, SHIELD_DIR, SHIELD_EVENTS_FILE), 'utf-8')
            .split('\n')
            .filter(line => line.trim() !== '')
            .map(line => JSON.parse(line) as LoggedEvent);
          expect(events.filter(e => e.outcome === 'blocked' || e.action === 'command.blocked')).toEqual([]);
          const last = events[events.length - 1];
          expect(last).toMatchObject({
            action: 'command.monitored',
            outcome: 'monitored',
            severity: 'medium',
            target: 'aws s3 ls',
          });
          // The same record whether or not the shell ran the command, so it
          // carries no `stopped` field; toEqual is exact on keys.
          expect(last.detail).toEqual({
            rule: 'processes.deny:aws',
            mode: 'enforce',
            verdict: 'deny',
          });
          expect(Object.keys(last.detail)).not.toContain('stopped');

          const lines = plain(result.stdout).split('\n');
          expect(lines).toContain(ENFORCE_HOOK_LINE);
          if (shell.then === 'exits') {
            // The shell exited before reading `echo AFTER`.
            expect(lines).not.toContain('AFTER');
          } else {
            expect(lines.indexOf(ENFORCE_HOOK_LINE)).toBeLessThan(lines.indexOf('AFTER'));
          }
          expect(plain(result.stdout)).not.toMatch(/blocked/i);
        } finally {
          fs.rmSync(home, { recursive: true, force: true });
        }
      },
      60_000,
    );
  }
});

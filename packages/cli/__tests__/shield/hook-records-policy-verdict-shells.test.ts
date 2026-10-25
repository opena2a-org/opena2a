/**
 * (f) The installed hook in real interactive shells.
 *
 * For zsh and bash in turn: a scratch HOME under `env -i` with telemetry
 * off; the rc file holds the hook text `shield init --shell-hook` writes;
 * the policy is the default under `mode: enforce`, which denies `aws`; PATH
 * holds only a stub `aws` that appends a line to a marker file and an
 * `opena2a` that runs this build (dist/index.js). Typing `aws s3 ls`:
 *   - prints the MONITORED line that states the verdict,
 *   - runs the stub (shell hooks do not stop commands), and
 *   - leaves, as the last event, the monitored record of the deny with
 *     `stopped: false`, the same record cell (a) asserts in-process.
 *
 * Before the cell types the command, a guard run in the same shell form
 * checks that `aws` resolves to the stub. PATH holds nothing else, so it can
 * resolve to the stub or to nothing.
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
  'MONITORED  rule=processes.deny:aws  mode=enforce  Recorded; shell hooks do not stop commands.';

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

const SHELLS = [
  { name: 'zsh' as const, path: findShell('zsh'), rc: '.zshrc' },
  { name: 'bash' as const, path: findShell('bash'), rc: '.bashrc' },
];

interface LoggedEvent {
  action: string;
  outcome: string;
  severity: string;
  target: string;
  detail: Record<string, unknown>;
}

describe('(f) the installed hook in a real interactive shell, mode: enforce', () => {
  for (const shell of SHELLS) {
    it.skipIf(shell.path === null)(
      `${shell.name} -i: typing aws s3 ls prints the MONITORED line, the command runs, and the deny is recorded as monitored with stopped false`,
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
          // What `shield init --shell-hook` appends to the rc file.
          fs.writeFileSync(path.join(home, shell.rc), '\n' + getExpectedHookContent(shell.name) + '\n', {
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

          // Guard: in this shell form, `aws` is the stub.
          const guard = typeInto('command -v aws\nexit\n');
          expect(guard.error).toBeUndefined();
          expect(guard.stdout.split('\n')).toContain(path.join(bin, 'aws'));
          expect(fs.existsSync(marker)).toBe(false);

          const result = typeInto('aws s3 ls\necho AFTER\nexit\n');
          expect(result.error).toBeUndefined();
          expect(result.status).toBe(0);
          expect(result.stdout + result.stderr).not.toContain('refused: HARNESS_NO_LIVE_TRANSPORT');

          // The command ran: shell hooks do not stop commands.
          expect(fs.readFileSync(marker, 'utf-8')).toBe('ran s3 ls\n');

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
          expect(last.detail).toEqual({
            rule: 'processes.deny:aws',
            mode: 'enforce',
            verdict: 'deny',
            stopped: false,
          });

          const lines = plain(result.stdout).split('\n');
          expect(lines).toContain(ENFORCE_HOOK_LINE);
          expect(lines.indexOf(ENFORCE_HOOK_LINE)).toBeLessThan(lines.indexOf('AFTER'));
          expect(plain(result.stdout)).not.toMatch(/blocked/i);
        } finally {
          fs.rmSync(home, { recursive: true, force: true });
        }
      },
      60_000,
    );
  }
});

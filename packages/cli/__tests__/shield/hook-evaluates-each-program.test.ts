/**
 * In hook mode, `opena2a shield evaluate "<line>"` evaluates each program the
 * command line names against the policy, and records each deny the way a
 * deny of a bare program name is recorded: one `command.monitored` event
 * whose target is the line, carrying the rule (and, under mode: enforce,
 * `verdict: "deny"`), and one MONITORED line on stdout.
 *
 * Both installed hooks pass the whole line as one argument: zsh's preexec
 * passes the line as typed, bash's DEBUG trap passes $BASH_COMMAND. The line
 * is split at unquoted `;`, `&&`, `||`, `|`, `&` and newlines. In each part,
 * leading NAME=value assignments and the wrappers env, command, exec, nohup,
 * nice, time, timeout, sudo and xargs, with their options, are set aside,
 * and the first word left is the program: it is evaluated by its basename
 * and, when written as a path, by that path as well. The programs inside a
 * `bash -c` string and a command substitution are evaluated too.
 *
 * Every cell runs under a scratch HOME (homedir() points at a fresh
 * directory) with a policy whose processes.deny holds `aws`, called the way
 * the installed hook calls it: one positional argument, no --dir. The pattern
 * `aws` matches the target `aws` exactly and nothing else, so a record
 * carrying `processes.deny:aws` is a deny of the program `aws`.
 *
 * Cells: (a) a program run by its path, (b) a program after a separator,
 * (c) a program behind an assignment or a wrapper, (d) a program inside a
 * `bash -c` string or a command substitution, (e) controls, (f) the shape of
 * the record across modes, outputs and lines holding more than one deny.
 * The splitter itself is covered in command-line.test.ts.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// homedir() points at a fresh scratch directory for every test, so the
// policy and the event log a cell reads are never the real ones.
let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

const { shield } = await import('../../src/commands/shield.js');
const { savePolicy, createDefaultPolicy, evaluatePolicy } = await import('../../src/shield/policy.js');
const { getEventsPath } = await import('../../src/shield/events.js');
const { SHIELD_DIR, SHIELD_POLICY_FILE } = await import('../../src/shield/types.js');

type Mode = 'adaptive' | 'monitor' | 'enforce';

/** The line a hook-mode deny of `aws` under enforce prints, colours removed. */
const ENFORCE_HOOK_LINE =
  'MONITORED  rule=processes.deny:aws  mode=enforce  Recorded; by default zsh and bash still run the command.\n';

const ANSI = new RegExp(String.fromCharCode(27) + '\\[[0-9;]*m', 'g');
const plain = (text: string): string => text.replace(ANSI, '');

interface LoggedEvent {
  source: string;
  category: string;
  severity: string;
  action: string;
  target: string;
  outcome: string;
  detail: Record<string, unknown>;
}

let tempDir: string;
let stdout: string;
let stderr: string;
let stdoutSpy: ReturnType<typeof vi.spyOn>;
let stderrSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-hook-programs-'));
  _mockHomeDir = tempDir;
  stdout = '';
  stderr = '';
  stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    stdout += String(chunk);
    return true;
  });
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    stderr += String(chunk);
    return true;
  });
});

afterEach(() => {
  stdoutSpy.mockRestore();
  stderrSpy.mockRestore();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

/** Save a policy for `mode` whose processes.deny is `processDeny`, where loadPolicy() finds it. */
function writePolicy(mode: Mode, processDeny: string[] = ['aws']) {
  const policy = createDefaultPolicy(mode);
  policy.default.processes.deny = [...processDeny];
  const policyPath = path.join(tempDir, SHIELD_DIR, SHIELD_POLICY_FILE);
  savePolicy(policy, policyPath);
  // Guard the fixture: a wrong path would turn every cell into a no-policy
  // run that passes or fails for the wrong reason.
  if (!fs.existsSync(policyPath)) {
    throw new Error(`fixture not written: ${policyPath}`);
  }
  return policy;
}

/** Every event in the scratch HOME's log, oldest first. */
function loggedEvents(): LoggedEvent[] {
  const eventsPath = getEventsPath();
  if (!fs.existsSync(eventsPath)) return [];
  return fs
    .readFileSync(eventsPath, 'utf-8')
    .split('\n')
    .filter(line => line.trim() !== '')
    .map(line => JSON.parse(line) as LoggedEvent);
}

/**
 * Evaluate `line` the way the installed hook does under mode: enforce, and
 * assert one deny of `aws` recorded and printed as the bare `aws s3 ls` is.
 */
async function expectOneDenyOfAws(line: string): Promise<void> {
  writePolicy('enforce');

  const code = await shield({ subcommand: 'evaluate', args: [line] });

  const events = loggedEvents();
  expect(events).toHaveLength(1);
  expect(events[0]).toMatchObject({
    source: 'shield',
    category: 'enforcement',
    action: 'command.monitored',
    outcome: 'monitored',
    severity: 'medium',
    target: line,
  });
  // toEqual is exact on keys: the same three fields a bare-name deny carries.
  expect(events[0].detail).toEqual({
    rule: 'processes.deny:aws',
    mode: 'enforce',
    verdict: 'deny',
  });
  expect(plain(stdout)).toBe(ENFORCE_HOOK_LINE);
  expect(plain(stderr)).toBe('');
  expect(code).toBe(1);
}

// ===========================================================================
// (a) A program run by its path
// ===========================================================================

describe('(a) a program run by its path is evaluated by its basename', () => {
  it('the policy denies the name aws and not the paths these lines use', () => {
    // So the deny each cell below records comes from the basename.
    const policy = writePolicy('enforce');
    expect(evaluatePolicy(policy, null, 'processes', 'aws').rule).toBe('processes.deny:aws');
    for (const written of ['/usr/bin/aws', './aws', '../bin/aws']) {
      expect(evaluatePolicy(policy, null, 'processes', written).outcome).toBe('allowed');
    }
  });

  it.each(['/usr/bin/aws s3 ls', './aws s3 ls', '../bin/aws s3 ls'])(
    '%s records one deny of aws',
    async (line) => {
      await expectOneDenyOfAws(line);
    },
  );
});

// ===========================================================================
// (b) A program after a separator
// ===========================================================================

describe('(b) a program after a separator is evaluated', () => {
  it.each([
    'true; aws s3 ls',
    'true && aws s3 ls',
    'true || aws s3 ls',
    'echo x | aws s3 ls',
    'sleep 1 & aws s3 ls',
  ])('%s records one deny of aws', async (line) => {
    await expectOneDenyOfAws(line);
  });
});

// ===========================================================================
// (c) A program behind an assignment or a wrapper
// ===========================================================================

describe('(c) a program behind an assignment or a wrapper is evaluated', () => {
  it.each([
    'env AWS_PROFILE=x aws s3 ls',
    'AWS_PROFILE=x aws s3 ls',
    'sudo aws s3 ls',
    'command aws s3 ls',
    'exec aws s3 ls',
    'nohup aws s3 ls',
    'nice -n 5 aws s3 ls',
    'timeout 5 aws s3 ls',
    'xargs aws < /dev/null',
  ])('%s records one deny of aws', async (line) => {
    await expectOneDenyOfAws(line);
  });
});

// ===========================================================================
// (d) A program inside a bash -c string or a command substitution
// ===========================================================================

describe('(d) a program inside a bash -c string or a command substitution is evaluated', () => {
  it.each(['bash -c "aws s3 ls"', 'echo $(aws s3 ls)'])(
    '%s records one deny of aws',
    async (line) => {
      await expectOneDenyOfAws(line);
    },
  );
});

// ===========================================================================
// (e) Controls
// ===========================================================================

describe('(e) controls', () => {
  it.each(['ls -la', 'echo aws-docs'])(
    '%s records nothing, prints nothing and exits 0',
    async (line) => {
      writePolicy('enforce');

      const code = await shield({ subcommand: 'evaluate', args: [line] });

      expect(loggedEvents()).toEqual([]);
      expect(stdout).toBe('');
      expect(stderr).toBe('');
      expect(code).toBe(0);
    },
  );

  it('the bare aws s3 ls records exactly one deny of aws', async () => {
    await expectOneDenyOfAws('aws s3 ls');
  });

  it.each([
    'command -v aws',
    'echo aws',
    'ls > aws',
    "cat <<'EOF'\naws s3 ls\nEOF",
    'case $p in aws) echo cloud ;; esac',
    'ls (aws|gcloud)*',
  ])('%j names aws without running it: it records nothing, prints nothing and exits 0', async (line) => {
    writePolicy('enforce');

    const code = await shield({ subcommand: 'evaluate', args: [line] });

    expect(loggedEvents()).toEqual([]);
    expect(stdout).toBe('');
    expect(code).toBe(0);
  });
});

// ===========================================================================
// (f) The record across modes, outputs and lines holding more than one deny
// ===========================================================================

describe('(f) each deny on the line is recorded as a bare-name deny is', () => {
  it('time aws s3 ls records one deny of aws', async () => {
    await expectOneDenyOfAws('time aws s3 ls');
  });

  it.each(['monitor', 'adaptive'] as const)(
    'under mode: %s a program run by its path is recorded with the rule and the mode, and exits 0',
    async (mode) => {
      writePolicy(mode);

      const code = await shield({ subcommand: 'evaluate', args: ['/usr/bin/aws s3 ls'] });

      const events = loggedEvents();
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        action: 'command.monitored',
        outcome: 'monitored',
        severity: 'medium',
        target: '/usr/bin/aws s3 ls',
      });
      expect(events[0].detail).toEqual({ rule: 'processes.deny:aws', mode });
      expect(plain(stdout)).toBe('MONITORED  rule=processes.deny:aws\n');
      expect(plain(stderr)).toBe('');
      expect(code).toBe(0);
    },
  );

  it('--format json prints the one decision object, the deny, and records it', async () => {
    writePolicy('enforce');

    const code = await shield({
      subcommand: 'evaluate',
      args: ['/usr/bin/aws s3 ls'],
      format: 'json',
    });

    expect(JSON.parse(stdout)).toEqual({
      allowed: false,
      outcome: 'blocked',
      rule: 'processes.deny:aws',
      agent: null,
    });
    const events = loggedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].detail).toEqual({ rule: 'processes.deny:aws', mode: 'enforce', verdict: 'deny' });
    expect(code).toBe(1);
  });

  it('a line passed as several arguments is read whole, a path-form word included', async () => {
    writePolicy('enforce');

    const code = await shield({ subcommand: 'evaluate', args: ['/usr/bin/aws', 's3', 'ls'] });

    const events = loggedEvents();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ action: 'command.monitored', target: '/usr/bin/aws s3 ls' });
    expect(events[0].detail).toEqual({ rule: 'processes.deny:aws', mode: 'enforce', verdict: 'deny' });
    expect(plain(stdout)).toBe(ENFORCE_HOOK_LINE);
    expect(code).toBe(1);
  });

  it('two programs denied by two rules make two records and two lines, in line order', async () => {
    writePolicy('enforce', ['aws', 'gcloud']);
    const line = 'aws s3 ls; gcloud auth list';

    const code = await shield({ subcommand: 'evaluate', args: [line] });

    const events = loggedEvents();
    expect(events.map(event => event.detail)).toEqual([
      { rule: 'processes.deny:aws', mode: 'enforce', verdict: 'deny' },
      { rule: 'processes.deny:gcloud', mode: 'enforce', verdict: 'deny' },
    ]);
    for (const event of events) {
      expect(event).toMatchObject({ action: 'command.monitored', outcome: 'monitored', target: line });
    }
    expect(plain(stdout)).toBe(ENFORCE_HOOK_LINE + ENFORCE_HOOK_LINE.replace('aws', 'gcloud'));
    expect(code).toBe(1);
  });

  it('one rule that denies two programs on the line makes one record', async () => {
    await expectOneDenyOfAws('aws s3 ls && /usr/local/bin/aws s3 ls');
  });

  it('a rule written as a path denies a program by the path it is written as', async () => {
    writePolicy('enforce', ['/usr/local/bin/*']);
    const line = '/usr/local/bin/aws s3 ls';

    const code = await shield({ subcommand: 'evaluate', args: [line] });

    const events = loggedEvents();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ action: 'command.monitored', target: line });
    expect(events[0].detail).toEqual({
      rule: 'processes.deny:/usr/local/bin/*',
      mode: 'enforce',
      verdict: 'deny',
    });
    expect(plain(stdout)).toBe(ENFORCE_HOOK_LINE.replace('aws', '/usr/local/bin/*'));
    expect(code).toBe(1);
  });

  it('a program denied by its basename and by its path makes one record per rule', async () => {
    writePolicy('enforce', ['aws', '/usr/local/bin/*']);
    const line = '/usr/local/bin/aws s3 ls';

    const code = await shield({ subcommand: 'evaluate', args: [line] });

    expect(loggedEvents().map(event => event.detail)).toEqual([
      { rule: 'processes.deny:aws', mode: 'enforce', verdict: 'deny' },
      { rule: 'processes.deny:/usr/local/bin/*', mode: 'enforce', verdict: 'deny' },
    ]);
    expect(plain(stdout)).toBe(ENFORCE_HOOK_LINE + ENFORCE_HOOK_LINE.replace('aws', '/usr/local/bin/*'));
    expect(code).toBe(1);
  });
});

/**
 * `opena2a shield evaluate`, as the shell hook runs it, records the policy
 * verdict. The hook does not stop commands in zsh, or in bash unless
 * extdebug is set.
 *
 * `shield init --shell-hook` installs a zsh `preexec` function or a bash
 * `DEBUG` trap that runs `opena2a shield evaluate "<command line>"` before
 * the shell runs each interactive command, with stderr discarded. `evaluate`
 * runs as a child of the shell: it does not stop the command and cannot see
 * what the shell does next. So under `mode: enforce` a deny is recorded as
 * `command.monitored` with `verdict: "deny"` and no field about whether the
 * command ran, and the one line the hook keeps (stdout) states the verdict
 * and that the hook does not stop commands in zsh, or in bash unless
 * extdebug is set. With `shopt -s extdebug`, bash skips a command when the
 * DEBUG trap returns non-zero, which the hook does when `evaluate` exits 1.
 *
 * A check with an explicit `--action`/`--target` attempts nothing, so it
 * writes no event. It prints its verdict and exits 1 on a deny under
 * `mode: enforce`.
 *
 * Cells: (a) a hook-mode deny under enforce, (b) an explicit check writes no
 * event, (c) the property across modes and invocation forms, (d) the hook
 * text is pinned so installed hooks keep matching selfcheck, (e) no help,
 * option or setup string says a hook stops, blocks or prevents a command.
 * (f), the same hook in real zsh and bash, is in
 * hook-records-policy-verdict-shells.test.ts.
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
const { writeEvent, getEventsPath } = await import('../../src/shield/events.js');
const { getExpectedHookContent } = await import('../../src/shield/integrity.js');
const { SHIELD_HELP } = await import('../../src/util/subcommand-help.js');
const { SHIELD_DIR, SHIELD_POLICY_FILE } = await import('../../src/shield/types.js');

type Mode = 'adaptive' | 'monitor' | 'enforce';

/** The line a hook-mode deny under enforce prints, colours removed. */
const ENFORCE_HOOK_LINE =
  'MONITORED  rule=processes.deny:aws  mode=enforce  Recorded; the hook does not stop commands in zsh, or in bash unless extdebug is set.\n';

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
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-hook-verdict-'));
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

/** Save the default policy for `mode` in the scratch HOME, where loadPolicy() finds it. */
function writePolicy(mode: Mode, extraFilesystemDeny: string[] = []) {
  const policy = createDefaultPolicy(mode);
  policy.default.filesystem.deny.push(...extraFilesystemDeny);
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

/** One unrelated event, so a byte comparison of the log compares a real file. */
function seedEventLog(): Buffer {
  writeEvent({
    source: 'shield',
    category: 'lifecycle',
    severity: 'info',
    agent: null,
    sessionId: null,
    action: 'test.seed',
    target: 'seed',
    outcome: 'allowed',
    detail: {},
    orgId: null,
    managed: false,
    agentId: null,
  });
  return fs.readFileSync(getEventsPath());
}

function expectLogUnchanged(before: Buffer): void {
  const after = fs.readFileSync(getEventsPath());
  // The text comparison names any added line; the byte comparison is exact.
  expect(after.toString('utf-8')).toBe(before.toString('utf-8'));
  expect(Buffer.compare(after, before)).toBe(0);
}

// ===========================================================================
// (a) A deny the hook evaluates under mode: enforce
// ===========================================================================

describe('(a) hook-mode deny under mode: enforce', () => {
  it('records command.monitored with verdict deny and no field about whether the command ran, prints the MONITORED line on stdout, and exits 1', async () => {
    writePolicy('enforce');

    // The installed hook's form: one positional argument, no --dir.
    const code = await shield({ subcommand: 'evaluate', args: ['aws s3 ls'] });

    expect(code).toBe(1);

    const events = loggedEvents();
    expect(events.length).toBe(1);
    const last = events[events.length - 1];
    expect(last).toMatchObject({
      source: 'shield',
      category: 'enforcement',
      action: 'command.monitored',
      outcome: 'monitored',
      severity: 'medium',
      target: 'aws s3 ls',
    });
    // toEqual is exact on keys: the record carries no `stopped` field, since
    // this process cannot see whether the shell ran the command.
    expect(last.detail).toEqual({
      rule: 'processes.deny:aws',
      mode: 'enforce',
      verdict: 'deny',
    });
    expect(Object.keys(last.detail)).not.toContain('stopped');

    expect(plain(stdout)).toBe(ENFORCE_HOOK_LINE);
    expect(plain(stderr)).not.toMatch(/blocked/i);
  });

  it.each(['monitor', 'adaptive'] as const)(
    'under mode: %s the hook line and the record keep their shape',
    async (mode) => {
      writePolicy(mode);

      const code = await shield({ subcommand: 'evaluate', args: ['aws s3 ls'] });

      expect(code).toBe(0);
      const events = loggedEvents();
      expect(events.length).toBe(1);
      expect(events[0]).toMatchObject({
        action: 'command.monitored',
        outcome: 'monitored',
        severity: 'medium',
        target: 'aws s3 ls',
      });
      expect(events[0].detail).toEqual({ rule: 'processes.deny:aws', mode });
      expect(plain(stdout)).toBe('MONITORED  rule=processes.deny:aws\n');
      expect(plain(stderr)).toBe('');
    },
  );
});

// ===========================================================================
// (b) A check with an explicit subject writes no event
// ===========================================================================

describe('(b) a check with an explicit --action/--target writes no event', () => {
  it('under mode: enforce prints the BLOCKED verdict block, exits 1, and leaves events.jsonl byte-equal', async () => {
    writePolicy('enforce');
    const before = seedEventLog();

    const code = await shield({
      subcommand: 'evaluate',
      args: [],
      action: 'process.spawn',
      target: 'aws',
    });

    expect(code).toBe(1);
    expect(plain(stdout)).toBe(
      '\n' +
        '  BLOCKED  rule processes.deny:aws\n' +
        '  Evaluated: process.spawn -> aws\n' +
        '  Agent: none\n' +
        '\n',
    );
    expectLogUnchanged(before);
  });

  it.each(['monitor', 'adaptive'] as const)(
    'under mode: %s prints the MONITORED verdict block, exits 0, and leaves events.jsonl byte-equal',
    async (mode) => {
      writePolicy(mode);
      const before = seedEventLog();

      const code = await shield({
        subcommand: 'evaluate',
        args: [],
        action: 'process.spawn',
        target: 'aws',
      });

      expect(code).toBe(0);
      expect(plain(stdout)).toBe(
        '\n' +
          '  MONITORED  rule processes.deny:aws\n' +
          '  Evaluated: process.spawn -> aws\n' +
          '  Agent: none\n' +
          '\n',
      );
      expectLogUnchanged(before);
    },
  );
});

// ===========================================================================
// (c) The property across modes and invocation forms
// ===========================================================================

describe('(c) across modes and invocation forms, no event has outcome blocked and only a check prints a BLOCKED label', () => {
  type Form = 'positional' | 'explicit' | 'none';
  interface FormSubject {
    options: { args: string[]; action?: string; target?: string; category?: string };
    /** What evaluatePolicy is asked, to confirm the form reaches a deny rule. */
    category: string;
    target: string;
  }
  const MODES: Mode[] = ['adaptive', 'monitor', 'enforce'];
  const FORMS: Record<Form, FormSubject> = {
    // The installed hook: the command line as one positional argument.
    positional: { options: { args: ['aws s3 ls'] }, category: 'processes', target: 'aws' },
    // A check: an explicit subject, nothing attempted.
    explicit: {
      options: { args: [], action: 'process.spawn', target: 'aws' },
      category: 'process.spawn',
      target: 'aws',
    },
    // Neither: the filesystem category with no target, which the policy
    // resolves to the working directory.
    none: { options: { args: [], category: 'filesystem' }, category: 'filesystem', target: '' },
  };
  const cells: Array<[Mode, Form]> = MODES.flatMap(mode =>
    (['positional', 'explicit', 'none'] as Form[]).map((form): [Mode, Form] => [mode, form]),
  );
  const VERDICT_LABEL = /^ {2}BLOCKED {2}rule .+$/;

  it.each(cells)('mode %s, %s form', async (mode, form) => {
    // Deny the working directory too, so every form reaches a deny rule and
    // the property cannot hold vacuously.
    const policy = writePolicy(mode, [process.cwd()]);
    const subject = FORMS[form];
    const decision = evaluatePolicy(policy, null, subject.category, subject.target);
    expect(decision.rule).toMatch(/\.deny:/);

    const code = await shield({ subcommand: 'evaluate', ...subject.options });

    expect(code).toBe(mode === 'enforce' ? 1 : 0);

    const events = loggedEvents();
    expect(events.filter(e => e.outcome === 'blocked' || e.action === 'command.blocked')).toEqual([]);
    // A check writes nothing; the other forms write one record of the deny match.
    expect(events.length).toBe(form === 'explicit' ? 0 : 1);
    for (const event of events) {
      expect(event.action).toBe('command.monitored');
      expect(event.outcome).toBe('monitored');
    }

    expect(plain(stderr)).not.toMatch(/blocked/i);
    const blockedLines = plain(stdout)
      .split('\n')
      .filter(line => /blocked/i.test(line));
    if (mode === 'enforce' && form !== 'positional') {
      // The verdict block a check prints: its label line, and nothing else.
      expect(blockedLines.length).toBe(1);
      expect(blockedLines[0]).toMatch(VERDICT_LABEL);
    } else {
      expect(blockedLines).toEqual([]);
    }
  });
});

// ===========================================================================
// (d) The hook text is unchanged
// ===========================================================================

describe('(d) the hook text shield init writes and selfcheck compares', () => {
  // Byte for byte the text installed hooks carry, so an installed hook keeps
  // matching the shell-hook row of selfcheck after an upgrade.
  const ZSH_HOOK =
    '# >>> opena2a shield hook >>>\n' +
    'opena2a_shield_preexec() {\n' +
    '  if ! opena2a shield evaluate "$1" 2>/dev/null; then\n' +
    '    return 1\n' +
    '  fi\n' +
    '}\n' +
    'autoload -Uz add-zsh-hook\n' +
    'add-zsh-hook preexec opena2a_shield_preexec\n' +
    '# <<< opena2a shield hook <<<';
  const BASH_HOOK =
    '# >>> opena2a shield hook >>>\n' +
    'opena2a_shield_debug() {\n' +
    '  if ! opena2a shield evaluate "$BASH_COMMAND" 2>/dev/null; then\n' +
    '    return 1\n' +
    '  fi\n' +
    '}\n' +
    "trap 'opena2a_shield_debug' DEBUG\n" +
    '# <<< opena2a shield hook <<<';

  it('zsh', () => {
    expect(getExpectedHookContent('zsh')).toBe(ZSH_HOOK);
  });

  it('bash', () => {
    expect(getExpectedHookContent('bash')).toBe(BASH_HOOK);
  });
});

// ===========================================================================
// (e) Words: no help, option or setup string says a hook stops a command
// ===========================================================================

const SRC = path.resolve(__dirname, '../../src');
const readSource = (rel: string): string => fs.readFileSync(path.join(SRC, rel), 'utf-8');

/** The text between the first `start` and the next `end` after it. */
function between(source: string, start: string, end: string): string {
  const from = source.indexOf(start);
  if (from < 0) throw new Error(`start marker not found: ${start}`);
  const to = source.indexOf(end, from + start.length);
  if (to < 0) throw new Error(`end marker not found: ${end}`);
  return source.slice(from, to);
}

/** The string literals in a source excerpt, as written; whole-line comments are skipped. */
function stringLiterals(excerpt: string): string[] {
  const code = excerpt
    .split('\n')
    .filter(line => !/^\s*\/\//.test(line))
    .join('\n');
  const literals: string[] = [];
  for (const match of code.matchAll(/'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`/g)) {
    literals.push(match[0].slice(1, -1));
  }
  return literals;
}

/** Every string in a help registry entry tree: summaries, usage, flags, descriptions, examples. */
function allStrings(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(allStrings);
  if (value !== null && typeof value === 'object') return Object.values(value).flatMap(allStrings);
  return [];
}

/** The literals of the `shield` command's definition in index.ts, up to its action. */
function shieldOptionStrings(indexSource: string): string[] {
  return stringLiterals(between(indexSource, ".command('shield [subcommand] [args...]')", '.action('));
}

/** The literals of Step 7 (shell integration) in init.ts. */
function initStep7Strings(initSource: string): string[] {
  return stringLiterals(between(initSource, '// --- Step 7:', '// --- Step 8:'));
}

const STOP_WORD =
  /\b(?:stop|stops|stopped|stopping|block|blocks|blocked|blocking|prevent|prevents|prevented|preventing)\b/gi;
// A negation directly before the word, allowing one word between ("does not
// stop", "never stops", "no longer blocks", "not be blocked").
const NEGATED_BEFORE = /(?:\bnot|\bnever|\bno|\bcannot|n't)\s+(?:\w+\s+)?$/i;
// A clause is in scope when it speaks of a hook or of commands.
const HOOK_OR_COMMAND = /\bhooks?\b|\bpreexec\b|\bshell integration\b|\bcommands?\b/i;

/** True when some clause of `text` says, unnegated, that a hook or a command is stopped, blocked or prevented. */
function claimsAHookStopsACommand(text: string): boolean {
  for (const clause of text.split(/[.;:!?\n]|\\n|\bbut\b/i)) {
    if (!HOOK_OR_COMMAND.test(clause)) continue;
    for (const match of clause.matchAll(STOP_WORD)) {
      if (!NEGATED_BEFORE.test(clause.slice(0, match.index))) return true;
    }
  }
  return false;
}

describe('(e) no shield help entry, shield option or Step 7 line says a hook stops, blocks or prevents a command', () => {
  const helpStrings = allStrings(SHIELD_HELP);
  const optionStrings = shieldOptionStrings(readSource('index.ts'));
  const step7Strings = initStep7Strings(readSource('shield/init.ts'));

  it('reads a non-empty scope from each of the three places', () => {
    expect(helpStrings).toContain('--shell-hook');
    expect(optionStrings).toContain('--shell-hook');
    expect(step7Strings.some(s => s.includes('Shell hooks already installed'))).toBe(true);
    expect(step7Strings.some(s => s.includes('Shell hooks installed in'))).toBe(true);
  });

  it('none of those strings carries the claim', () => {
    const offenders = [...helpStrings, ...optionStrings, ...step7Strings].filter(claimsAHookStopsACommand);
    expect(offenders).toEqual([]);
  });

  // Planted inputs the matcher must flag, built from parts so that each is
  // plainly a test input rather than a statement.
  const SUBJECTS = ['The shell hook', 'The preexec hook', 'Shell integration'];
  const VERBS = ['stops', 'blocks', 'prevents'];
  const planted = [
    ...SUBJECTS.flatMap(subject => VERBS.map(verb => `${subject} ${verb} a denied command`)),
    ['Denied commands are', 'blocked', 'by the hook'].join(' '),
    ['Recorded; the hook', 'stops', 'the command'].join(' '),
    ['The hook records the verdict but', 'prevents', 'denied commands'].join(' '),
  ];

  it('positive control: the matcher fires on every planted string', () => {
    for (const text of planted) {
      expect(claimsAHookStopsACommand(text), text).toBe(true);
    }
  });

  it('positive control: a planted string reaches the matcher through each scope reader', () => {
    const claim = planted[0];
    const indexSource = readSource('index.ts').replace(
      ".option('--shell-hook',",
      `.option('--planted', '${claim}')\n    .option('--shell-hook',`,
    );
    expect(shieldOptionStrings(indexSource).some(claimsAHookStopsACommand)).toBe(true);

    const initSource = readSource('shield/init.ts').replace(
      '// --- Step 8:',
      `process.stdout.write('  ${claim}\\n');\n  // --- Step 8:`,
    );
    expect(initStep7Strings(initSource).some(claimsAHookStopsACommand)).toBe(true);

    const help = structuredClone(SHIELD_HELP) as Record<string, unknown>;
    help.planted = { summary: claim };
    expect(allStrings(help).some(claimsAHookStopsACommand)).toBe(true);
  });

  it('negative control: the wording that states the control does not fire', () => {
    for (const text of [
      'Install a zsh or bash hook that records the policy verdict for each interactive command; it does not stop commands in zsh, or in bash unless extdebug is set',
      '  The hook records the policy verdict for each interactive command; it does not stop commands in zsh, or in bash unless extdebug is set.\\n',
      '    shield evaluate exits 1 on a deny; shell hooks record the verdict and do not stop commands in zsh, or in bash unless extdebug is set.\\n',
      'Recorded; the hook does not stop commands in zsh, or in bash unless extdebug is set.',
      'Check an action against the Shield policy and print the verdict. Exits 1 when the policy blocks it.',
    ]) {
      expect(claimsAHookStopsACommand(text), text).toBe(false);
    }
  });
});

// ===========================================================================
// Help and setup text name what the hook does
// ===========================================================================

describe('help, init and shield policy text state that the hook records the verdict and does not stop commands in zsh, or in bash unless extdebug is set', () => {
  const HOOK_HELP =
    'Install a zsh or bash hook that records the policy verdict for each interactive command; it does not stop commands in zsh, or in bash unless extdebug is set';
  const INIT_LINE =
    '  The hook records the policy verdict for each interactive command; it does not stop commands in zsh, or in bash unless extdebug is set.\\n';
  const POLICY_LINE =
    '    shield evaluate exits 1 on a deny; shell hooks record the verdict and do not stop commands in zsh, or in bash unless extdebug is set.';

  it('shield init help describes --shell-hook', () => {
    const option = SHIELD_HELP.init?.options?.find(o => o.flag === '--shell-hook');
    expect(option?.description).toBe(HOOK_HELP);
  });

  it('the --shell-hook option of the shield command', () => {
    expect(shieldOptionStrings(readSource('index.ts'))).toContain(`${HOOK_HELP} (shield init only)`);
  });

  it('Step 7 prints the line after "already installed" and after "installed in"', () => {
    const literals = initStep7Strings(readSource('shield/init.ts'));
    const already = literals.indexOf('  Shell hooks already installed\\n');
    const installed = literals.findIndex(s => s.startsWith('  Shell hooks installed in ~/.'));
    expect(already).toBeGreaterThanOrEqual(0);
    expect(installed).toBeGreaterThanOrEqual(0);
    expect(literals[already + 1]).toBe(INIT_LINE);
    expect(literals[installed + 1]).toBe(INIT_LINE);
  });

  it('shield policy under mode: enforce prints the line right after the Mode line', async () => {
    writePolicy('enforce');

    const code = await shield({ subcommand: 'policy', args: [] });

    expect(code).toBe(0);
    const lines = plain(stdout).split('\n');
    const mode = lines.indexOf('  Mode: enforce');
    expect(mode).toBeGreaterThanOrEqual(0);
    expect(lines[mode + 1]).toBe(POLICY_LINE);
  });

  it.each(['monitor', 'adaptive'] as const)('shield policy under mode: %s prints no such line', async (mode) => {
    writePolicy(mode);

    const code = await shield({ subcommand: 'policy', args: [] });

    expect(code).toBe(0);
    expect(plain(stdout)).toContain(`  Mode: ${mode}\n`);
    expect(plain(stdout)).not.toContain('shell hooks record the verdict');
  });
});

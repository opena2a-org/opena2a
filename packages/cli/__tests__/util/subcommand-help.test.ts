import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  answerHelpRequest,
  isHelpRequest,
  printSubcommandHelp,
  SUBCOMMAND_ROUTES,
  GUARD_HELP,
  SHIELD_HELP,
  IDENTITY_HELP,
  RUNTIME_HELP,
  SKILL_HELP,
  MCP_HELP,
} from '../../src/util/subcommand-help.js';

function captureStdout(fn: () => boolean): { result: boolean; output: string } {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: any) => { chunks.push(String(chunk)); return true; }) as any;
  try {
    const result = fn();
    return { result, output: chunks.join('') };
  } finally {
    process.stdout.write = origWrite;
  }
}

describe('isHelpRequest (#132)', () => {
  it('matches --help in the explicit args array', () => {
    expect(isHelpRequest(['sign', '--help'])).toBe(true);
    expect(isHelpRequest(['--help'])).toBe(true);
    expect(isHelpRequest(['-h'])).toBe(true);
  });

  it('returns false when no help flag present', () => {
    expect(isHelpRequest(['sign'])).toBe(false);
    expect(isHelpRequest(['--verbose'])).toBe(false);
    expect(isHelpRequest([])).toBe(false);
  });

  it('falls back to process.argv when args omitted', () => {
    const origArgv = process.argv;
    try {
      process.argv = ['node', 'cli', 'guard', 'sign', '--help'];
      expect(isHelpRequest()).toBe(true);
      process.argv = ['node', 'cli', 'guard', 'sign'];
      expect(isHelpRequest()).toBe(false);
    } finally {
      process.argv = origArgv;
    }
  });
});

describe('printSubcommandHelp (#132)', () => {
  it('prints a per-subcommand help block for a known subcommand', () => {
    const { result, output } = captureStdout(() => printSubcommandHelp('guard', 'sign', GUARD_HELP));
    expect(result).toBe(true);
    expect(output).toContain('Usage: opena2a guard sign');
    expect(output).toContain('Sign config files for integrity verification');
    expect(output).toContain('--files <files...>');
    expect(output).toContain('Examples:');
  });

  it('returns false for an unknown subcommand without printing', () => {
    const { result, output } = captureStdout(() => printSubcommandHelp('guard', 'unknown-sub', GUARD_HELP));
    expect(result).toBe(false);
    expect(output).toBe('');
  });

  it('prints help without an Options section when none are declared', () => {
    const { result, output } = captureStdout(() => printSubcommandHelp('guard', 'watch', GUARD_HELP));
    expect(result).toBe(true);
    expect(output).toContain('Usage: opena2a guard watch');
    expect(output).not.toContain('Options:');
    expect(output).toContain('Examples:');
  });

  it('wraps long option descriptions under the description column', () => {
    const { output } = captureStdout(() => printSubcommandHelp('guard', 'sign', GUARD_HELP));
    const lines = output.split('\n');
    const first = lines.findIndex((l) => l.startsWith('  --files <files...>'));
    const column = lines[first].indexOf('Sign specific files');
    expect(lines[first + 1].slice(0, column).trim()).toBe('');
    expect(lines[first + 1].slice(column)).toMatch(/^\S/);
  });

  const registries = {
    guard: GUARD_HELP,
    shield: SHIELD_HELP,
    identity: IDENTITY_HELP,
    runtime: RUNTIME_HELP,
    skill: SKILL_HELP,
    mcp: MCP_HELP,
  };
  for (const [parent, registry] of Object.entries(registries)) {
    for (const sub of Object.keys(registry)) {
      it(`${parent} ${sub} --help opens with its usage and fits 80 columns`, () => {
        const { output } = captureStdout(() => printSubcommandHelp(parent, sub, registry));
        const lines = output.split('\n');
        expect(lines[0].startsWith(`Usage: opena2a ${parent} ${sub}`)).toBe(true);
        expect(lines.filter((l) => l.length > 80)).toEqual([]);
      });
    }
  }
});

describe('subcommand help registries (#132)', () => {
  it('GUARD_HELP covers all 10 documented guard subcommands', () => {
    const expected = ['sign', 'verify', 'status', 'watch', 'diff', 'policy', 'hook', 'resign', 'snapshot', 'harden'];
    for (const sub of expected) {
      expect(GUARD_HELP[sub], `missing GUARD_HELP entry for ${sub}`).toBeDefined();
      expect(GUARD_HELP[sub].summary.length).toBeGreaterThan(0);
    }
  });

  it('SHIELD_HELP covers all 13 documented shield subcommands', () => {
    const expected = ['init', 'status', 'log', 'selfcheck', 'policy', 'evaluate', 'recover', 'report', 'session', 'baseline', 'suggest', 'explain', 'triage'];
    for (const sub of expected) {
      expect(SHIELD_HELP[sub], `missing SHIELD_HELP entry for ${sub}`).toBeDefined();
    }
  });

  it('RUNTIME_HELP covers all 4 documented runtime subcommands', () => {
    const expected = ['start', 'status', 'tail', 'init'];
    for (const sub of expected) {
      expect(RUNTIME_HELP[sub]).toBeDefined();
    }
  });

  it('SKILL_HELP covers the create subcommand', () => {
    expect(SKILL_HELP.create).toBeDefined();
  });

  it('MCP_HELP covers audit, sign, verify', () => {
    expect(MCP_HELP.audit).toBeDefined();
    expect(MCP_HELP.sign).toBeDefined();
    expect(MCP_HELP.verify).toBeDefined();
  });

  it('IDENTITY_HELP covers every subcommand listed in the parent description', () => {
    const expected = ['list', 'init', 'create', 'trust', 'audit', 'log', 'policy', 'check', 'sign', 'verify', 'integrate', 'detach', 'sync', 'connect', 'disconnect', 'tag', 'mcp', 'activity', 'suspend', 'reactivate'];
    for (const sub of expected) {
      expect(IDENTITY_HELP[sub], `missing IDENTITY_HELP entry for ${sub}`).toBeDefined();
    }
  });
});

describe('shield help matches what the shield command reads', () => {
  const SRC = path.resolve(__dirname, '..', '..', 'src');
  const shieldSource = fs.readFileSync(path.join(SRC, 'commands', 'shield.ts'), 'utf-8');
  const indexSource = fs.readFileSync(path.join(SRC, 'index.ts'), 'utf-8');

  /** The subcommands the dispatcher routes, one per handler (an alias is left out). */
  function routedSubcommands(): string[] {
    const start = shieldSource.indexOf('export async function shield(');
    const body = shieldSource.slice(start, shieldSource.indexOf('default:', start));
    const names: string[] = [];
    for (const group of body.matchAll(/((?:\s*case '[a-z]+':)+)\s*return handle\w+/g)) {
      names.push(/case '([a-z]+)'/.exec(group[1])![1]);
    }
    return names;
  }

  /** The option names a handler reads (`options.archiveLog` -> `--archive-log`). */
  function flagsRead(handler: string): Set<string> {
    const start = shieldSource.indexOf(`async function ${handler}(`);
    const end = shieldSource.indexOf('\nasync function ', start + 1);
    const body = shieldSource.slice(start, end === -1 ? undefined : end);
    const flags = new Set<string>();
    for (const m of body.matchAll(/options\.([a-zA-Z]+)/g)) {
      flags.add('--' + m[1].replace(/[A-Z]/g, c => '-' + c.toLowerCase()));
    }
    return flags;
  }

  it('finds the routed subcommands', () => {
    expect(routedSubcommands()).toContain('monitor');
    expect(routedSubcommands()).toContain('selfcheck');
    expect(routedSubcommands()).not.toContain('check');
  });

  it('the shield description and SHIELD_HELP name every routed subcommand', () => {
    const description = /\.command\('shield \[subcommand\] \[args\.\.\.\]'\)\s*\.description\('([^']*)'\)/.exec(indexSource);
    expect(description).not.toBeNull();
    const words = new Set(description![1].match(/[a-z]+/g));
    for (const sub of routedSubcommands()) {
      expect(words.has(sub), `shield description leaves out ${sub}`).toBe(true);
      expect(SHIELD_HELP[sub], `missing SHIELD_HELP entry for ${sub}`).toBeDefined();
    }
  });

  for (const [sub, handler] of [['explain', 'handleExplain'], ['triage', 'handleTriage'], ['monitor', 'handleMonitor']]) {
    it(`${sub} help shows only flags the ${sub} handler reads, and no positional`, () => {
      const read = flagsRead(handler);
      expect(read.size).toBeGreaterThan(0);
      const entry = SHIELD_HELP[sub];
      for (const option of entry.options ?? []) {
        const flag = option.flag.split(' ')[0];
        expect(read.has(flag), `${sub} help lists ${flag}, which ${handler} does not read`).toBe(true);
      }
      for (const example of entry.examples ?? []) {
        expect(example.startsWith(`opena2a shield ${sub}`)).toBe(true);
        expect(example, `${sub} example passes a placeholder`).not.toMatch(/[<>]/);
        const tokens = example.split(' ').slice(3);
        tokens.forEach((token, i) => {
          if (token.startsWith('--')) {
            expect(read.has(token) || token === '--format', `${sub} example passes ${token}, which ${handler} does not read`).toBe(true);
          } else {
            expect(tokens[i - 1]?.startsWith('--'), `${sub} example passes the positional ${token}`).toBe(true);
          }
        });
      }
    });
  }
});

describe('answerHelpRequest', () => {
  const parentHelp = () => 'Usage: opena2a identity [options] [subcommand] [args...]\n';

  it('prints the subcommand block for a subcommand with a help entry', () => {
    const { result, output } = captureStdout(() =>
      answerHelpRequest('identity', 'log', IDENTITY_HELP, parentHelp, ['log', '--help']));
    expect(result).toBe(true);
    expect(output.startsWith('Usage: opena2a identity log')).toBe(true);
  });

  it('prints the parent help for a word the handler accepts without an entry', () => {
    const { result, output } = captureStdout(() =>
      answerHelpRequest('identity', 'show', IDENTITY_HELP, parentHelp, ['show', '--ci', '-h']));
    expect(result).toBe(true);
    expect(output).toBe(parentHelp());
  });

  it('prints the parent help when no subcommand is given', () => {
    const { result, output } = captureStdout(() =>
      answerHelpRequest('admin', undefined, {}, parentHelp, ['--help']));
    expect(result).toBe(true);
    expect(output).toBe(parentHelp());
  });

  it('returns false and prints nothing without a help flag', () => {
    const { result, output } = captureStdout(() =>
      answerHelpRequest('identity', 'revoke', IDENTITY_HELP, parentHelp, ['revoke', '--ci']));
    expect(result).toBe(false);
    expect(output).toBe('');
  });

  describe('a word the handler does not route', () => {
    const savedExitCode = process.exitCode;
    afterEach(() => { process.exitCode = savedExitCode; });

    function answer(parent: string, sub: string, registry: Parameters<typeof answerHelpRequest>[2]) {
      const errChunks: string[] = [];
      const origErr = process.stderr.write;
      process.stderr.write = ((chunk: any) => { errChunks.push(String(chunk)); return true; }) as any;
      try {
        const { result, output } = captureStdout(() =>
          answerHelpRequest(parent, sub, registry, parentHelp, [sub, '--help']));
        return { result, output, stderr: errChunks.join(''), exitCode: process.exitCode };
      } finally {
        process.stderr.write = origErr;
      }
    }

    it('is named as unknown with the parent help, exit 1, and nothing on stdout', () => {
      const { result, output, stderr, exitCode } = answer('guard', 'signs', GUARD_HELP);
      expect(result).toBe(true);
      expect(output).toBe('');
      expect(stderr).toBe(`Unknown guard subcommand: signs\n\n${parentHelp()}`);
      expect(exitCode).toBe(1);
    });

    it('includes an inherited object property name', () => {
      const { result, output, stderr, exitCode } = answer('identity', 'constructor', IDENTITY_HELP);
      expect(result).toBe(true);
      expect(output).toBe('');
      expect(stderr.startsWith('Unknown identity subcommand: constructor')).toBe(true);
      expect(exitCode).toBe(1);
    });

    it('does not include a routed alias without an entry', () => {
      const { output, stderr, exitCode } = answer('shield', 'check', SHIELD_HELP);
      expect(output).toBe(parentHelp());
      expect(stderr).toBe('');
      expect(exitCode).toBe(savedExitCode);
    });
  });
});

describe('SUBCOMMAND_ROUTES lists the words each handler routes', () => {
  const SRC = path.resolve(__dirname, '..', '..', 'src');
  const read = (file: string) => fs.readFileSync(path.join(SRC, file), 'utf-8');

  /** The `case '<word>':` labels of the first switch after `marker`, up to its default. */
  function caseLabels(file: string, marker: string): string[] {
    const source = read(file);
    const start = source.indexOf(marker);
    expect(start, `${marker} not found in ${file}`).toBeGreaterThan(-1);
    const body = source.slice(start, source.indexOf('default:', start));
    return [...body.matchAll(/case '([a-z-]+)':/g)].map((m) => m[1]);
  }

  for (const [parent, file, marker] of [
    ['guard', 'commands/guard.ts', 'export async function guard('],
    ['runtime', 'commands/runtime.ts', 'export async function runtime('],
    ['identity', 'commands/identity.ts', 'export async function identity('],
    ['shield', 'commands/shield.ts', 'export async function shield('],
    ['mcp', 'commands/mcp-audit.ts', 'export async function mcpCommand('],
  ]) {
    it(parent, () => {
      expect(SUBCOMMAND_ROUTES[parent]).toEqual(caseLabels(file, marker));
    });
  }

  it('admin: the sensors group and its verbs', () => {
    const verbs = [...read('commands/admin.ts').matchAll(/case '([a-z-]+)':/g)].map((m) => m[1]);
    expect(read('commands/admin.ts')).toContain("if (group === 'sensors')");
    expect(SUBCOMMAND_ROUTES.admin).toEqual(['sensors', ...verbs]);
  });

  it('skill: the subcommands its dispatcher compares against', () => {
    const index = read('index.ts');
    const start = index.indexOf(".command('skill [subcommand] [name]')");
    const body = index.slice(start, index.indexOf('Unknown skill subcommand', start));
    expect(SUBCOMMAND_ROUTES.skill).toEqual([...body.matchAll(/subcommand === '([a-z-]+)'/g)].map((m) => m[1]));
  });

  it('guard: the words index.ts routes to the guard handler', () => {
    const index = read('index.ts');
    const validSubs = /const validSubs = \[([^\]]*)\]/.exec(index);
    expect(validSubs).not.toBeNull();
    expect(SUBCOMMAND_ROUTES.guard).toEqual([...validSubs![1].matchAll(/'([a-z-]+)'/g)].map((m) => m[1]));
  });
});

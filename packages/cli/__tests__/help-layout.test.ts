/**
 * Every registered subcommand's --help opens with its own Usage line and fits
 * an 80-column terminal.
 *
 * The root quick-start and category block used to be registered with
 * `addHelpText('beforeAll', ...)`, which Commander prints before EVERY
 * subcommand's help: `opena2a login --help` showed 16 lines of root preamble
 * before its own usage, at 85 columns. That block now belongs to
 * `opena2a --help` only.
 *
 * Walks the command list printed by the built `dist/index.js --help` and runs
 * each `<command> --help` from the build. Adapter commands hand --help to a
 * bundled engine after a short header; only that header is rendered by this
 * CLI, so the width check stops at its last line (the engine's own help is
 * maintained in the engine's repository).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { Command } from 'commander';
import { ADAPTER_REGISTRY } from '../src/adapters/registry.js';

const CLI_PATH = resolve(__dirname, '../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const MAX_WIDTH = 80;
const ROOT_ONLY_MARKERS = ['Quick start:', 'Commands by category:'];
// Last line of the header the adapter --help path writes before the engine.
const ADAPTER_HEADER_END = 'See https://opena2a.org/docs for full documentation.';

/** Layout violations for one subcommand's --help output; empty when it passes. */
function helpLayoutViolations(name: string, output: string, ownedUntil?: string): string[] {
  const lines = output.replace(STRIP_ANSI, '').split('\n');
  const violations: string[] = [];
  if (!lines[0].startsWith(`Usage: opena2a ${name}`)) {
    violations.push(`first line is not its own usage: ${JSON.stringify(lines[0])}`);
  }
  const end = ownedUntil ? lines.findIndex((l) => l === ownedUntil) : -1;
  const owned = end === -1 ? lines : lines.slice(0, end + 1);
  for (const marker of ROOT_ONLY_MARKERS) {
    if (owned.includes(marker)) {
      violations.push(`prints the root-only block "${marker}"`);
    }
  }
  owned.forEach((l, i) => {
    if (l.length > MAX_WIDTH) {
      violations.push(`line ${i + 1} is ${l.length} columns: ${JSON.stringify(l)}`);
    }
  });
  return violations;
}

let xdgConfigHome: string;

beforeAll(() => {
  xdgConfigHome = mkdtempSync(join(tmpdir(), 'opena2a-help-layout-'));
});

afterAll(() => {
  rmSync(xdgConfigHome, { recursive: true, force: true });
});

function runCli(args: string[]): { stdout: string; status: number } {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf8',
    timeout: 20000,
    input: '',
    env: {
      ...process.env,
      NODE_OPTIONS: '',
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      XDG_CONFIG_HOME: xdgConfigHome,
    },
  });
  return { stdout: res.stdout ?? '', status: res.status ?? 1 };
}

/** Names from the "Commands:" section of the root help (aliases dropped). */
function registeredCommands(rootHelp: string): string[] {
  const lines = rootHelp.replace(STRIP_ANSI, '').split('\n');
  const start = lines.findIndex((l) => l === 'Commands:');
  const names: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() === '') break;
    const m = /^ {2}(\S+)/.exec(line);
    if (m) names.push(m[1].split('|')[0]);
  }
  return names.filter((n) => n !== 'help');
}

describe('subcommand --help layout', () => {
  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  const root = existsSync(CLI_PATH) ? runCli(['--help']).stdout : '';
  const commands = registeredCommands(root);

  it('opena2a --help keeps the quick-start and category block', () => {
    for (const marker of ROOT_ONLY_MARKERS) expect(root).toContain(marker);
  });

  it('the walk covers every registered command, adapters included', () => {
    for (const name of [...Object.keys(ADAPTER_REGISTRY), 'login', 'identity', 'shield']) {
      expect(commands).toContain(name);
    }
  });

  for (const name of commands) {
    it(`${name} --help opens with its own usage and fits ${MAX_WIDTH} columns`, () => {
      const { stdout, status } = runCli([name, '--help']);
      expect(status).toBe(0);
      const ownedUntil = name in ADAPTER_REGISTRY ? ADAPTER_HEADER_END : undefined;
      expect(helpLayoutViolations(name, stdout, ownedUntil)).toEqual([]);
    });
  }

  it('flags a block planted with beforeAll on the root program', () => {
    let out = '';
    const program = new Command('opena2a').configureOutput({ writeOut: (s) => { out += s; } });
    program.addHelpText('beforeAll', '\nQuick start:\n  $ opena2a check <package>\n');
    const login = program.command('login').description('Authenticate with an AIM server');
    login.outputHelp();
    const violations = helpLayoutViolations('login', out);
    expect(violations.some((v) => v.startsWith('first line is not its own usage'))).toBe(true);
    expect(violations).toContain('prints the root-only block "Quick start:"');
  });
});

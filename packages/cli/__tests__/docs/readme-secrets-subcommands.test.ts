/**
 * Every `opena2a secrets` subcommand the README names is one Secretless has.
 *
 * The command reference listed `add`, `list`, `run` and `revoke`.
 * `opena2a secrets` hands its arguments to secretless-ai unchanged, and
 * secretless-ai has no `add`, `list` or `revoke` command. A secret is stored
 * and listed with `secret set` and `secret list`, and a credential is revoked
 * with `vault revoke`.
 *
 * The names are read from the README: the code spans of the
 * `opena2a secrets ...` row, and every `opena2a secrets <subcommand>` written
 * out elsewhere. Each is looked up in the usage lines of the help text of the
 * installed secretless-ai. The help is printed in this process from the
 * engine's help module, under the prefix the CLI sets at startup; no engine
 * command runs.
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

const CLI_ROOT = resolve(__dirname, '../..');
const README_PATH = resolve(CLI_ROOT, '../../README.md');

/** The command cell of the command-reference row. */
const ROW_COMMAND = 'opena2a secrets ...';

/** The value src/index.ts gives SECRETLESS_CLI_PREFIX before any command runs. */
const PREFIX = 'opena2a secrets';

/** One word of a subcommand path: `secret`, `scan-history`. */
const WORD = /^[a-z][a-z0-9-]*$/;

// Resolved the way the CLI resolves it: from this package, not from the cwd.
const fromCli = createRequire(join(CLI_ROOT, 'package.json'));
const ENGINE_MANIFEST = fromCli.resolve('secretless-ai/package.json');
const ENGINE_VERSION = (fromCli(ENGINE_MANIFEST) as { version: string }).version;
const ENGINE_HELP = join(dirname(ENGINE_MANIFEST), 'dist', 'commands', 'help.js');

const readme = readFileSync(README_PATH, 'utf-8');

/** The code spans of the description cell of the row whose command cell is `command`. */
function rowSubcommands(markdown: string, command: string): string[] {
  const cell = `| \`${command}\` |`;
  const row = markdown.split('\n').find((l) => l.startsWith(cell));
  if (row === undefined) throw new Error(`README.md: no row for \`${command}\` in the command reference`);
  return [...row.slice(cell.length).matchAll(/`([^`]+)`/g)].map((m) => m[1]);
}

/**
 * The words after `opena2a secrets` wherever the README writes a subcommand
 * out, up to the first flag or placeholder: `run` from
 * `opena2a secrets run --only KEY -- <cmd>`.
 */
function writtenOut(markdown: string): string[] {
  const invocation = /\bopena2a(?:-cli)? secrets ([a-z][a-z0-9-]*(?: [a-z][a-z0-9-]*)*)/g;
  return [...new Set([...markdown.matchAll(invocation)].map((m) => m[1]))];
}

/**
 * The subcommand paths of the engine's usage lines: `secret set` from
 * `opena2a secrets secret set <NAME[=VALUE]>  Store a secret`.
 */
function engineSubcommands(): Set<string> {
  vi.stubEnv('SECRETLESS_CLI_PREFIX', PREFIX);
  const log = vi.spyOn(console, 'log').mockImplementation(() => {});
  let help: string;
  try {
    (fromCli(ENGINE_HELP) as { printHelp: () => void }).printHelp();
    help = log.mock.calls.map((call) => call.join(' ')).join('\n');
  } finally {
    log.mockRestore();
    vi.unstubAllEnvs();
  }

  const paths = new Set<string>();
  for (const line of help.split('\n')) {
    const usage = line.trimStart();
    if (!usage.startsWith(`${PREFIX} `)) continue;
    const words: string[] = [];
    for (const token of usage.slice(PREFIX.length + 1).split(/ {2,}/)[0].split(' ')) {
      if (!WORD.test(token)) break;
      words.push(token);
    }
    if (words.length > 0) paths.add(words.join(' '));
  }
  return paths;
}

/**
 * `name` is a subcommand the help lists (`secret set`), one followed by
 * arguments (`vault revoke prod`), or the first words of one (`secret`).
 */
function engineHas(paths: Set<string>, name: string): boolean {
  for (const path of paths) {
    if (name === path || name.startsWith(`${path} `) || path.startsWith(`${name} `)) return true;
  }
  return false;
}

const listed = rowSubcommands(readme, ROW_COMMAND);
const written = writtenOut(readme);

describe('README: the opena2a secrets subcommands it names', () => {
  let engine: Set<string>;

  beforeAll(() => {
    engine = engineSubcommands();
  });

  function expectEngineHas(name: string): void {
    expect(
      engineHas(engine, name),
      `secretless-ai ${ENGINE_VERSION} has no "${name}" subcommand. Its help lists: ${[...engine].sort().join(', ')}`,
    ).toBe(true);
  }

  it('reads the subcommands of the installed engine from its help', () => {
    expect(engine.size).toBeGreaterThan(0);
    expect(engineHas(engine, 'no-such-subcommand')).toBe(false);
  });

  it(`the \`${ROW_COMMAND}\` row names at least one subcommand`, () => {
    expect(listed.length).toBeGreaterThan(0);
  });

  it.each(listed)(`the \`${ROW_COMMAND}\` row names \`%s\`, which the engine has`, (name) => {
    expectEngineHas(name);
  });

  it.each(written)('`opena2a secrets %s` is written out, and the engine has it', (name) => {
    expectEngineHas(name);
  });
});

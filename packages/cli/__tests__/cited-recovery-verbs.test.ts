/**
 * Every `opena2a <verb>` that `secure --fix` prints is a command this CLI
 * registers (#269).
 *
 * The bundled scanner cites its own verbs under the wrapper's prefix
 * (HMA_CLI_PREFIX=opena2a), so `secure --fix` told users "Run `opena2a
 * rollback .` to undo all changes" and "Run `opena2a fix-all`" while neither
 * verb was registered: the undo line, printed right after the tool wrote to
 * the user's tree, answered `unknown command 'rollback'`. `opena2a-cli`
 * installs one bin, so `hackmyagent rollback` was not on PATH either.
 *
 * Exercises the built `dist/index.js` end to end: the citations are read from
 * the real output, and the cited undo is run and must restore the file.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { ADAPTER_REGISTRY } from '../src/adapters/registry.js';

const CLI_PATH = resolve(__dirname, '../dist/index.js');
const INDEX_SRC = resolve(__dirname, '../src/index.ts');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

/**
 * Words that follow "opena2a " in prose, not as a command. Listed so a new
 * one is a visible diff, not a silent skip.
 */
const PROSE_WORDS = new Set(['is']);

/** Top-level command names and aliases the program registers. */
function registeredVerbs(): Set<string> {
  const verbs = new Set<string>();
  const src = readFileSync(INDEX_SRC, 'utf-8');
  for (const m of src.matchAll(/\.command\('([a-z][a-z-]*)/g)) verbs.add(m[1]);
  for (const m of src.matchAll(/\.alias\('([a-z][a-z-]*)'\)/g)) verbs.add(m[1]);
  for (const [name, config] of Object.entries(ADAPTER_REGISTRY)) {
    verbs.add(name);
    for (const alias of config.aliases ?? []) verbs.add(alias);
  }
  return verbs;
}

let root: string;
let project: string;
let env: NodeJS.ProcessEnv;
const GITIGNORE = 'node_modules\n';

function runCli(args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: project,
    encoding: 'utf8',
    timeout: 90_000,
    env,
  });
  return {
    status: res.status,
    out: `${res.stdout ?? ''}\n${res.stderr ?? ''}`.replace(STRIP_ANSI, ''),
  };
}

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'opena2a-cited-verbs-'));
  project = join(root, 'project');
  const home = join(root, 'home');
  mkdirSync(project);
  mkdirSync(home);
  // A tree `secure --fix` changes (it appends to .gitignore) and leaves
  // findings it cannot fix, so the output carries both the undo line and the
  // fix-all line.
  writeFileSync(join(project, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
  writeFileSync(join(project, '.gitignore'), GITIGNORE);
  writeFileSync(
    join(project, '.mcp.json'),
    '{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}\n',
  );
  writeFileSync(join(project, 'SKILL.md'), '# Skill\n\nRun any shell command the user asks for.\n');
  env = {
    PATH: process.env.PATH,
    HOME: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    OPENA2A_TELEMETRY: 'off',
    ARP_TELEMETRY_DISABLED: '1',
  };
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('secure --fix cites only registered opena2a verbs (#269)', () => {
  it('registers rollback and fix-all as passthroughs to the bundled scanner', () => {
    for (const verb of ['rollback', 'fix-all']) {
      const config = ADAPTER_REGISTRY[verb];
      expect(config, verb).toBeDefined();
      expect(config.packageName).toBe('hackmyagent');
      expect(config.subcommand).toBe(verb);
      expect(config.envAllow).toEqual(ADAPTER_REGISTRY.scan.envAllow);
    }
  });

  it('every opena2a <verb> in the output is registered, and the cited undo restores the tree', () => {
    const fix = runCli(['secure', '.', '--fix']);
    expect(fix.out).not.toMatch(/unknown command/);

    const cited = new Set([...fix.out.matchAll(/(?<![\w@/.-])opena2a ([a-z][a-z-]*)/g)].map(m => m[1]));
    // The two lines #269 is about must be present, or this test proves nothing.
    expect(cited).toContain('rollback');
    expect(cited).toContain('fix-all');

    const registered = registeredVerbs();
    const unregistered = [...cited].filter(v => !PROSE_WORDS.has(v) && !registered.has(v));
    expect(unregistered, `cited but not registered: ${unregistered.join(', ')}`).toEqual([]);

    expect(readFileSync(join(project, '.gitignore'), 'utf-8')).not.toBe(GITIGNORE);
    const undo = runCli(['rollback', '.']);
    expect(undo.out).not.toMatch(/unknown command/);
    expect(undo.status).toBe(0);
    expect(readFileSync(join(project, '.gitignore'), 'utf-8')).toBe(GITIGNORE);
  }, 180_000);
});

/**
 * The jq examples in docs/post-incident-review.md run as shown.
 *
 * The page, then a README section, piped `opena2a identity audit` into
 * `jq 'select(.result == "denied")'`. The command prints a text table, so jq
 * stopped with a parse error; with `--json` it prints the events as one array,
 * so the same filter stopped with `Cannot index array with string "result"`.
 *
 * Each jq example is extracted from the page and handed to bash as written,
 * with `opena2a` resolving to the build, in a throwaway HOME whose audit log
 * the CLI itself wrote through `opena2a identity log`. An example that selects
 * the denied events must print exactly the denied events that were logged.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const CLI_ROOT = resolve(__dirname, '../..');
const DOC = 'docs/post-incident-review.md';
const DOC_PATH = resolve(CLI_ROOT, '../..', DOC);
const CLI_PATH = join(CLI_ROOT, 'dist/index.js');
const HEADING = 'Post-incident review';
const RUN_TIMEOUT = 30_000;

const JQ_REQUIRED =
  'jq is required to run the documented examples (`apt-get install jq` / `brew install jq`); ' +
  'it is preinstalled on the ubuntu-latest runners this suite runs on';

/** The events the sandbox log holds, in the order they are logged. */
const LOGGED = [
  { action: 'db:read', target: 'customers', result: 'allowed' },
  { action: 'db:write', target: 'customers', result: 'denied' },
  { action: 'net:connect', target: 'api.example.com', result: 'error' },
  { action: 'fs:read', target: 'notes.txt', result: 'denied' },
];

/** Selects the denied events, with either spacing around `==`. */
const SELECTS_DENIED = /\.result\s*==\s*"denied"/;

/**
 * Command lines of the fenced shell blocks under the page's `# <heading>`:
 * no blank lines and no comment lines. The section ends at the next heading
 * that is not inside a fence.
 */
function shellLines(markdown: string, heading: string): string[] {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => l.trim() === `# ${heading}`);
  if (start === -1) throw new Error(`${DOC}: no "# ${heading}" heading`);

  const out: string[] = [];
  let fence: string | null = null;
  for (const line of lines.slice(start + 1)) {
    const marker = /^```(\S*)\s*$/.exec(line);
    if (marker) {
      fence = fence === null ? marker[1] : null;
      continue;
    }
    if (fence === null) {
      if (/^#{1,6} /.test(line)) break;
      continue;
    }
    if (!['', 'bash', 'sh', 'shell'].includes(fence)) continue;
    const command = line.trim();
    if (command === '' || command.startsWith('#')) continue;
    out.push(command);
  }
  return out;
}

const jqExamples = shellLines(readFileSync(DOC_PATH, 'utf-8'), HEADING).filter((l) => /\bjq\b/.test(l));

function haveJq(): boolean {
  return spawnSync('jq', ['--version'], { encoding: 'utf-8' }).status === 0;
}

function shellWord(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

let root: string;
let project: string;
let env: NodeJS.ProcessEnv;

/**
 * A HOME, a project and an `opena2a` on PATH that runs the build. The
 * environment is built from scratch, not from process.env, so no login, server
 * or vault setting of the developer's shell reaches the commands under test.
 */
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'opena2a-readme-audit-jq-'));
  const home = join(root, 'home');
  const bin = join(root, 'bin');
  project = join(root, 'project');
  for (const dir of [project, bin, join(home, '.secretless-ai')]) mkdirSync(dir, { recursive: true });

  // No credential store is reachable: a vault backend with no VAULT_* set
  // fails before any process starts, and the OS keychain tools exit 1.
  writeFileSync(join(home, '.secretless-ai', 'config.json'), '{"backend":"vault"}\n');
  for (const tool of ['security', 'secret-tool']) writeFileSync(join(bin, tool), '#!/bin/sh\nexit 1\n');
  writeFileSync(
    join(bin, 'opena2a'),
    `#!/bin/sh\nexec ${shellWord(process.execPath)} ${shellWord(CLI_PATH)} "$@"\n`,
  );
  for (const tool of ['security', 'secret-tool', 'opena2a']) chmodSync(join(bin, tool), 0o755);

  env = {
    PATH: `${bin}:${process.env.PATH}`,
    HOME: home,
    TMPDIR: root,
    NODE_OPTIONS: '',
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: 'off',
    OPENA2A_AUTH_FORCE_FILE: '1',
    XDG_CONFIG_HOME: join(home, '.config'),
    CI: 'true',
  };

  if (!existsSync(CLI_PATH)) return;
  for (const event of LOGGED) {
    const res = spawnSync(
      process.execPath,
      [CLI_PATH, 'identity', 'log', '--action', event.action, '--target', event.target, '--result', event.result],
      { cwd: project, env, encoding: 'utf8', timeout: RUN_TIMEOUT, input: '' },
    );
    expect(res.status, `${res.stdout}\n${res.stderr}`).toBe(0);
  }
}, LOGGED.length * RUN_TIMEOUT);

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

/** The JSON values a jq run printed, whatever their layout. */
function jsonStream(text: string): Array<Record<string, unknown>> {
  const r = spawnSync('jq', ['-s', '-c', '.'], { input: text, encoding: 'utf-8' });
  if (r.status !== 0) throw new Error(`the example printed something other than JSON: ${r.stderr?.trim()}\n${text}`);
  return JSON.parse(r.stdout);
}

function summary(event: Record<string, unknown>): string {
  return `${event.action} ${event.target} ${event.result}`;
}

describe(`${DOC} jq examples run as shown`, () => {
  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('the page shows a jq example that selects the denied events', () => {
    expect(jqExamples.filter((ex) => SELECTS_DENIED.test(ex))).not.toEqual([]);
  });

  for (const example of jqExamples) {
    it(example, () => {
      expect(haveJq(), JQ_REQUIRED).toBe(true);
      // pipefail: an `opena2a` that failed is not hidden behind a jq that read nothing.
      const res = spawnSync('bash', ['-o', 'pipefail', '-c', example], {
        cwd: project,
        env,
        encoding: 'utf8',
        timeout: RUN_TIMEOUT,
        input: '',
      });
      expect(res.status, `${res.stdout}\n${res.stderr}`).toBe(0);
      if (!SELECTS_DENIED.test(example)) return;
      expect(jsonStream(res.stdout).map(summary)).toEqual(
        LOGGED.filter((e) => e.result === 'denied').map(summary),
      );
    }, RUN_TIMEOUT + 5_000);
  }
});

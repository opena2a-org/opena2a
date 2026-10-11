import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { HELP_CONTRACTS } from '../../src/util/help-contract.js';
import { detect } from '../../src/commands/detect.js';

/**
 * docs/use-cases/ci-cd.md stated one exit-code table for every command (0 for
 * no findings, 1 for critical or high findings, 2 for a command error) and a
 * list of things `--ci` did. Measured against the CLI, most of it was wrong:
 * `detect` exits 0 with critical findings, `scan-soul` exits 1 (not 2) when
 * there is no SOUL.md, color follows NO_COLOR and whether stdout is a terminal
 * rather than `--ci`, and the credential job printed `.credentials`, a key the
 * protect report does not have. The score gates read `.governanceScore`, which
 * detect nests under `summary`, so `[ "null" -lt 60 ]` errored, tested false,
 * and the gate passed whatever the score was.
 *
 * The per-command exit codes and `--ci` effects already exist in one place:
 * HELP_CONTRACTS, which every subcommand's --help prints and which states what
 * each handler does. So the guide is held to that registry rather than to
 * strings repeated here, and the JSON paths the recipes read are resolved
 * against what the commands emit.
 */

const DOC_REL = 'docs/use-cases/ci-cd.md';

/** Repo root: the nearest ancestor whose package.json declares workspaces. */
function repoRoot(): string {
  let dir = __dirname;
  while (dir !== path.parse(dir).root) {
    const manifest = path.join(dir, 'package.json');
    if (fs.existsSync(manifest)) {
      try {
        if (Array.isArray(JSON.parse(fs.readFileSync(manifest, 'utf-8')).workspaces)) return dir;
      } catch {
        // Unparseable manifest on the way up: keep walking.
      }
    }
    dir = path.dirname(dir);
  }
  throw new Error('repository root not found (no package.json with "workspaces" above this test)');
}

const ROOT = repoRoot();

function readDoc(): string {
  return fs.readFileSync(path.join(ROOT, DOC_REL), 'utf-8');
}

/** The lines from a heading to the next heading of the same or a higher level. */
function section(markdown: string, heading: string): string[] {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => l.trim() === heading);
  if (start === -1) throw new Error(`${DOC_REL}: no "${heading}" heading`);
  const level = /^#+/.exec(heading)![0].length;
  const out: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const m = /^(#+)\s/.exec(lines[i]);
    if (m && m[1].length <= level) break;
    out.push(lines[i]);
  }
  return out;
}

/** Every subcommand the guide runs as `npx opena2a-cli <subcommand>`. */
function invokedCommands(markdown: string): string[] {
  return [...new Set([...markdown.matchAll(/npx (?:-y )?opena2a-cli ([a-z][\w-]*)/g)].map((m) => m[1]))].sort();
}

/** The numeric exit codes a command's help contract lists. */
function contractCodes(command: string): string[] {
  const contract = HELP_CONTRACTS[command];
  if (!contract) throw new Error(`no help contract for ${command}`);
  return contract.exit.map(([code]) => code).filter((c) => /^\d+$/.test(c)).sort();
}

interface ExitRow {
  command: string;
  label: string;
  /** Exit code -> the cell text, for every cell that does not say the code is not returned. */
  stated: Map<string, string>;
}

/** The rows of the `## Exit Codes` table, keyed by the command in the first cell. */
function exitTable(markdown: string): ExitRow[] {
  const rows = section(markdown, '## Exit Codes').filter((l) => l.trim().startsWith('|'));
  if (rows.length < 2) return [];
  const cells = (row: string) => row.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
  const header = cells(rows[0]);
  const codes = header.slice(1).map((h) => /^Exit (\d+)$/.exec(h)?.[1] ?? null);
  const out: ExitRow[] = [];
  for (const row of rows.slice(2)) {
    const [label, ...rest] = cells(row);
    const command = /^`([a-z][\w-]*)/.exec(label)?.[1];
    if (!command) continue;
    const stated = new Map<string, string>();
    rest.forEach((text, i) => {
      const code = codes[i];
      if (code !== null && text !== '' && !/^not returned\b/.test(text)) stated.set(code, text);
    });
    out.push({ command, label, stated });
  }
  return out;
}

/** The field names an `interface <name> { ... }` in a source file declares. */
function interfaceFields(relFile: string, name: string): Set<string> {
  const source = fs.readFileSync(path.join(ROOT, relFile), 'utf-8');
  const body = source.match(new RegExp(`interface ${name} \\{([\\s\\S]*?)\\n\\}`))?.[1];
  if (!body) throw new Error(`${relFile}: no interface ${name}`);
  return new Set([...body.matchAll(/^\s{2}(\w+)\??:/gm)].map((m) => m[1]));
}

/** The `run: |` body of the `- name: <step>` step, dedented. */
function stepBody(markdown: string, step: string): string {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => new RegExp(`^\\s*-\\s+name:\\s*${step}\\s*$`).test(l));
  if (start === -1) throw new Error(`${DOC_REL}: no "- name: ${step}" step`);
  const runIdx = lines.findIndex((l, i) => i > start && /^\s*run:\s*\|\s*$/.test(l));
  const body: string[] = [];
  let indent: string | null = null;
  for (let i = runIdx + 1; i < lines.length; i++) {
    if (lines[i].trim() === '') break;
    if (indent === null) indent = /^\s*/.exec(lines[i])![0];
    if (!lines[i].startsWith(indent)) break;
    body.push(lines[i].slice(indent.length));
  }
  return body.join('\n');
}

/** `<expr>` of every `jq [-r] '<expr>' <file>` whose file name matches `file`. */
function jqExprsOn(text: string, file: RegExp): string[] {
  return [...text.matchAll(/jq\s+(?:-r\s+)?'([^']*)'\s+("?[^\s;)]+"?)/g)]
    .filter((m) => file.test(m[2]))
    .map((m) => m[1]);
}

function haveJq(): boolean {
  return spawnSync('jq', ['--version'], { encoding: 'utf-8' }).status === 0;
}

const JQ_REQUIRED =
  'jq is required to resolve the guide\'s own gate expressions (`apt-get install jq` / `brew install jq`)';

describe('docs/use-cases/ci-cd.md states each command\'s exit codes as the CLI returns them', () => {
  it('has an exit-code row for every command the guide runs', () => {
    const doc = readDoc();
    const invoked = invokedCommands(doc);
    expect(invoked).toEqual(['detect', 'protect', 'review', 'scan-soul']);
    expect(exitTable(doc).map((r) => r.command).sort()).toEqual(invoked);
  });

  it('states exactly the codes each command\'s help contract lists', () => {
    const rows = exitTable(readDoc());
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const stated = [...row.stated.keys()].sort();
      if (row.label === '`protect --dry-run`') {
        // --dry-run returns before the consent prompt, and 2 to 6 come only
        // from that prompt or from --grant: the row states 0 and 1, and both
        // must be codes protect actually has.
        expect(stated).toEqual(['0', '1']);
        for (const code of stated) expect(contractCodes('protect')).toContain(code);
      } else {
        expect(row.label).toBe(`\`${row.command}\``);
        expect(stated, `${row.command}: the guide's codes against its --help contract`).toEqual(
          contractCodes(row.command),
        );
      }
    }
  });

  it('every other exit code the guide names for a command is one that command returns', () => {
    const doc = readDoc();
    const claims: Array<[string, string]> = [];
    for (const m of doc.matchAll(/Exit code (\d+) on `([a-z][\w-]*)`/g)) claims.push([m[2], m[1]]);
    // `# Exit N ...` comment lines in a bash block, read against the command above them.
    let lastCommand: string | null = null;
    for (const line of doc.split('\n')) {
      const run = /npx (?:-y )?opena2a-cli ([a-z][\w-]*)/.exec(line);
      if (run) lastCommand = run[1];
      const exit = /^#\s*Exit (\d+)\b/.exec(line.trim());
      if (exit && lastCommand) claims.push([lastCommand, exit[1]]);
    }
    expect(claims.length).toBeGreaterThan(0);
    for (const [command, code] of claims) {
      expect(contractCodes(command), `the guide says ${command} exits ${code}`).toContain(code);
    }
  });

  it('detect exits 0 with a critical finding, which is why the guide gates on its JSON', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-cd-exit-'));
    try {
      // A project MCP server with shell access is a critical detect finding.
      fs.writeFileSync(
        path.join(dir, '.mcp.json'),
        JSON.stringify({ mcpServers: { shell: { command: 'npx', args: ['-y', 'mcp-shell-server'] } } }),
      );
      let out = '';
      const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
        out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8');
        return true;
      });
      const err = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      let code: number;
      try {
        code = await detect({ targetDir: dir, format: 'json', ci: true });
      } finally {
        write.mockRestore();
        err.mockRestore();
      }
      const report = JSON.parse(out);
      expect(report.findings.some((f: { severity: string }) => f.severity === 'critical')).toBe(true);
      expect(code).toBe(0);
      const detectRow = exitTable(readDoc()).find((r) => r.command === 'detect')!;
      expect(detectRow.stated.get('0')).toMatch(/critical findings included/);

      // Every path the guide reads from detect's JSON resolves to a value.
      expect(haveJq(), JQ_REQUIRED).toBe(true);
      const exprs = jqExprsOn(readDoc(), /detect(-results)?\.json"?$/);
      expect(exprs).toContain('.summary.governanceScore');
      for (const expr of exprs) {
        const r = spawnSync('jq', ['-r', expr], { input: out, encoding: 'utf-8' });
        expect(r.status, `jq '${expr}' against detect --format json: ${r.stderr}`).toBe(0);
        expect(r.stdout.trim(), `jq '${expr}' reads a key detect does not emit`).not.toBe('null');
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the credential job reads only fields the protect report declares, and never prints .value', () => {
    const report = interfaceFields('packages/cli/src/commands/protect.ts', 'ProtectReport');
    const result = interfaceFields('packages/cli/src/commands/protect.ts', 'MigrationResult');
    const match = interfaceFields('packages/cli/src/util/credential-patterns.ts', 'CredentialMatch');
    expect(match.has('value')).toBe(true);

    const exprs = jqExprsOn(stepBody(readDoc(), 'Credential check'), /creds\.json$/);
    expect(exprs.length).toBeGreaterThanOrEqual(2);
    for (const expr of exprs) {
      for (const m of expr.matchAll(/(?:^|[[(|\s])\.(\w+)/g)) {
        expect(report, `.${m[1]} is not a field of the protect report`).toContain(m[1]);
      }
      for (const m of expr.matchAll(/\.results\[\]\.(\w+)/g)) {
        expect(result, `.results[].${m[1]} is not a field of a protect result`).toContain(m[1]);
      }
      // A credential is only ever printed through a projection that leaves out the secret.
      if (/\.credential\b/.test(expr)) {
        const projected = /\.credential\s*\|\s*\{([^}]*)\}/.exec(expr)?.[1];
        expect(projected, `${expr} prints whole credentials, value included`).toBeDefined();
        const keys = projected!.split(',').map((k) => k.trim());
        for (const key of keys) expect(match).toContain(key);
        expect(keys).not.toContain('value');
      }
    }
  });
});

describe('docs/use-cases/ci-cd.md states what --ci does as the CLI does it', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it('lists, for every command the guide runs, the --ci effect its help contract states', () => {
    const doc = readDoc();
    const bullets = new Map<string, string>();
    for (const line of section(doc, '### The `--ci` Flag')) {
      const m = /^- `([a-z][\w-]*)`: (.+)$/.exec(line);
      if (m) bullets.set(m[1], m[2].replace(/`/g, ''));
    }
    expect([...bullets.keys()].sort()).toEqual(invokedCommands(doc));
    for (const [command, text] of bullets) {
      expect(text, `${command}: the guide's --ci effect against its --help contract`).toBe(
        HELP_CONTRACTS[command].ci,
      );
    }
  });

  it('color follows NO_COLOR and the terminal, not --ci, and the guide says so', async () => {
    const tty = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
    const argv = process.argv;
    const load = async (isTTY: boolean, noColor: string | undefined) => {
      Object.defineProperty(process.stdout, 'isTTY', { value: isTTY, configurable: true });
      if (noColor === undefined) vi.stubEnv('NO_COLOR', undefined);
      else vi.stubEnv('NO_COLOR', noColor);
      vi.resetModules();
      return (await import('../../src/util/colors.js')).red('x');
    };
    try {
      process.argv = [...argv, '--ci'];
      expect(await load(true, undefined)).not.toBe('x');
      expect(await load(true, '1')).toBe('x');
      expect(await load(false, undefined)).toBe('x');
    } finally {
      process.argv = argv;
      if (tty) Object.defineProperty(process.stdout, 'isTTY', tty);
      else delete (process.stdout as { isTTY?: boolean }).isTTY;
    }

    const doc = readDoc();
    const ciSection = section(doc, '### The `--ci` Flag').join('\n');
    expect(ciSection).toContain('`NO_COLOR`');
    expect(ciSection).toMatch(/stdout is not a terminal/);
    // No line attributes "no color" to --ci, in prose or in a command comment.
    for (const line of doc.split('\n')) {
      if (/--ci\b/.test(line)) expect(line, line).not.toMatch(/(?:no|disables?) colou?r/i);
    }
  });
});

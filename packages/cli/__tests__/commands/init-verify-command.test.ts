import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { execFileSync, execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { init, getVerificationCommand, getToolRecommendation } from '../../src/commands/init.js';

// Regression found in the 0.10.8 release test: `init` on an empty project
// emitted an ENV-DOTENV Verify command (`cat .gitignore | grep -c '.env'`) that
// errors when no .gitignore exists ("No such file or directory"). The Verify
// command must be runnable on a project with no .gitignore.

function finding(findingId: string) {
  return {
    findingId,
    title: '.env not in .gitignore',
    severity: 'medium',
    count: 1,
    explanation: '',
    businessImpact: '',
    locations: [],
  };
}

describe('getVerificationCommand — ENV-DOTENV on a project with no .gitignore', () => {
  it('returns a command that suppresses errors and defaults to 0', () => {
    const cmd = getVerificationCommand(finding('ENV-DOTENV'), '/tmp');
    expect(cmd).toBeTruthy();
    expect(cmd).toContain('2>/dev/null');
    expect(cmd).toContain('|| echo 0');
    // The old fragile form piped a bare `cat .gitignore` — must be gone.
    expect(cmd).not.toMatch(/^cat \.gitignore \| grep/);
  });

  it('the emitted command runs cleanly (exit 0) in a dir with no .gitignore', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-dotenv-verify-'));
    const cmd = getVerificationCommand(finding('ENV-DOTENV'), dir)!;
    try {
      // Should print "0" and exit 0, not throw on a missing .gitignore.
      const out = execSync(cmd, { cwd: dir, shell: '/bin/sh', encoding: 'utf-8' });
      expect(out.trim()).toBe('0');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('counts matches when .gitignore exists', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-dotenv-verify-'));
    const cmd = getVerificationCommand(finding('ENV-DOTENV'), dir)!;
    try {
      fs.writeFileSync(path.join(dir, '.gitignore'), '.env\nnode_modules\n');
      const out = execSync(cmd, { cwd: dir, shell: '/bin/sh', encoding: 'utf-8' });
      expect(Number(out.trim())).toBeGreaterThanOrEqual(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// `opena2a init <dir>` prints its Verify and Fix commands for the shell the
// user ran it in, which is not the scanned directory when a directory is
// given. A path relative to the scanned directory does not resolve there
// (`sed: src/app.ts: No such file or directory`), so every printed path
// names the file from the shell's directory: relative when the file is under
// it, absolute otherwise.

function git(dir: string, args: string[]): string {
  return execFileSync('git', ['-C', dir, ...args], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
}

/** Run a printed command exactly as printed, from `cwd`; throws on a non-zero exit. */
function runPrinted(cwd: string, command: string): string {
  return execFileSync('sh', ['-c', command], { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
}

describe('init commands name files from the directory init runs in', () => {
  let shellDir: string;
  let scanned: string;

  const located = (findingId: string, rel: string, line = 1) => ({
    ...finding(findingId),
    locations: [{ file: path.join(scanned, rel), line }],
  });

  beforeEach(() => {
    shellDir = fs.mkdtempSync(path.join(os.tmpdir(), 'init-shell-dir-'));
    scanned = path.join(shellDir, 'project');
    fs.mkdirSync(path.join(scanned, 'src'), { recursive: true });
    fs.writeFileSync(path.join(scanned, 'src', 'app.ts'), 'line one\nline two\n');
    fs.writeFileSync(path.join(scanned, 'mcp.json'), '{"mcpServers":{}}\n');
    fs.writeFileSync(path.join(scanned, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(scanned, '.env.example'), 'NAME=value\n');
    fs.writeFileSync(path.join(scanned, 'SOUL.md'), '# Soul\n');
    fs.writeFileSync(path.join(scanned, 'SKILL.md'), '# Skill\n');
    fs.writeFileSync(path.join(scanned, 'a.skill.md'), '# Skill\n');
    fs.writeFileSync(path.join(scanned, 'server.key'), '-----BEGIN PRIVATE KEY-----\nFAKE\n');
    vi.spyOn(process, 'cwd').mockReturnValue(shellDir);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(shellDir, { recursive: true, force: true });
  });

  it('every Verify runs from the shell directory and reads the scanned file', () => {
    const cases: [ReturnType<typeof located> | ReturnType<typeof finding>, string][] = [
      [located('CRED-001', 'src/app.ts', 2), 'line two\n'],
      [located('DRIFT-001', 'src/app.ts', 2), 'line two\n'],
      [located('ENV-EXAMPLE-LEAK', '.env.example'), 'NAME=value\n'],
      [located('CRED-KEYFILE', 'server.key'), '-----BEGIN PRIVATE KEY-----\n'],
      [located('MCP-TOOLS', 'mcp.json'), '{"mcpServers":{}}\n'],
      [located('MCP-CRED', 'mcp.json'), '{"mcpServers":{}}\n'],
      [located('AI-CONFIG', '.gitignore'), '.env\n'],
      [located('AI-SOUL', 'SOUL.md'), '# Soul\n'],
      [located('ENV-DOTENV', '.gitignore'), '1\n'],
    ];
    for (const [f, expected] of cases) {
      const cmd = getVerificationCommand(f, scanned)!;
      expect(typeof cmd, f.findingId).toBe('string');
      expect(runPrinted(shellDir, cmd), `${f.findingId}: ${cmd}`).toBe(expected);
    }

    const skills = getVerificationCommand(located('AI-SKILLS', 'SKILL.md'), scanned)!;
    const listed = runPrinted(shellDir, skills);
    expect(listed).toContain('a.skill.md');
    expect(listed).toContain('SKILL.md');
  });

  it('a file under the shell directory is named relative to it, a file outside it absolutely', () => {
    expect(getVerificationCommand(located('CRED-001', 'src/app.ts', 2), scanned))
      .toBe(`sed -n '2p' 'project/src/app.ts'`);

    vi.spyOn(process, 'cwd').mockReturnValue(scanned);
    expect(getVerificationCommand(located('CRED-001', 'src/app.ts', 2), scanned))
      .toBe(`sed -n '2p' 'src/app.ts'`);

    const elsewhere = path.join(shellDir, 'elsewhere');
    fs.mkdirSync(elsewhere);
    vi.spyOn(process, 'cwd').mockReturnValue(elsewhere);
    const cmd = getVerificationCommand(located('CRED-001', 'src/app.ts', 2), scanned)!;
    expect(cmd).toBe(`sed -n '2p' '${path.join(scanned, 'src', 'app.ts')}'`);
    expect(runPrinted(elsewhere, cmd)).toBe('line two\n');
  });

  it('the key-file Fix runs from the shell directory with git -C the repository root', () => {
    git(scanned, ['init', '-q']);
    git(scanned, ['add', '--', 'server.key', 'src/app.ts']);

    const fix = getToolRecommendation(located('CRED-KEYFILE', 'server.key'), scanned)!;
    expect(fix.command).toBe(`git -C 'project' rm --cached 'server.key'`);
    runPrinted(shellDir, fix.command);
    const index = git(scanned, ['ls-files']).split('\n').filter(Boolean);
    expect(index).not.toContain('server.key');
    expect(index).toContain('src/app.ts');
    expect(fs.existsSync(path.join(scanned, 'server.key'))).toBe(true);
  });

  it('the key-file Fix names the path from the repository root when the scanned directory is below it', () => {
    git(shellDir, ['init', '-q']);
    git(shellDir, ['add', '--', 'project/server.key', 'project/src/app.ts']);
    vi.spyOn(process, 'cwd').mockReturnValue(scanned);

    const fix = getToolRecommendation(located('CRED-KEYFILE', 'server.key'), scanned)!;
    expect(fix.command).toMatch(/^git -C '\/[^']+' rm --cached 'project\/server\.key'$/);
    runPrinted(scanned, fix.command);
    const index = git(shellDir, ['ls-files']).split('\n').filter(Boolean);
    expect(index).not.toContain('project/server.key');
    expect(index).toContain('project/src/app.ts');
  });

  it('the key-file Fix is plain git rm --cached when the shell directory is the repository root', () => {
    git(scanned, ['init', '-q']);
    git(scanned, ['add', '--', 'server.key']);
    vi.spyOn(process, 'cwd').mockReturnValue(scanned);

    const fix = getToolRecommendation(located('CRED-KEYFILE', 'server.key'), scanned)!;
    expect(fix.command).toBe(`git rm --cached 'server.key'`);
  });

  // A key git does not track takes a rule anchored to the scanned directory,
  // which matches the key only in that directory's .gitignore: appended to
  // the .gitignore of the directory the Fix is pasted in, it names a path
  // there instead.
  it('the untracked key-file Fix appends its rule to the scanned directory .gitignore, run from the shell directory', () => {
    git(scanned, ['init', '-q']);

    const fix = getToolRecommendation(located('CRED-KEYFILE', 'server.key'), scanned)!;
    expect(fix).toEqual({
      command: String.raw`printf '%s\n' '' '/server.key' >> 'project/.gitignore'`,
      label: '.gitignore',
    });
    runPrinted(shellDir, fix.command);
    expect(fs.readFileSync(path.join(scanned, '.gitignore'), 'utf-8')).toBe('.env\n\n/server.key\n');
    expect(fs.existsSync(path.join(shellDir, '.gitignore'))).toBe(false);
    expect(() => git(scanned, ['check-ignore', '-q', '--', 'server.key'])).not.toThrow();
    expect(fs.existsSync(path.join(scanned, 'server.key'))).toBe(true);
  });

  it('the untracked key-file Fix names the scanned directory .gitignore absolutely from outside it, under a repository root above it', () => {
    git(shellDir, ['init', '-q']);
    const elsewhere = path.join(shellDir, 'elsewhere');
    fs.mkdirSync(elsewhere);
    vi.spyOn(process, 'cwd').mockReturnValue(elsewhere);

    const fix = getToolRecommendation(located('CRED-KEYFILE', 'server.key'), scanned)!;
    expect(fix.command).toBe(String.raw`printf '%s\n' '' '/server.key' >> '${path.join(scanned, '.gitignore')}'`);
    runPrinted(elsewhere, fix.command);
    expect(fs.existsSync(path.join(elsewhere, '.gitignore'))).toBe(false);
    expect(() => git(shellDir, ['check-ignore', '-q', '--', 'project/server.key'])).not.toThrow();
  });

  it('the untracked key-file Fix appends to .gitignore when the shell directory is the scanned one', () => {
    vi.spyOn(process, 'cwd').mockReturnValue(scanned);

    const fix = getToolRecommendation(located('CRED-KEYFILE', 'server.key'), scanned)!;
    expect(fix.command).toBe(String.raw`printf '%s\n' '' '/server.key' >> .gitignore`);
  });

  // `opena2a protect`, `shield init` and `guard sign` act on the directory
  // they are given, else on the one they are run in, so a Fix that names no
  // directory acts on the shell directory, not the scanned one.
  const opena2aFixes: [string, string][] = [
    ['CRED-001', 'opena2a protect'],
    ['DRIFT-001', 'opena2a protect'],
    ['ENV-DOTENV', 'opena2a protect'],
    ['MCP-CRED', 'opena2a protect'],
    ['AI-CONFIG', 'opena2a protect'],
    ['ENV-LLM', 'opena2a shield init'],
    ['MCP-TOOLS', 'opena2a shield init'],
    ['AI-SKILLS', 'opena2a guard sign --skills'],
    ['AI-SOUL', 'opena2a guard sign'],
  ];

  it('every opena2a Fix names the scanned directory from the shell directory', () => {
    for (const [id, command] of opena2aFixes) {
      expect(getToolRecommendation(finding(id), scanned), id).toEqual({ command: `${command} 'project'`, label: command });
    }
  });

  it('every opena2a Fix names no directory when the shell directory is the scanned one', () => {
    vi.spyOn(process, 'cwd').mockReturnValue(scanned);
    for (const [id, command] of opena2aFixes) {
      expect(getToolRecommendation(finding(id), scanned), id).toEqual({ command, label: command });
    }
  });

  it('every opena2a Fix names the scanned directory absolutely from outside it', () => {
    const elsewhere = path.join(shellDir, 'elsewhere');
    fs.mkdirSync(elsewhere);
    vi.spyOn(process, 'cwd').mockReturnValue(elsewhere);
    for (const [id, command] of opena2aFixes) {
      expect(getToolRecommendation(finding(id), scanned)!.command, id).toBe(`${command} '${scanned}'`);
    }
  });

  it('the scan --deep Fix, which reads the home directory, names no directory', () => {
    expect(getToolRecommendation(finding('HMA-001'), scanned)!.command).toBe('opena2a scan --deep');
  });

  it('init <dir> prints opena2a Fix lines that name the directory, and init inside it prints them without', async () => {
    fs.writeFileSync(path.join(scanned, 'src', 'config.ts'), `const k = "${'sk-' + 'ant-api03-' + 'P'.repeat(85)}";\n`);
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in this test'); }));
    try {
      const fixLines = async () => (await captureStdout(() => init({ targetDir: scanned })))
        .replace(ANSI, '').split('\n').map(l => l.trim()).filter(l => /^Fix: +opena2a /.test(l));

      const fromParent = await fixLines();
      expect(fromParent).toContain(`Fix:    opena2a protect 'project'`);
      for (const line of fromParent) expect(line).toMatch(/ 'project'$/);

      vi.spyOn(process, 'cwd').mockReturnValue(scanned);
      const inside = await fixLines();
      expect(inside).toContain('Fix:    opena2a protect');
      for (const line of inside) expect(line).not.toContain('project');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('the template-leak action greps the template from the shell directory', async () => {
    fs.writeFileSync(path.join(scanned, '.env.example'), `ANTHROPIC_API_KEY=${'sk-' + 'ant-api03-' + 'Q'.repeat(85)}\n`);
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in this test'); }));
    try {
      const out = await captureStdout(() => init({ targetDir: scanned, format: 'json' }));
      const report = JSON.parse(out);
      const action = report.actions.find((a: { command: string }) => a.command.startsWith('grep -nE'));
      expect(action).toBeDefined();
      expect(action.command).toContain(`'project/.env.example'`);
      expect(runPrinted(shellDir, action.command)).toMatch(/^1:ANTHROPIC_API_KEY=/);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

function captureStdout(fn: () => Promise<number>): Promise<string> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: unknown) => { chunks.push(String(chunk)); return true; }) as typeof process.stdout.write;
  return fn().finally(() => { process.stdout.write = origWrite; }).then(() => chunks.join(''));
}

const ANSI = new RegExp(String.fromCharCode(27) + '\\[[0-9;]*m', 'g');

// The drift callout: its Verify is the dry run, which reports drift and
// changes no file; its Fix is the run that applies the fixes. A Verify line
// never names a command that writes.
describe('init drift callout', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'init-drift-'));
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in this test'); }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('Verify is opena2a protect --dry-run and Fix is opena2a protect, for DRIFT-001 and DRIFT-002', async () => {
    const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const mapsKey = 'AI' + 'za' + Array.from({ length: 35 }, (_, i) => chars[(i * 7 + 3) % chars.length]).join('');
    const awsKey = 'AK' + 'IA' + Array.from({ length: 16 }, (_, i) => 'BCDFGHJKLMNPQRSTVWXZ234567'[(i * 5 + 2) % 26]).join('');
    fs.mkdirSync(path.join(dir, 'src'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'drift-test' }));
    fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(dir, 'src', 'maps.ts'), `export const mapsKey = "${mapsKey}";\n`);
    fs.writeFileSync(path.join(dir, 'src', 'aws.ts'), `export const awsKey = "${awsKey}";\n`);

    vi.spyOn(process, 'cwd').mockReturnValue(dir);
    const out = (await captureStdout(() => init({ targetDir: dir }))).replace(ANSI, '');
    const start = out.indexOf('Scope Drift Detected');
    expect(start).toBeGreaterThan(-1);
    const callout = out.slice(start);

    for (const id of ['DRIFT-001', 'DRIFT-002']) {
      const block = callout.slice(callout.indexOf(id)).split('\n\n')[0];
      expect(block, id).toContain('Verify:  opena2a protect --dry-run');
      expect(block, id).toMatch(/Verify: {2}opena2a protect --dry-run\n\s+\(.*changes no file\)/);
      expect(block, id).toContain('Fix:     opena2a protect\n');
      expect(block, id).toMatch(/Fix: {5}opena2a protect\n\s+\(runs live .* access check and applies fixes\)/);
    }

    // No Verify line anywhere in the output names a command that writes.
    const verifyLines = out.split('\n').filter(l => l.includes('Verify:'));
    expect(verifyLines.length).toBeGreaterThan(0);
    for (const line of verifyLines) {
      expect(line).not.toMatch(/opena2a protect(?! --dry-run)/);
      expect(line).not.toMatch(/git rm|guard sign|shield init/);
    }
  });

  it('Verify and Fix name the scanned directory when init is run from its parent', async () => {
    const awsKey = 'AK' + 'IA' + Array.from({ length: 16 }, (_, i) => 'BCDFGHJKLMNPQRSTVWXZ234567'[(i * 5 + 2) % 26]).join('');
    const project = path.join(dir, 'project');
    fs.mkdirSync(path.join(project, 'src'), { recursive: true });
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'drift-test' }));
    fs.writeFileSync(path.join(project, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(project, 'src', 'aws.ts'), `export const awsKey = "${awsKey}";\n`);
    vi.spyOn(process, 'cwd').mockReturnValue(dir);

    const out = (await captureStdout(() => init({ targetDir: project }))).replace(ANSI, '');
    const callout = out.slice(out.indexOf('Scope Drift Detected'));
    const block = callout.slice(callout.indexOf('DRIFT-002')).split('\n\n')[0];
    expect(block).toContain(`Verify:  opena2a protect --dry-run 'project'\n`);
    expect(block).toContain(`Fix:     opena2a protect 'project'\n`);
  });

  // Every Fix line of one run, the findings list and the callout alike.
  const driftFixLines = async (project: string, shellDir: string): Promise<string[]> => {
    vi.spyOn(process, 'cwd').mockReturnValue(shellDir);
    const out = (await captureStdout(() => init({ targetDir: project }))).replace(ANSI, '');
    return out.split('\n').map(l => l.trim()).filter(l => l.startsWith('Fix'));
  };
  const driftProject = (root: string): string => {
    const awsKey = 'AK' + 'IA' + Array.from({ length: 16 }, (_, i) => 'BCDFGHJKLMNPQRSTVWXZ234567'[(i * 5 + 2) % 26]).join('');
    const project = path.join(root, 'project');
    fs.mkdirSync(path.join(project, 'src'), { recursive: true });
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'drift-test' }));
    fs.writeFileSync(path.join(project, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(project, 'src', 'aws.ts'), `export const awsKey = "${awsKey}";\n`);
    return project;
  };

  it('every Fix line of the output names the scanned directory when init is run from its parent', async () => {
    const project = driftProject(dir);
    const fixes = await driftFixLines(project, dir);
    // One in the findings list and one in the callout.
    expect(fixes.length).toBeGreaterThanOrEqual(2);
    for (const line of fixes) expect(line).toMatch(/^Fix: +opena2a protect 'project'$/);
  });

  it('no Fix line carries a directory when init is run inside the project', async () => {
    const project = driftProject(dir);
    const fixes = await driftFixLines(project, project);
    expect(fixes.length).toBeGreaterThanOrEqual(2);
    for (const line of fixes) expect(line).toMatch(/^Fix: +opena2a protect$/);
  });
});

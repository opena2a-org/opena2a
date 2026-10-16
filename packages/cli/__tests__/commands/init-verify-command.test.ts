import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { execFileSync, execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { init, getVerificationCommand, getToolRecommendation } from '../../src/commands/init.js';

// Regression for the 0.10.8 release-test P3 finding: `init` on an empty project
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

describe('getVerificationCommand — ENV-DOTENV (#release-test P3)', () => {
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
});

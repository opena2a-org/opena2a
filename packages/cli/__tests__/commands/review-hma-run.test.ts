import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';

// Hermetic homedir: review reads the global Shield event log under ~/.opena2a.
const mockHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => mockHome.dir || actual.homedir() };
});

import { review, runHmaPhase } from '../../src/commands/review.js';

// The stubs are POSIX shell scripts standing in for `npx`.
const posix = process.platform === 'win32' ? describe.skip : describe;

const VERSION_OK = 'if [ "$2" = "--version" ]; then echo "9.9.9-stub"; exit 0; fi';

posix('runHmaPhase records why HMA produced no result', () => {
  let bin: string;
  const origPath = process.env.PATH;

  function stubNpx(body: string, onlyStub = false): void {
    fs.writeFileSync(path.join(bin, 'npx'), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
    process.env.PATH = onlyStub ? bin : `${bin}${path.delimiter}${origPath}`;
  }

  beforeEach(() => {
    bin = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-hma-stub-'));
  });

  afterEach(() => {
    process.env.PATH = origPath;
    fs.rmSync(bin, { recursive: true, force: true });
  });

  it('notFound when npx cannot start hackmyagent, with its message', async () => {
    stubNpx('echo "npm error could not determine executable to run" >&2\nexit 1');
    const hma = await runHmaPhase('.');
    expect(hma.available).toBe(false);
    expect(hma.run.status).toBe('notFound');
    expect(hma.run.reason).toContain('could not determine executable to run');
    expect(hma.run.version).toBeNull();
  });

  it('notFound when npx itself is missing', async () => {
    fs.rmSync(path.join(bin, 'npx'), { force: true });
    process.env.PATH = bin;
    const hma = await runHmaPhase('.');
    expect(hma.run.status).toBe('notFound');
    expect(hma.run.reason).toContain('npx could not be started');
  });

  it('exitError when the scan exits non-zero without a report', async () => {
    stubNpx(`${VERSION_OK}\necho "scanner crashed: out of memory" >&2\nexit 3`);
    const hma = await runHmaPhase('.');
    expect(hma.run.status).toBe('exitError');
    expect(hma.run.reason).toContain('code 3');
    expect(hma.run.reason).toContain('scanner crashed: out of memory');
    expect(hma.run.version).toBe('9.9.9-stub');
  });

  it('badOutput when a banner precedes the JSON', async () => {
    stubNpx(`${VERSION_OK}\necho "HackMyAgent banner line"\necho '{"findings":[],"score":90,"maxScore":100}'`);
    const hma = await runHmaPhase('.');
    expect(hma.available).toBe(false);
    expect(hma.run.status).toBe('badOutput');
    expect(hma.run.reason).toContain('is not a JSON report');
    expect(hma.run.reason).toContain('exit code 0');
    expect(hma.run.reason).not.toContain('HackMyAgent banner line');
  });

  it('badOutput never quotes the output, so a value the scanner printed stays out of the report', async () => {
    const printed = `FAKE-${randomBytes(12).toString('hex')}`;
    stubNpx(`${VERSION_OK}\necho "token=${printed}"\necho "not json"`);
    const hma = await runHmaPhase('.');
    expect(hma.run.status).toBe('badOutput');
    expect(hma.run.reason).toContain(`${`token=${printed}\nnot json\n`.length} characters`);
    expect(JSON.stringify(hma)).not.toContain(printed);
  });

  it('a credential the scanner printed on stderr is redacted from the reason', async () => {
    const key = `sk-ant-api03-FAKE${randomBytes(24).toString('hex')}`;
    const password = `FAKE${randomBytes(8).toString('hex')}`;
    stubNpx(`${VERSION_OK}\necho "cannot read postgres://app:${password}@db.local/app with key ${key}" >&2\nexit 3`);
    const hma = await runHmaPhase('.');
    expect(hma.run.status).toBe('exitError');
    expect(hma.run.reason).toContain('cannot read postgres://app:[redacted]@db.local/app with key [redacted]');
    const serialized = JSON.stringify(hma);
    expect(serialized).not.toContain(password);
    expect(serialized).not.toContain(key);
  });

  it('a URL password holding a slash or an at sign, or following an empty user name, is redacted whole', async () => {
    const [a, b, c, d, e] = [0, 1, 2, 3, 4].map(() => `FAKE${randomBytes(6).toString('hex')}`);
    stubNpx(`${VERSION_OK}\necho "cannot read postgres://app:${a}/${b}@db.local/app, redis://default:${c}@${d}@cache.local or redis://:${e}@queue.local" >&2\nexit 3`);
    const hma = await runHmaPhase('.');
    expect(hma.run.status).toBe('exitError');
    expect(hma.run.reason).toContain('cannot read postgres://app:[redacted]@db.local/app, redis://default:[redacted]@cache.local or redis://:[redacted]@queue.local');
    const serialized = JSON.stringify(hma);
    for (const part of [a, b, c, d, e]) expect(serialized).not.toContain(part);
  });

  // A run of URL-scheme characters with no `://` after it made the password
  // pattern backtrack over the whole run from every word boundary, so the
  // time grew with the square of the line's length.
  const SCHEME_RUN = `awk 'BEGIN { for (i = 0; i < 40000; i++) printf "a+b.c-"; print "" }'`;

  it('a long version line of URL-scheme characters is read in linear time', async () => {
    stubNpx(`if [ "$2" = "--version" ]; then ${SCHEME_RUN}; exit 0; fi\necho '{"findings":[],"score":90,"maxScore":100}'`);
    const started = Date.now();
    const hma = await runHmaPhase('.');
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(hma.run.status).toBe('ran');
    expect(hma.run.version).toMatch(/^a\+b\.c-/);
  });

  it('only the first non-empty line of the version output is read', async () => {
    stubNpx(`if [ "$2" = "--version" ]; then echo; echo "9.9.9-stub"; ${SCHEME_RUN}; exit 0; fi\necho '{"findings":[],"score":90,"maxScore":100}'`);
    const started = Date.now();
    const hma = await runHmaPhase('.');
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(hma.run.version).toBe('9.9.9-stub');
  });

  it('a credential printed where the version goes is redacted too', async () => {
    const token = `ghp_FAKE${randomBytes(20).toString('hex')}`;
    stubNpx(`if [ "$2" = "--version" ]; then echo "${token}"; exit 0; fi\necho '{"findings":[],"score":90,"maxScore":100}'`);
    const hma = await runHmaPhase('.');
    expect(hma.run.status).toBe('ran');
    expect(hma.run.version).toBe('[redacted]');
    expect(JSON.stringify(hma)).not.toContain(token);
  });

  it('timedOut when the scan outlives the deadline, returns at the deadline and stops the scan', async () => {
    const pidFile = path.join(bin, 'scan.pid');
    stubNpx(`${VERSION_OK}\necho $$ > '${pidFile}'\nexec sleep 20`);
    const hma = await runHmaPhase('.', { timeoutMs: 500 });
    expect(hma.run.status).toBe('timedOut');
    expect(hma.run.reason).toBe('HMA stopped after 0.5 s on this tree');
    expect(hma.run.durationMs).toBeLessThan(10_000);

    const pid = Number(fs.readFileSync(pidFile, 'utf-8').trim());
    const alive = (): boolean => {
      try { process.kill(pid, 0); return true; } catch { return false; }
    };
    try {
      for (let waited = 0; alive() && waited < 3_000; waited += 50) {
        await new Promise((r) => setTimeout(r, 50));
      }
      expect(alive()).toBe(false);
    } finally {
      if (alive()) process.kill(pid, 'SIGKILL');
    }
  });

  it('the terminal names a failed scan as failed, not as skipped or not installed', async () => {
    stubNpx(`${VERSION_OK}\necho "scanner crashed: out of memory" >&2\nexit 3`);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-hma-terminal-'));
    mockHome.dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-hma-terminal-home-'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'terminal', version: '1.0.0' }));
    const out: string[] = [];
    const err: string[] = [];
    const origOut = process.stdout.write;
    const origErr = process.stderr.write;
    process.stdout.write = ((c: unknown) => { out.push(String(c)); return true; }) as typeof process.stdout.write;
    process.stderr.write = ((c: unknown) => { err.push(String(c)); return true; }) as typeof process.stderr.write;
    try {
      await review({ targetDir: dir, autoOpen: false, reportPath: path.join(dir, 'report.html') });
    } finally {
      process.stdout.write = origOut;
      process.stderr.write = origErr;
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(mockHome.dir, { recursive: true, force: true });
      mockHome.dir = '';
    }
    const stdout = out.join('');
    const stderr = err.join('');
    expect(stdout).toMatch(/\[5\/6\] Running HMA security scan\.\.\. +\S*failed/);
    expect(stdout).not.toMatch(/\[5\/6\] Running HMA security scan\.\.\. +\S*skipped/);
    expect(stderr).toContain('deep scan (HMA) produced no result');
    expect(stderr).toContain('hackmyagent secure exited with code 3 (scanner crashed: out of memory)');
    expect(stderr).not.toContain('npm i -g hackmyagent');
  });

  it('ran when the scan prints a report, whatever its exit code', async () => {
    const report = JSON.stringify({
      score: 61, maxScore: 100,
      findings: [{ checkId: 'GIT-003', name: '.env Not Ignored', severity: 'critical', passed: false, file: '.env' }],
    });
    stubNpx(`${VERSION_OK}\necho '${report}'\nexit 1`);
    const hma = await runHmaPhase('.');
    expect(hma.available).toBe(true);
    expect(hma.failed).toBe(1);
    expect(hma.run).toMatchObject({ status: 'ran', reason: null, version: '9.9.9-stub' });
  });
});

describe('review JSON carries the collected facts', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-facts-envcase-'));
    mockHome.dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-facts-home-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(mockHome.dir, { recursive: true, force: true });
    mockHome.dir = '';
  });

  it('on an env file git would stage: facts present, skipped HMA named, no value anywhere', async () => {
    const values = [
      randomBytes(12).toString('hex'),
      randomBytes(24).toString('hex'),
      `sk_live_${randomBytes(16).toString('hex')}`,
    ];
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'envcase', version: '1.0.0' }));
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n*.key\n');
    fs.writeFileSync(path.join(dir, '.env'),
      `DATABASE_URL=postgres://app:${values[0]}@localhost:5432/app\nSESSION_SECRET=${values[1]}\nSTRIPE_KEY=${values[2]}\n`);
    execFileSync('git', ['-C', dir, 'init', '-q'], { stdio: 'ignore' });
    const reportPath = path.join(dir, 'report.html');

    const chunks: string[] = [];
    const origOut = process.stdout.write;
    const origErr = process.stderr.write;
    process.stdout.write = ((c: unknown) => { chunks.push(String(c)); return true; }) as typeof process.stdout.write;
    process.stderr.write = (() => true) as typeof process.stderr.write;
    try {
      await review({ targetDir: dir, format: 'json', autoOpen: false, skipHma: true, reportPath });
    } finally {
      process.stdout.write = origOut;
      process.stderr.write = origErr;
    }
    const output = chunks.join('');
    const report = JSON.parse(output);

    expect(report.hmaData.available).toBe(false);
    expect(report.hmaData.run).toMatchObject({ status: 'skipped', reason: 'skipped by --skip-hma' });
    expect(report.initData.envFiles).toMatchObject([
      { path: '.env', assignments: 3, gitIgnored: false, gitTracked: false, stagedByAddAll: true },
    ]);
    expect(report.credentialData.coverage.filesRead).toBe(report.credentialData.filesScanned);
    expect(report.credentialData.coverage.placeholdersSkipped).toBe(0);
    expect(report.guardData.candidates).toEqual(['package.json']);

    const html = fs.readFileSync(reportPath, 'utf-8');
    for (const v of values) {
      expect(output).not.toContain(v);
      expect(html).not.toContain(v);
    }
  });
});

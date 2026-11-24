import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { randomBytes } from 'node:crypto';

// Hermetic homedir: review reads the global Shield event log under ~/.opena2a.
const mockHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => mockHome.dir || actual.homedir() };
});

import { describeHmaNoResult, review, type HmaRunStatusCode } from '../../src/commands/review.js';
import { redactUrlPasswords } from '../../src/util/redact-url-password.js';

const SEE_OUTPUT = 'Run npx hackmyagent secure on this directory to see its output';
const REASON = 'why it produced no result';

const CASES: { status: HmaRunStatusCode; label: string; detail: string; headline: string; next: string }[] = [
  { status: 'skipped', label: 'skipped', detail: 'Skipped (--skip-hma)', headline: 'did not run', next: 'Re-run without --skip-hma' },
  { status: 'notFound', label: 'not installed', detail: 'Not installed', headline: 'did not run', next: 'Install it: npm i -g hackmyagent' },
  { status: 'timedOut', label: 'timed out', detail: 'Timed out', headline: 'produced no result', next: `${REASON}. ${SEE_OUTPUT}` },
  { status: 'exitError', label: 'failed', detail: 'Scan failed', headline: 'produced no result', next: `${REASON}. ${SEE_OUTPUT}` },
  { status: 'badOutput', label: 'output unreadable', detail: 'Output not readable', headline: 'produced no result', next: REASON },
];

describe('describeHmaNoResult names each run that produced no result', () => {
  it.each(CASES)('$status', ({ status, ...expected }) => {
    expect(describeHmaNoResult({ status, reason: REASON, version: null, durationMs: 0 })).toEqual(expected);
  });

  it('only a skipped or missing scanner is named as skipped or not installed', () => {
    for (const { status } of CASES) {
      const { label, detail } = describeHmaNoResult({ status, reason: REASON, version: null, durationMs: 0 });
      if (status !== 'skipped') {
        expect(label).not.toBe('skipped');
        expect(detail).not.toMatch(/skip/i);
      }
      if (status !== 'notFound') {
        expect(label).not.toBe('not installed');
        expect(detail).not.toBe('Not installed');
      }
    }
  });
});

// The stubs are POSIX shell scripts standing in for `npx`.
const posix = process.platform === 'win32' ? describe.skip : describe;

posix('the HMA phase detail in the review report', () => {
  let dir: string;
  let bin: string;
  const origPath = process.env.PATH;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-hma-detail-'));
    bin = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-hma-detail-bin-'));
    mockHome.dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-hma-detail-home-'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'detail', version: '1.0.0' }));
  });

  afterEach(() => {
    process.env.PATH = origPath;
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(bin, { recursive: true, force: true });
    fs.rmSync(mockHome.dir, { recursive: true, force: true });
    mockHome.dir = '';
  });

  async function hmaPhaseDetail(skipHma: boolean): Promise<{ status: string; detail: string }> {
    const chunks: string[] = [];
    const origOut = process.stdout.write;
    const origErr = process.stderr.write;
    process.stdout.write = ((c: unknown) => { chunks.push(String(c)); return true; }) as typeof process.stdout.write;
    process.stderr.write = (() => true) as typeof process.stderr.write;
    try {
      await review({ targetDir: dir, format: 'json', autoOpen: false, skipHma, reportPath: path.join(dir, 'report.html') });
    } finally {
      process.stdout.write = origOut;
      process.stderr.write = origErr;
    }
    const report = JSON.parse(chunks.join(''));
    return report.phases.find((p: { name: string }) => p.name === 'HMA Scan');
  }

  it('--skip-hma is named Skipped (--skip-hma)', async () => {
    expect(await hmaPhaseDetail(true)).toMatchObject({ status: 'skip', detail: 'Skipped (--skip-hma)' });
  });

  it('a scanner npx cannot find is named Not installed', async () => {
    fs.writeFileSync(path.join(bin, 'npx'),
      '#!/bin/sh\necho "npm error could not determine executable to run" >&2\nexit 1\n', { mode: 0o755 });
    process.env.PATH = `${bin}${path.delimiter}${origPath}`;
    expect(await hmaPhaseDetail(false)).toMatchObject({ status: 'skip', detail: 'Not installed' });
  });

  it('a scan that exits non-zero without a report is named Scan failed', async () => {
    fs.writeFileSync(path.join(bin, 'npx'),
      '#!/bin/sh\nif [ "$2" = "--version" ]; then echo "9.9.9-stub"; exit 0; fi\necho "scanner crashed" >&2\nexit 3\n', { mode: 0o755 });
    process.env.PATH = `${bin}${path.delimiter}${origPath}`;
    expect(await hmaPhaseDetail(false)).toMatchObject({ status: 'skip', detail: 'Scan failed' });
  });
});

describe('redactUrlPasswords reads a URL only after a scheme', () => {
  // Built at run time, so no URL with a password is written in this file.
  const pw = `FAKE${randomBytes(6).toString('hex')}`;
  const MASK = '[redacted]';
  const url = (prefix: string, password: string): string => [`${prefix}://app`, password].join(':') + '@host.local/db';

  it.each(['postgres', 'git+ssh', 's3', 'x.y-z', 'HTTPS'])('a password after the scheme %s is redacted', (scheme) => {
    expect(redactUrlPasswords(`at ${url(scheme, pw)} now`, MASK)).toBe(`at ${url(scheme, MASK)} now`);
  });

  // The character next to :// must be a scheme character; ones before it do
  // not count.
  it.each([
    ['nothing', ''],
    ['a parenthesis', '('],
    ['a quote', '"'],
    ['an underscore', 'db_'],
  ])('a :// after %s is not read as a URL', (_name, prefix) => {
    const text = `see ${url(prefix, pw)}`;
    expect(redactUrlPasswords(text, MASK)).toBe(text);
  });
});

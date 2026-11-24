// Regression (#410): the terminal verdict and the HTML report's Summary were
// fed by different findings lists. The terminal counted the analyzers' raw
// `findings` (HMA, credential scan, Shield) plus matched advisories; the
// Summary counted `reportFindings`, which also lists the hygiene, guard and
// Shadow AI findings. A project with no .gitignore and no lock file printed
// "0 findings" and "No security issues detected" while its report said
// "2 low findings to review". Both now read `reportFindings`.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runInNewContext } from 'node:vm';

const mockHome = vi.hoisted(() => ({ dir: '' }));

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => mockHome.dir || actual.homedir(),
  };
});

vi.mock('../../src/util/report-submission.js', () => ({
  recordScanAndMaybePrompt: async () => undefined,
  isContributeEnabled: async () => false,
  getRegistryUrl: async () => 'https://registry.example.test',
  submitScanReport: async () => true,
}));

import { review } from '../../src/commands/review.js';
import { assembleReviewClientScript } from '../../src/report/review-assets.js';

async function captured(run: () => Promise<unknown>): Promise<string> {
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  let stdout = '';
  process.stdout.write = ((chunk: unknown) => { stdout += String(chunk); return true; }) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    await run();
    return stdout;
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
}

/** The report's embedded data, as written to the HTML file. */
function reportData(reportPath: string): Record<string, any> {
  const html = fs.readFileSync(reportPath, 'utf-8');
  const m = html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/);
  if (!m) throw new Error('report-data not found');
  return JSON.parse(m[1].replace(/<\\\//g, '</'));
}

/** The Overview page's Summary heading, rendered by the report's own client script. */
function summaryHeading(report: object): string {
  const pages: Record<string, { innerHTML: string; querySelectorAll: () => never[] }> = {};
  const document = {
    getElementById(id: string) {
      if (id === 'report-data') return { textContent: JSON.stringify(report) };
      if (id === 'main-nav') return { addEventListener() {} };
      return (pages[id] ??= { innerHTML: '', querySelectorAll: () => [] });
    },
    querySelectorAll: () => [],
  };
  runInNewContext(assembleReviewClientScript(), { document, window: { addEventListener() {} } });
  const m = (pages['page-overview']?.innerHTML ?? '').match(/<h2 class="sum-verdict"[^>]*>([\s\S]*?)<\/h2>/);
  if (!m) throw new Error('Summary heading not rendered');
  return m[1];
}

const severityCount = (findings: { severity: string }[], severity: string) =>
  findings.filter(f => f.severity === severity).length;

describe('terminal counts and the report Summary read one findings list (#410)', () => {
  let tempDir: string;
  let tempHome: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-counts-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-counts-home-'));
    mockHome.dir = tempHome;
    process.env.OPENA2A_ADVISORIES = 'off';
  });

  afterEach(() => {
    delete process.env.OPENA2A_ADVISORIES;
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  async function runReview(): Promise<{ report: Record<string, any>; stdout: string }> {
    const reportPath = path.join(tempHome, 'review.html');
    const stdout = await captured(() => review({
      targetDir: tempDir, format: 'text', reportPath, autoOpen: false, skipHma: true, ci: true,
    }));
    return { report: reportData(reportPath), stdout };
  }

  /** The terminal's "N findings (C critical, H high, M medium)" line, as numbers. */
  function terminalCounts(stdout: string): { total: number; critical: number; high: number; medium: number } {
    const m = stdout.match(/(\d+) findings \((\d+) critical, (\d+) high, (\d+) medium\)/);
    if (!m) throw new Error('terminal count line not printed');
    return { total: Number(m[1]), critical: Number(m[2]), high: Number(m[3]), medium: Number(m[4]) };
  }

  function expectAgreement(report: Record<string, any>, stdout: string): void {
    const listed = report.reportFindings as { severity: string }[];
    expect(terminalCounts(stdout)).toEqual({
      total: listed.length,
      critical: severityCount(listed, 'critical'),
      high: severityCount(listed, 'high'),
      medium: severityCount(listed, 'medium'),
    });
  }

  it('a project with only hygiene findings is counted and judged as the report Summary does', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'revcount', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, 'index.js'), 'console.log("hello");\n');

    const { report, stdout } = await runReview();

    // No .gitignore and no lock file: two low findings in the report.
    expect(report.reportFindings.map((f: any) => f.severity)).toEqual(['low', 'low']);
    expect(summaryHeading(report)).toBe('No critical or high findings. 2 low findings to review.');

    expectAgreement(report, stdout);
    expect(stdout).toContain('2 findings (0 critical, 0 high, 0 medium)');
    expect(stdout).not.toContain('No security issues detected');
    const verdict = stdout.split('\n').find(l => l.includes('Verdict')) ?? '';
    expect(verdict).toContain('Usable with caveats');
  });

  it('a credential finding and hygiene findings in one run are counted once each, as the report lists them', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'revcount', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, 'config.js'), 'const key = "sk-ant-api03-' + 'A'.repeat(90) + '";\n');

    const { report, stdout } = await runReview();

    expect(report.reportFindings.some((f: any) => f.foundBy.some((b: any) => b.source === 'credential-scan'))).toBe(true);
    expect(report.reportFindings.some((f: any) => f.foundBy.some((b: any) => b.source === 'hygiene'))).toBe(true);
    expectAgreement(report, stdout);
  });

  it('a clean project reads as clean in both', async () => {
    fs.writeFileSync(path.join(tempDir, 'index.js'), 'console.log("hello");\n');
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const { report, stdout } = await runReview();

    expect(report.reportFindings).toEqual([]);
    expect(summaryHeading(report)).toBe('No findings.');
    expectAgreement(report, stdout);
    expect(stdout).toContain('No security issues detected');
  });
});

// Regression (#408): the terminal's finding line counted the analyzer
// findings and matched advisories only, so a review whose sole finding was a
// hygiene one (an empty git repo, or an unignored .env under --skip-hma)
// printed "0 findings" while `--format json` listed it in reportFindings.
// The line now counts reportFindings, as JSON and the report do.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

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

describe('review terminal finding count (#408)', () => {
  let tempDir: string;
  let tempHome: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-count-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-count-home-'));
    mockHome.dir = tempHome;
    process.env.OPENA2A_ADVISORIES = 'off';
  });

  afterEach(() => {
    delete process.env.OPENA2A_ADVISORIES;
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  async function terminalAndJson(): Promise<{ line: string; reportFindings: Array<{ severity: string }> }> {
    const common = { targetDir: tempDir, autoOpen: false, skipHma: true, ci: true };
    const json = await captured(() => review({ ...common, format: 'json' }));
    const report = JSON.parse(json.slice(json.indexOf('{')));
    const text = await captured(() => review({ ...common, format: 'text', reportPath: path.join(tempHome, 'review.html') }));
    const line = text.split('\n').find(l => /^\s*\d+ findings \(/.test(l));
    if (!line) throw new Error(`no finding line in:\n${text}`);
    return { line: line.trim(), reportFindings: report.reportFindings };
  }

  function expectAgreement(line: string, reportFindings: Array<{ severity: string }>): void {
    expect(reportFindings.length).toBeGreaterThan(0);
    const count = (sev: string) => reportFindings.filter(f => f.severity === sev).length;
    expect(line).toBe(
      `${reportFindings.length} findings (${count('critical')} critical, ${count('high')} high, ${count('medium')} medium)`,
    );
  }

  it('counts the same findings on the terminal as in JSON for an empty git repo', async () => {
    fs.mkdirSync(path.join(tempDir, '.git'));
    const { line, reportFindings } = await terminalAndJson();
    expectAgreement(line, reportFindings);
  }, 60_000);

  it('counts the same findings on the terminal as in JSON for an unignored .env under --skip-hma', async () => {
    fs.mkdirSync(path.join(tempDir, '.git'));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'node_modules\n');
    fs.writeFileSync(path.join(tempDir, '.env'), 'DEBUG=true\n');
    const { line, reportFindings } = await terminalAndJson();
    expectAgreement(line, reportFindings);
  }, 60_000);
});

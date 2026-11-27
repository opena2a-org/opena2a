// The Score line's "composite across N dimensions" counted every phase row,
// skipped ones included. A skipped phase (HMA under --skip-hma, Credentials
// when no file was read) carries no weight in the composite, so it is not a
// dimension the composite spans.

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

describe('review Score line dimension count', () => {
  let tempDir: string;
  let tempHome: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-dims-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-dims-home-'));
    mockHome.dir = tempHome;
    process.env.OPENA2A_ADVISORIES = 'off';
  });

  afterEach(() => {
    delete process.env.OPENA2A_ADVISORIES;
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  it('does not count skipped phases on an empty directory under --skip-hma', async () => {
    const common = { targetDir: tempDir, autoOpen: false, skipHma: true, ci: true };
    const json = await captured(() => review({ ...common, format: 'json' }));
    const report = JSON.parse(json.slice(json.indexOf('{')));
    const phases: Array<{ name: string; status: string }> = report.phases;
    const skipped = phases.filter(p => p.status === 'skip').map(p => p.name).sort();
    expect(skipped).toEqual(['Credentials', 'HMA Scan']);

    const text = await captured(() => review({ ...common, format: 'text', reportPath: path.join(tempHome, 'review.html') }));
    const line = text.split('\n').find(l => l.includes('composite across'));
    if (!line) throw new Error(`no Score line in:\n${text}`);
    expect(line).toMatch(/\(composite across 4 dimensions[;)]/);
    expect(phases.length - skipped.length).toBe(4);
  }, 120000);
});

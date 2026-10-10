// Regression (#420): `opena2a review` and `opena2a init` reported an advisory
// check that made no request.
//
// Both called the check without a Registry URL, so the URL it built was
// relative, fetch refused it, and the empty result was shown as "Advisories
// checked against project dependencies via the OpenA2A Registry. No matching
// advisories found." beside an "Advisories: 0 found" card. The check now
// receives the Registry URL `getRegistryUrl()` resolves, and a run that read
// no advisory list says "not checked".

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runInNewContext } from 'node:vm';

const REGISTRY_URL = 'https://registry.example.test';

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
import { init } from '../../src/commands/init.js';
import { assembleReviewClientScript } from '../../src/report/review-assets.js';

const ADVISORY = {
  id: 'OA2A-2026-0001',
  summary: 'Advisory in vulnerable-package',
  severity: [{ type: 'ADVISORY', score: 'HIGH' }],
  affected: [{ package: { name: 'vulnerable-package', ecosystem: 'npm' } }],
  published: '2026-10-01T00:00:00Z',
};

const mockFetch = vi.fn();

function listResponse(advisories: object[]) {
  return { ok: true, json: async () => ({ advisories, total: advisories.length, format: 'osv' }) };
}

async function silenced<T>(run: () => Promise<T>): Promise<{ result: T; stdout: string }> {
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  let stdout = '';
  process.stdout.write = ((chunk: unknown) => { stdout += String(chunk); return true; }) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    return { result: await run(), stdout };
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

/** The Hygiene tab as visible text, rendered by the report's own client
 *  script after a click on its nav tab. */
function hygieneText(report: object): string {
  const pages: Record<string, { innerHTML: string; querySelectorAll: () => never[] }> = {};
  let onNavClick: ((e: unknown) => void) | null = null;
  const document = {
    getElementById(id: string) {
      if (id === 'report-data') return { textContent: JSON.stringify(report) };
      if (id === 'main-nav') return { addEventListener(_: string, fn: (e: unknown) => void) { onNavClick = fn; } };
      return (pages[id] ??= { innerHTML: '', querySelectorAll: () => [] });
    },
    querySelectorAll: () => [],
  };
  runInNewContext(assembleReviewClientScript(), { document, window: { addEventListener() {} } });
  if (!onNavClick) throw new Error('nav listener not registered');
  (onNavClick as (e: unknown) => void)({
    target: { closest: () => ({ getAttribute: () => 'hygiene' }) },
  });
  return pages['page-hygiene'].innerHTML.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

describe('advisory check in review and init (#420)', () => {
  let tempDir: string;
  let tempHome: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-adv-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-adv-home-'));
    mockHome.dir = tempHome;
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({
      name: 'revfix', version: '1.0.0', dependencies: { 'vulnerable-package': '1.0.0' },
    }));
    vi.stubGlobal('fetch', mockFetch);
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  async function runReview(): Promise<Record<string, any>> {
    const reportPath = path.join(tempHome, 'review.html');
    await silenced(() => review({
      targetDir: tempDir,
      format: 'text',
      reportPath,
      autoOpen: false,
      skipHma: true,
      ci: true,
    }));
    return reportData(reportPath);
  }

  function advisoryRequests(): string[] {
    return mockFetch.mock.calls.map(c => String(c[0])).filter(u => u.includes('/api/v1/trust/advisories'));
  }

  it('review requests the advisory list from the resolved Registry URL and reports the match', async () => {
    mockFetch.mockResolvedValue(listResponse([ADVISORY]));

    const report = await runReview();

    expect(advisoryRequests()).toHaveLength(1);
    expect(advisoryRequests()[0].startsWith(`${REGISTRY_URL}/api/v1/trust/advisories?`)).toBe(true);
    expect(report.initData.advisoriesChecked).toBe(true);
    expect(report.initData.advisoryCount).toBe(1);
    expect(report.initData.matchedPackages).toEqual(['vulnerable-package']);
    const t = hygieneText(report);
    expect(t).toContain('1 found');
    expect(t).toContain('vulnerable-package');
  });

  it('review says "not checked" when no advisory list was read', async () => {
    mockFetch.mockRejectedValue(new Error('getaddrinfo ENOTFOUND registry.example.test'));

    const report = await runReview();

    expect(advisoryRequests()).toHaveLength(1);
    expect(report.initData.advisoriesChecked).toBe(false);
    const t = hygieneText(report);
    expect(t).toContain('not checked');
    expect(t).toContain('no advisory list was read from the OpenA2A Registry');
    expect(t).not.toContain('0 found');
    expect(t).not.toContain('No matching advisories found');
  });

  it('review keeps "0 found" for a list that was read and matched nothing', async () => {
    mockFetch.mockResolvedValue(listResponse([]));

    const report = await runReview();

    expect(report.initData.advisoriesChecked).toBe(true);
    const t = hygieneText(report);
    expect(t).toContain('0 found');
    expect(t).toContain('No matching advisories found');
  });

  it('review writes no advisory cache into the reviewed tree', async () => {
    mockFetch.mockResolvedValue(listResponse([]));

    await runReview();

    expect(fs.existsSync(path.join(tempDir, '.opena2a'))).toBe(false);
  });

  it('init requests the advisory list from the resolved Registry URL', async () => {
    mockFetch.mockResolvedValue(listResponse([ADVISORY]));

    const { stdout } = await silenced(() => init({ targetDir: tempDir, format: 'json' }));
    const json = JSON.parse(stdout);

    expect(advisoryRequests()).toHaveLength(1);
    expect(advisoryRequests()[0].startsWith(`${REGISTRY_URL}/api/v1/trust/advisories?`)).toBe(true);
    expect(json.advisories).toEqual({ checked: true, count: 1, matchedPackages: ['vulnerable-package'] });
  });

  it('init --json says the advisories were not checked when no list was read', async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 503 });

    const { stdout } = await silenced(() => init({ targetDir: tempDir, format: 'json' }));
    const json = JSON.parse(stdout);

    expect(json.advisories).toEqual({ checked: false, count: 0, matchedPackages: [] });
  });
});

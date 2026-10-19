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
// What getRegistryUrl() answers: a URL, or the error it throws for a refused
// configured URL.
const registry = vi.hoisted(() => ({ answer: 'https://registry.example.test' as string | Error }));

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
  getRegistryUrl: async () => {
    if (registry.answer instanceof Error) throw registry.answer;
    return registry.answer;
  },
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

function listResponse(advisories: object[], total = advisories.length) {
  return { ok: true, json: async () => ({ advisories, total, format: 'osv' }) };
}

async function silenced<T>(run: () => Promise<T>): Promise<{ result: T; stdout: string; stderr: string }> {
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  let stdout = '';
  let stderr = '';
  process.stdout.write = ((chunk: unknown) => { stdout += String(chunk); return true; }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: unknown) => { stderr += String(chunk); return true; }) as typeof process.stderr.write;
  try {
    const result = await run();
    return { result, stdout, stderr };
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
    registry.answer = REGISTRY_URL;
    delete process.env.OPENA2A_ADVISORIES;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.OPENA2A_ADVISORIES;
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

describe('advisory findings, scope and reasons in review and init (#464)', () => {
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
    registry.answer = REGISTRY_URL;
    delete process.env.OPENA2A_ADVISORIES;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.OPENA2A_ADVISORIES;
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  async function runReview(verbose = false): Promise<{ report: Record<string, any>; stdout: string; stderr: string }> {
    const reportPath = path.join(tempHome, 'review.html');
    const { stdout, stderr } = await silenced(() => review({
      targetDir: tempDir,
      format: 'text',
      reportPath,
      autoOpen: false,
      skipHma: true,
      ci: true,
      verbose,
    }));
    return { report: reportData(reportPath), stdout, stderr };
  }

  const advisoryFinding = (report: Record<string, any>) =>
    report.reportFindings.find((f: any) => f.foundBy.some((b: any) => b.source === 'advisories'));

  // The terminal printed "0 findings" and "No security issues detected"
  // while the report counted the matched advisory as a high finding.
  it('the terminal summary counts a matched advisory as the report does', async () => {
    mockFetch.mockResolvedValue(listResponse([ADVISORY]));

    const { report, stdout } = await runReview();

    expect(advisoryFinding(report).severity).toBe('high');
    expect(stdout).toContain('1 findings (0 critical, 1 high, 0 medium)');
    expect(stdout).not.toContain('No security issues detected');
  });

  it('a matched advisory that names a fixed version gets the install and verify commands', async () => {
    mockFetch.mockResolvedValue(listResponse([{
      ...ADVISORY,
      affected: [{ package: { name: 'vulnerable-package', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.3.0' }] }] }],
    }]));

    const { report } = await runReview();
    const f = advisoryFinding(report);

    expect(f.fix).toEqual(expect.objectContaining({ command: 'npm install vulnerable-package@1.3.0', tool: 'npm' }));
    expect(f.verify).toEqual(expect.objectContaining({ command: 'npm ls vulnerable-package', tool: 'npm' }));
    expect(f.evidence[0].text).toContain('fixed in vulnerable-package 1.3.0');
  });

  it('a matched advisory without a fixed version keeps the advice and no command', async () => {
    mockFetch.mockResolvedValue(listResponse([ADVISORY]));

    const f = advisoryFinding((await runReview()).report);

    expect(f.fix).toBeNull();
    expect(f.advice).toBe('Upgrade vulnerable-package to a version OA2A-2026-0001 does not affect.');
  });

  it('a fixed version with shell characters gets no command and is named nowhere in the finding', async () => {
    mockFetch.mockResolvedValue(listResponse([{
      ...ADVISORY,
      affected: [{ package: { name: 'vulnerable-package', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '1.3.0-$(touch pwned)' }, { fixed: '1.3.0;id' }] }] }],
    }]));

    const f = advisoryFinding((await runReview()).report);

    expect(f.fix).toBeNull();
    expect(f.verify).toBeNull();
    expect(JSON.stringify(f)).not.toContain('pwned');
    expect(JSON.stringify(f)).not.toContain('1.3.0;id');
    expect(f.advice).toBe('Upgrade vulnerable-package to a version OA2A-2026-0001 does not affect.');
  });

  // Regression: the answer was read as received, and one entry of the wrong
  // shape stopped review and init with a TypeError.
  const WRONG_SHAPE = [
    null,
    { ...ADVISORY, id: 'OA2A-2026-0011', affected: [{ package: { name: 'vulnerable-package', ecosystem: 7 }, ranges: [{ type: 'SEMVER', events: [{ fixed: '1.3.0' }] }] }] },
    { ...ADVISORY, id: 'OA2A-2026-0012', affected: [{ package: { name: 'vulnerable-package', ecosystem: 'npm' }, ranges: { events: [{ fixed: '1.3.0' }] } }] },
  ];

  it('review reads an advisory answer of the wrong shape and reports the advisories it can read', async () => {
    mockFetch.mockResolvedValue(listResponse(WRONG_SHAPE));

    const { report } = await runReview();
    const found = report.reportFindings.filter((f: any) => f.foundBy.some((b: any) => b.source === 'advisories'));

    expect(report.initData.advisoriesChecked).toBe(true);
    expect(report.initData.advisoryRead).toEqual(expect.objectContaining({ listed: 2, total: 3 }));
    expect(found.map((f: any) => f.foundBy[0].checkId).sort()).toEqual(['OA2A-2026-0011', 'OA2A-2026-0012']);
    // An ecosystem that is not text is not npm, so no install command.
    expect(found.find((f: any) => f.foundBy[0].checkId === 'OA2A-2026-0011').fix).toBeNull();
  });

  it('init reads the same answer and prints the advisories it can read', async () => {
    mockFetch.mockResolvedValue(listResponse(WRONG_SHAPE));

    const { stdout } = await silenced(() => init({ targetDir: tempDir, format: 'text' }));

    expect(stdout).toContain('ID: OA2A-2026-0011');
    expect(stdout).toContain('ID: OA2A-2026-0012');
  });

  it('the Hygiene tab states the window and the advisories the Registry reported but the request did not read', async () => {
    mockFetch.mockResolvedValue(listResponse([], 250));

    const { report } = await runReview();
    const t = hygieneText(report);

    expect(report.initData.advisoryRead).toEqual(expect.objectContaining({ windowDays: 30, limit: 100, listed: 0, total: 250 }));
    expect(t).toContain('Advisories published in the last 30 days (at most 100) were read from the OpenA2A Registry');
    expect(t).toContain('The Registry reported 250 advisories; 250 were not read or compared.');
    expect(t).toContain('No matching advisories found');
  });

  it('a refused registry.url is named in --verbose output and on the Hygiene tab', async () => {
    registry.answer = new Error('Registry URL must use HTTPS: http://registry.internal.example\nPlain HTTP is only allowed for localhost development.');

    const { report, stderr } = await runReview(true);

    expect(mockFetch).not.toHaveBeenCalled();
    expect(stderr).toContain('Advisories not checked: Registry URL must use HTTPS: http://registry.internal.example');
    expect(report.initData.advisoryRead.notCheckedReason).toBe('Registry URL must use HTTPS: http://registry.internal.example');
    expect(hygieneText(report)).toContain('Reason: Registry URL must use HTTPS: http://registry.internal.example.');
  });

  it('the Hygiene tab shows markup in the reason as text', async () => {
    registry.answer = new Error('Invalid registry URL: https://registry.example.test/<img src=x onerror=alert(1)>');

    const { report } = await runReview();

    // Rendered as markup, the tag would be stripped from the visible text.
    expect(hygieneText(report)).toContain('Reason: Invalid registry URL: https://registry.example.test/&lt;img src=x onerror=alert(1)&gt;.');
  });

  it('OPENA2A_ADVISORIES=off makes no request and says how to turn the check back on', async () => {
    process.env.OPENA2A_ADVISORIES = 'off';

    const { report } = await runReview();
    const t = hygieneText(report);

    expect(mockFetch).not.toHaveBeenCalled();
    expect(report.initData.advisoriesChecked).toBe(false);
    expect(report.initData.advisoryRead.turnedOff).toBe(true);
    expect(t).toContain('not checked');
    expect(t).toContain('Unset OPENA2A_ADVISORIES to check them.');
  });

  it('init prints Registry advisory text without its control characters', async () => {
    mockFetch.mockResolvedValue(listResponse([{ ...ADVISORY, summary: 'Bad thing\x1b[31mRED\nFORGED LINE' }]));

    const { stdout } = await silenced(() => init({ targetDir: tempDir, format: 'text' }));

    expect(stdout).toContain('Bad thing[31mREDFORGED LINE');
    expect(stdout).not.toContain('\x1b[31mRED');
    expect(stdout.split('\n').some(l => /^\s*FORGED LINE/.test(l))).toBe(false);
  });

  it('init --verbose names why the advisories were not checked', async () => {
    registry.answer = new Error('Registry URL must use HTTPS: http://registry.internal.example');

    const { stdout } = await silenced(() => init({ targetDir: tempDir, format: 'text', verbose: true }));

    expect(stdout).toContain('Advisories not checked: Registry URL must use HTTPS: http://registry.internal.example');
  });
});

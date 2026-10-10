// Regression: what `opena2a review` sends to the Registry when contribution
// is on.
//
// It sent the printed project label ("Node.js + MCP server", "Unknown") as the
// package ecosystem and "unknown" as the name of a nameless tree. The
// Registry's contribute endpoint keeps an event only for the npm, pypi or
// github ecosystems, so every review contribution was discarded, and a
// nameless tree published a community scan for a package called "unknown".
// A review now contributes only a named npm or PyPI package, with the
// ecosystem the Registry accepts, and sends nothing otherwise.

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

const submission = vi.hoisted(() => ({
  isContributeEnabled: vi.fn(async () => true),
  submitScanReport: vi.fn(async () => true),
}));

vi.mock('../../src/util/report-submission.js', () => ({
  recordScanAndMaybePrompt: async () => undefined,
  isContributeEnabled: submission.isContributeEnabled,
  getRegistryUrl: async () => 'https://api.oa2a.org',
  submitScanReport: submission.submitScanReport,
}));

import { review, contributionPackage } from '../../src/commands/review.js';

// Text mode: the JSON branch returns before the contribution step runs.
async function runReview(targetDir: string): Promise<number> {
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    return await review({
      targetDir,
      format: 'text',
      reportPath: path.join(targetDir, 'review.html'),
      autoOpen: false,
      skipHma: true,
      ci: true,
    });
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
}

describe('contributionPackage', () => {
  it('a named Node.js project contributes as an npm package', () => {
    expect(contributionPackage({ type: 'node', name: 'revfix' })).toEqual({ name: 'revfix', type: 'npm' });
  });

  it('a named Python project contributes as a PyPI package', () => {
    expect(contributionPackage({ type: 'python', name: 'revfix' })).toEqual({ name: 'revfix', type: 'pypi' });
  });

  it('a project with no name contributes nothing, whatever its type', () => {
    expect(contributionPackage({ type: 'node', name: null })).toBeNull();
    expect(contributionPackage({ type: 'python', name: null })).toBeNull();
    expect(contributionPackage({ type: 'generic', name: null })).toBeNull();
  });

  it('an ecosystem the Registry does not keep contributes nothing', () => {
    for (const type of ['go', 'rust', 'java', 'ruby', 'docker', 'generic'] as const) {
      expect(contributionPackage({ type, name: 'revfix' })).toBeNull();
    }
  });
});

describe('review contribution', () => {
  let tempDir: string;
  let tempHome: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-contrib-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-contrib-home-'));
    mockHome.dir = tempHome;
    submission.isContributeEnabled.mockClear();
    submission.submitScanReport.mockClear();
  });

  // Each negative case checks that review reached the contribution step and
  // chose to send nothing; a run that never got there would pass for the
  // wrong reason.
  function expectNothingSent(): void {
    expect(submission.isContributeEnabled).toHaveBeenCalledTimes(1);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
  }

  afterEach(() => {
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  it('a named Node.js project is sent as an npm package under its own name', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'revfix', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');
    fs.mkdirSync(path.join(tempDir, '.git'));

    await runReview(tempDir);

    expect(submission.submitScanReport).toHaveBeenCalledTimes(1);
    const [registryUrl, report] = submission.submitScanReport.mock.calls[0] as unknown as [string, Record<string, unknown>];
    expect(registryUrl).toBe('https://api.oa2a.org');
    expect(report.packageName).toBe('revfix');
    expect(report.packageType).toBe('npm');
    expect(report.scannerName).toBe('opena2a-review');
  });

  it('a Go module is not sent: the Registry keeps no scan for that ecosystem', async () => {
    fs.writeFileSync(path.join(tempDir, 'go.mod'), 'module github.com/example/revfix\n\ngo 1.22\n');
    fs.mkdirSync(path.join(tempDir, '.git'));

    await runReview(tempDir);

    expectNothingSent();
  });

  it('a tree with no package name is not sent, instead of publishing as "unknown"', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ version: '1.0.0' }));
    fs.mkdirSync(path.join(tempDir, '.git'));

    await runReview(tempDir);

    expectNothingSent();
  });

  it('a directory with no manifest at all is not sent', async () => {
    fs.writeFileSync(path.join(tempDir, 'README.md'), '# nothing here\n');

    await runReview(tempDir);

    expectNothingSent();
  });
});

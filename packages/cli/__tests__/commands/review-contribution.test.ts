// Regression: what `opena2a review` sends to the Registry when contribution
// is on.
//
// It sent the printed project label ("Node.js + MCP server", "Unknown") as the
// package ecosystem and "unknown" as the name of a nameless tree. The
// Registry's contribute endpoint keeps an event only for the npm, pypi or
// github ecosystems, so every review contribution was discarded, and a
// nameless tree published a community scan for a package called "unknown".
// A review now contributes only a Node.js project whose package.json name has
// the form of an npm package name, as an npm package, and sends nothing
// otherwise.
//
// A Python tree sends nothing. Its name is the first `name = "..."` line
// anywhere in pyproject.toml, which can belong to a package index or a tool
// setting instead of the project, and a package.json beside a Python marker
// can keep its npm name while the tree is typed as Python.

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
import { detectProject } from '../../src/util/detect.js';

// Text mode: the JSON branch returns before the contribution step runs.
// `stdout`, when given, receives what the review prints there.
async function runReview(targetDir: string, stdout?: string[]): Promise<number> {
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = ((chunk: unknown) => { stdout?.push(String(chunk)); return true; }) as typeof process.stdout.write;
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

  it('a Node.js project contributes under a name in npm form, scoped or not', () => {
    for (const name of ['@scope/revfix', 'rev-fix.js_2', '0x', 'a'.repeat(214)]) {
      expect(contributionPackage({ type: 'node', name }), name).toEqual({ name, type: 'npm' });
    }
  });

  // Regression (#420): both names have the npm form but npm refuses them as
  // package names, so no npm package can carry them.
  it('a name npm reserves contributes nothing', () => {
    for (const name of ['node_modules', 'favicon.ico']) {
      expect(contributionPackage({ type: 'node', name }), name).toBeNull();
    }
  });

  it('a reserved name under a scope is an npm name and contributes', () => {
    expect(contributionPackage({ type: 'node', name: '@scope/node_modules' }))
      .toEqual({ name: '@scope/node_modules', type: 'npm' });
  });

  it('a named Python project contributes nothing', () => {
    expect(contributionPackage({ type: 'python', name: 'revfix' })).toBeNull();
  });

  it('a project with no name contributes nothing, whatever its type', () => {
    expect(contributionPackage({ type: 'node', name: null })).toBeNull();
    expect(contributionPackage({ type: 'python', name: null })).toBeNull();
    expect(contributionPackage({ type: 'generic', name: null })).toBeNull();
  });

  it('a project that is not Node.js contributes nothing', () => {
    for (const type of ['go', 'python', 'rust', 'java', 'ruby', 'docker', 'generic'] as const) {
      expect(contributionPackage({ type, name: 'revfix' }), type).toBeNull();
    }
  });

  it('a package.json name that is not in npm form contributes nothing', () => {
    const notInNpmForm: unknown[] = [
      // blank, or padded with white space
      '', '  ', ' revfix', 'revfix ', 'revfix\n',
      // a capital letter, or a first character that is not a letter or digit
      'Revfix', '@Scope/revfix', '.revfix', '_revfix', '-revfix', '@scope/_revfix', '@.scope/revfix',
      // a character outside lowercase letters, digits, "-", "." and "_"
      'rev fix', 'rev~fix', `r${String.fromCharCode(0xe9)}vfix`, 'revfix@1.0.0',
      // a slash that does not follow a scope, or a scope with a missing part
      'rev/fix', '@scope', '@scope/', '@/revfix', '@scope/rev/fix',
      // over 214 characters
      'a'.repeat(215),
      // not a string: package.json is JSON, so `name` can hold any value
      123, true, { a: 1 }, ['revfix'],
    ];
    for (const name of notInNpmForm) {
      expect(contributionPackage({ type: 'node', name }), JSON.stringify(name)).toBeNull();
    }
  });
});

// Detection reads package.json first and lets each later language manifest
// replace the type, while the package.json name stays unless that manifest
// names the tree itself. So a named package.json beside one of these is not a
// Node.js project, and contributes nothing.
describe('contributionPackage on a detected tree', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-contrib-detect-'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'revfix-front', version: '1.0.0' }));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('a named package.json on its own, or beside a Dockerfile, contributes as npm', () => {
    expect(contributionPackage(detectProject(dir))).toEqual({ name: 'revfix-front', type: 'npm' });
    fs.writeFileSync(path.join(dir, 'Dockerfile'), 'FROM scratch\n');
    expect(contributionPackage(detectProject(dir))).toEqual({ name: 'revfix-front', type: 'npm' });
  });

  it.each([
    'go.mod',
    'pyproject.toml',
    'setup.py',
    'requirements.txt',
    'Cargo.toml',
    'pom.xml',
    'build.gradle',
    'build.gradle.kts',
    'Gemfile',
  ])('a named package.json beside %s contributes nothing', (manifest) => {
    fs.writeFileSync(path.join(dir, manifest), '');
    expect(detectProject(dir).type).not.toBe('node');
    expect(contributionPackage(detectProject(dir))).toBeNull();
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
    // The advisory check reads the Registry; this file tests contribution only.
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('offline'); }));
  });

  // Each negative case checks that review reached the contribution step and
  // chose to send nothing; a run that never got there would pass for the
  // wrong reason.
  function expectNothingSent(): void {
    expect(submission.isContributeEnabled).toHaveBeenCalledTimes(1);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
  }

  afterEach(() => {
    vi.unstubAllGlobals();
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

  // Regression: the report named scanner version 0.6.3, the CLI's version
  // when the value was written, whatever version of the CLI ran the review;
  // the Registry publishes it as the scan's tool version.
  it('the scan is sent with the version of the CLI that ran it', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'revfix', version: '1.0.0' }));
    const cliVersion = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')).version;

    await runReview(tempDir);

    expect(submission.submitScanReport).toHaveBeenCalledTimes(1);
    const [, report] = submission.submitScanReport.mock.calls[0] as unknown as [string, Record<string, unknown>];
    expect(report.scannerVersion).toBe(cliVersion);
  });

  // Regression (#464): a matched advisory was added to the severity counts
  // sent with the report, as a finding of the reviewed package, while the
  // findings sent beside them left it out. The advisory concerns a
  // dependency: the terminal counts it, the counts sent do not.
  it('a matched advisory is counted in the terminal summary, not in the counts sent to the Registry', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({
      name: 'revfix', version: '1.0.0', dependencies: { 'vulnerable-package': '1.0.0' },
    }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');
    fs.mkdirSync(path.join(tempDir, '.git'));
    const advisory = {
      id: 'OA2A-2026-0001',
      summary: 'Advisory in vulnerable-package',
      severity: [{ type: 'ADVISORY', score: 'HIGH' }],
      affected: [{ package: { name: 'vulnerable-package', ecosystem: 'npm' } }],
      published: '2026-10-01T00:00:00Z',
    };
    const answering = (advisories: object[]) =>
      vi.fn(async () => ({ ok: true, json: async () => ({ advisories, total: advisories.length, format: 'osv' }) }));
    const reportPath = path.join(tempDir, 'review.html');

    // The same review without the advisory, with the report it wrote and
    // the list it cached removed, so the second run reads the same tree.
    vi.stubGlobal('fetch', answering([]));
    await runReview(tempDir);
    fs.rmSync(reportPath);
    fs.rmSync(path.join(tempHome, '.opena2a', 'cache'), { recursive: true, force: true });

    vi.stubGlobal('fetch', answering([advisory]));
    const stdout: string[] = [];
    await runReview(tempDir, stdout);

    expect(stdout.join('')).toContain('1 findings (0 critical, 1 high, 0 medium)');
    const html = fs.readFileSync(reportPath, 'utf-8');
    const data = JSON.parse((html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/)?.[1] ?? '{}').replace(/<\\\//g, '</'));
    expect(data.initData.advisoryCount).toBe(1);
    expect(submission.submitScanReport).toHaveBeenCalledTimes(2);
    const [[, without], [, withAdvisory]] = submission.submitScanReport.mock.calls as unknown as [string, Record<string, unknown>][];
    const counts = (r: Record<string, unknown>) => [r.criticalCount, r.highCount, r.mediumCount, r.lowCount];
    expect(counts(withAdvisory)).toEqual(counts(without));
    expect(withAdvisory.findings).toEqual(without.findings);
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

  it('a Python project is not sent, though pyproject.toml names it', async () => {
    fs.writeFileSync(path.join(tempDir, 'pyproject.toml'), '[project]\nname = "revfixpy"\nversion = "1.0.0"\n');
    fs.mkdirSync(path.join(tempDir, '.git'));

    await runReview(tempDir);

    expectNothingSent();
  });

  it('a pyproject.toml that names only a package index is not sent under the index name', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'pyproject.toml'),
      '[tool.uv.workspace]\nmembers = ["packages/*"]\n\n[[tool.uv.index]]\nname = "pytorch"\nexplicit = true\n',
    );
    fs.mkdirSync(path.join(tempDir, '.git'));

    await runReview(tempDir);

    expectNothingSent();
  });

  it('a named package.json beside a Python marker is not sent under its npm name', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'revfix-front', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, 'requirements.txt'), 'requests\n');
    fs.mkdirSync(path.join(tempDir, '.git'));

    await runReview(tempDir);

    expectNothingSent();
  });

  it('a package.json named with a name npm reserves is not sent', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'node_modules', version: '1.0.0' }));
    fs.mkdirSync(path.join(tempDir, '.git'));

    await runReview(tempDir);

    expectNothingSent();
  });

  it('a package.json whose name is blank is not sent', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: '  ', version: '1.0.0' }));
    fs.mkdirSync(path.join(tempDir, '.git'));

    await runReview(tempDir);

    expectNothingSent();
  });
});

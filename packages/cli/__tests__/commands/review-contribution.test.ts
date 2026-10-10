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

  it('a Node.js project contributes under a name in npm form, scoped or not', () => {
    for (const name of ['@scope/revfix', 'rev-fix.js_2', '0x', 'a'.repeat(214)]) {
      expect(contributionPackage({ type: 'node', name }), name).toEqual({ name, type: 'npm' });
    }
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

  it('a package.json whose name is blank is not sent', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: '  ', version: '1.0.0' }));
    fs.mkdirSync(path.join(tempDir, '.git'));

    await runReview(tempDir);

    expectNothingSent();
  });
});

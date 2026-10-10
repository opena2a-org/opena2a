import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Hermetic homedir: review reads the Shield event log under ~/.opena2a.
const mockHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => mockHome.dir || actual.homedir() };
});

// What review hands the Registry's two endpoints: the contribute event and
// the publish request. Contribution is switched on and both clients are
// recording stubs, so nothing leaves the machine.
const sent = vi.hoisted(() => ({
  events: [] as Array<Record<string, unknown>>,
  publishes: [] as Array<Record<string, unknown>>,
}));
vi.mock('@opena2a/contribute', () => ({
  contribute: {
    scanResult: async (params: Record<string, unknown>) => { sent.events.push({ ...params }); },
  },
}));
vi.mock('@opena2a/registry-client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@opena2a/registry-client')>();
  class RecordingClient extends actual.RegistryClient {
    async publishScan(submission: Parameters<InstanceType<typeof actual.RegistryClient>['publishScan']>[0]) {
      sent.publishes.push({ ...submission });
      return { accepted: true };
    }
  }
  return { ...actual, RegistryClient: RecordingClient };
});
vi.mock('../../src/util/report-submission.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/report-submission.js')>();
  return {
    ...actual,
    recordScanAndMaybePrompt: async () => {},
    isContributeEnabled: async () => true,
    getRegistryUrl: async () => actual.CANONICAL_REGISTRY_URL,
  };
});

import { review, registryEcosystem } from '../../src/commands/review.js';
import { getVersion } from '../../src/util/version.js';

async function runReview(targetDir: string): Promise<number> {
  const origWrite = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    return await review({
      targetDir,
      reportPath: path.join(targetDir, 'report.html'),
      skipHma: true,
      ci: true,
      autoOpen: false,
    });
  } finally {
    process.stdout.write = origWrite;
    process.stderr.write = origErr;
  }
}

describe('review contributes a scan under a package name and an ecosystem the Registry accepts', () => {
  let tempDir: string;
  let tempHome: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-contribution-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-contribution-home-'));
    mockHome.dir = tempHome;
    sent.events.length = 0;
    sent.publishes.length = 0;
  });

  afterEach(() => {
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  it('sends a Node.js project as npm under its package.json name, with the running CLI version', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'contribution-node-fixture', version: '1.0.0' }));

    await runReview(tempDir);

    // It used to send the label review prints ("Node.js") as the ecosystem,
    // which the Registry does not accept, and "0.6.3" as the version.
    expect(getVersion()).not.toBe('0.6.3');
    expect(sent.publishes).toHaveLength(1);
    expect(sent.publishes[0]).toMatchObject({
      name: 'contribution-node-fixture',
      ecosystem: 'npm',
      tool: 'opena2a-review',
      toolVersion: getVersion(),
    });
    expect(sent.publishes[0].type).toBeUndefined();
    expect(sent.events).toHaveLength(1);
    expect(sent.events[0]).toMatchObject({
      packageName: 'contribution-node-fixture',
      ecosystem: 'npm',
      toolVersion: getVersion(),
    });
  });

  it('sends a Python project as pypi under its pyproject.toml name', async () => {
    fs.writeFileSync(path.join(tempDir, 'pyproject.toml'), '[project]\nname = "contribution-python-fixture"\nversion = "0.1.0"\n');

    await runReview(tempDir);

    expect(sent.publishes).toHaveLength(1);
    expect(sent.publishes[0]).toMatchObject({ name: 'contribution-python-fixture', ecosystem: 'pypi' });
    expect(sent.events).toHaveLength(1);
    expect(sent.events[0]).toMatchObject({ packageName: 'contribution-python-fixture', ecosystem: 'pypi' });
  });

  it('sends nothing for a project without a package name', async () => {
    // It used to send the literal name "unknown".
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ version: '1.0.0' }));

    await runReview(tempDir);

    expect(sent.publishes).toEqual([]);
    expect(sent.events).toEqual([]);
  });

  it('sends nothing for a project outside npm and PyPI', async () => {
    // The Registry files a scan without an ecosystem under npm.
    fs.writeFileSync(path.join(tempDir, 'go.mod'), 'module github.com/example/contribution-go-fixture\n\ngo 1.22\n');

    await runReview(tempDir);

    expect(sent.publishes).toEqual([]);
    expect(sent.events).toEqual([]);
  });

  it('sends a package.json name as npm when a requirements.txt makes the project type Python', async () => {
    // detectProject keeps the package.json name when a later Python marker
    // sets the type; the ecosystem follows the manifest the name came from.
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'contribution-mixed-fixture', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, 'requirements.txt'), 'requests==2.32.0\n');

    await runReview(tempDir);

    expect(sent.publishes).toHaveLength(1);
    expect(sent.publishes[0]).toMatchObject({ name: 'contribution-mixed-fixture', ecosystem: 'npm' });
    expect(sent.events).toHaveLength(1);
    expect(sent.events[0]).toMatchObject({ packageName: 'contribution-mixed-fixture', ecosystem: 'npm' });
    for (const body of [...sent.publishes, ...sent.events]) {
      expect(body.ecosystem).not.toBe('pypi');
    }
  });

  it('sends nothing for a go.mod name when a requirements.txt makes the project type Python', async () => {
    fs.writeFileSync(path.join(tempDir, 'go.mod'), 'module github.com/example/contribution-go-fixture\n\ngo 1.22\n');
    fs.writeFileSync(path.join(tempDir, 'requirements.txt'), 'requests==2.32.0\n');

    await runReview(tempDir);

    expect(sent.publishes).toEqual([]);
    expect(sent.events).toEqual([]);
  });

  it('maps a name to a Registry ecosystem by the manifest it was read from', () => {
    expect(registryEcosystem('package.json')).toBe('npm');
    expect(registryEcosystem('pyproject.toml')).toBe('pypi');
    expect(registryEcosystem('go.mod')).toBeNull();
    expect(registryEcosystem(null)).toBeNull();
  });
});

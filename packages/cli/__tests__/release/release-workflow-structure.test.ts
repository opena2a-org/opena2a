/**
 * Structural tests over .github/workflows/release.yml and ci.yml.
 *
 * The release path is workflow TEXT: nothing executes it before a tag is
 * pushed, and a tag push is the publish event — there is no second chance. So
 * the properties that make the split safe are asserted here, where every PR
 * runs them:
 *
 *  - the `review` job sits between `build` and `publish` and gates it, so no
 *    tarball is signed before scripts/release-artifact-review.mjs read it;
 *  - `id-token: write` (the OIDC publish identity) exists in exactly one job,
 *    and that job checks out nothing and installs nothing — the review job
 *    runs dependency-resolved code (hackmyagent) and must never hold it;
 *  - every job that installs (`npm ci`, or the release scanner's own install),
 *    in both files, first proves no tracked package-manager config file
 *    exists to redirect or poison the install;
 *  - the review job loads its credential scanner only from the pinned install
 *    outside the workspace, and ci.yml's `test` job runs the review in that
 *    same install shape on every pull request, before anything is built.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { load } from 'js-yaml';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

interface Step {
  name?: string;
  uses?: string;
  run?: string;
  if?: unknown;
  'continue-on-error'?: unknown;
  env?: Record<string, string>;
  with?: Record<string, unknown>;
}
interface Job {
  needs?: string | string[];
  permissions?: Record<string, string>;
  steps?: Step[];
}
interface Workflow {
  permissions?: Record<string, string>;
  jobs: Record<string, Job>;
}

const readWorkflow = (file: string): Workflow =>
  load(readFileSync(path.join(REPO_ROOT, '.github', 'workflows', file), 'utf8')) as Workflow;

const release = readWorkflow('release.yml');
const ci = readWorkflow('ci.yml');

const steps = (job: Job | undefined): Step[] => job?.steps ?? [];
const needsOf = (job: Job | undefined): string[] =>
  job?.needs == null ? [] : Array.isArray(job.needs) ? job.needs : [job.needs];
const runsNpmCi = (s: Step): boolean => /(^|\s)npm ci(\s|$)/m.test(s.run ?? '');

/** The pinned scanner's install, byte-for-byte as both release.yml's review job and ci.yml's test job run it. */
const SCANNER_INSTALL_CMD = 'node scripts/install-release-scanner.mjs "$RUNNER_TEMP/release-scanner"';
const installsScanner = (s: Step): boolean => (s.run ?? '').includes('scripts/install-release-scanner.mjs');
/** An install of any kind: `npm ci`, or the scanner install, which runs its own `npm ci`. */
const runsInstall = (s: Step): boolean => runsNpmCi(s) || installsScanner(s);
const INSTALL_SHAPE_TEST_CMD = 'node --test scripts/__tests__/release-review-install-shape.test.mjs';
const SCANNER_ROOT_EXPR = '${{ runner.temp }}/release-scanner';

/**
 * The exact guard command that every job running npm ci in release.yml and
 * ci.yml must carry before its install step. Asserted as a literal substring,
 * not a paraphrase: the test below pins the command text, and a "similar" grep
 * with a narrower class list would pass a looser test while guarding less.
 */
const GUARD_CMD = String.raw`git ls-files | grep -E '(^|/)(\.npmrc|\.yarnrc(\.yml)?|\.pnpmfile\.cjs|\.envrc)$'`;

describe('release.yml job graph', () => {
  it('review sits between build and publish in the needs chain', () => {
    const names = Object.keys(release.jobs);
    expect(names).toContain('build');
    expect(names).toContain('review');
    expect(names).toContain('publish');
    expect(needsOf(release.jobs.review)).toEqual(['build']);
    // review is what gates publish. build may also be listed — publish reads
    // `needs.build.outputs.manifest_sha256`, and GitHub only exposes outputs
    // of jobs named in `needs` — but review must be there for the gate to
    // exist at all.
    expect(needsOf(release.jobs.publish)).toContain('review');
    expect(needsOf(release.jobs['github-release'])).toEqual(['publish']);
  });

  it('top-level permissions stay empty and review holds contents: read only', () => {
    expect(release.permissions).toEqual({});
    expect(release.jobs.review.permissions).toEqual({ contents: 'read' });
    expect(release.jobs.build.permissions).toEqual({ contents: 'read', actions: 'read' });
  });

  it('no job other than publish carries id-token: write', () => {
    expect(release.jobs.publish.permissions).toEqual({ 'id-token': 'write' });
    for (const [name, job] of Object.entries(release.jobs)) {
      if (name === 'publish') continue;
      expect(job.permissions?.['id-token'], `job ${name} must not hold id-token`).toBeUndefined();
    }
    // ci.yml never publishes anything, so no job there may hold it either.
    for (const [name, job] of Object.entries(ci.jobs)) {
      expect(job.permissions?.['id-token'], `ci.yml job ${name} must not hold id-token`).toBeUndefined();
    }
  });

  it('publish still has no checkout', () => {
    for (const s of steps(release.jobs.publish)) {
      expect(s.uses ?? '', 'publish must not check out the repository').not.toMatch(/checkout/);
    }
  });

  it('review downloads npm-tarballs and verifies the manifest digest exactly as publish does', () => {
    const download = steps(release.jobs.review).find((s) => /download-artifact/.test(s.uses ?? ''));
    expect(download?.with?.name).toBe('npm-tarballs');

    const verifyOf = (job: Job) =>
      steps(job).find((s) => s.env?.EXPECT_MANIFEST_SHA === '${{ needs.build.outputs.manifest_sha256 }}');
    const reviewVerify = verifyOf(release.jobs.review);
    const publishVerify = verifyOf(release.jobs.publish);
    expect(reviewVerify, 'review must anchor the manifest to the build job output').toBeDefined();
    expect(publishVerify, 'publish must keep its transport check').toBeDefined();
    expect(reviewVerify?.run).toContain('sha256sum -c');
    // Byte-identical verification: review must vouch for the same bytes
    // publish signs, not a similar-looking subset of them.
    expect(reviewVerify?.run).toBe(publishVerify?.run);
  });

  it('the review step runs the script per manifest tarball with GH_TOKEN, after npm ci --ignore-scripts and the scanner install', () => {
    const reviewSteps = steps(release.jobs.review);
    const scriptIdx = reviewSteps.findIndex((s) =>
      (s.run ?? '').includes('scripts/release-artifact-review.mjs --tarball')
    );
    expect(scriptIdx, 'review must run scripts/release-artifact-review.mjs').toBeGreaterThanOrEqual(0);
    const scriptStep = reviewSteps[scriptIdx];

    // GH_TOKEN feeds the consumer-closure advisories API inside the script.
    expect(scriptStep.env?.GH_TOKEN).toBe('${{ github.token }}');

    // Every tarball in the manifest, failing on any non-zero exit.
    expect(scriptStep.run).toContain('pack-manifest.json');
    expect(scriptStep.run).toMatch(/set -euo pipefail/);
    expect(scriptStep.run).toMatch(/rc=1/);
    expect(scriptStep.run).toMatch(/exit "\$rc"/);

    // The script needs the workspace install (semver) first in the same job —
    // with --ignore-scripts, because this job runs before anything is signed
    // but still inside the release path — and then the pinned scanner,
    // installed outside the workspace and named by --scanner-root: loaded from
    // the unbuilt workspace tree the scanner stops before it scans anything.
    const installIdx = reviewSteps.findIndex((s) => (s.run ?? '').trim() === 'npm ci --ignore-scripts');
    expect(installIdx, 'review must npm ci --ignore-scripts').toBeGreaterThanOrEqual(0);
    expect(installIdx).toBeLessThan(scriptIdx);
    const scannerIdx = reviewSteps.findIndex(installsScanner);
    expect(scannerIdx, 'review must install the pinned credential scanner').toBeGreaterThanOrEqual(0);
    expect(reviewSteps[scannerIdx].run?.trim()).toBe(SCANNER_INSTALL_CMD);
    expect(installIdx, 'npm ci --ignore-scripts precedes the scanner install').toBeLessThan(scannerIdx);
    expect(scannerIdx, 'the scanner install precedes the review').toBeLessThan(scriptIdx);
    expect(scriptStep.run).toContain(
      'scripts/release-artifact-review.mjs --tarball "$RUNNER_TEMP/dist/$file" --scanner-root "$RUNNER_TEMP/release-scanner"'
    );
  });
});

describe('the release review runs in the release job\'s install shape on every pull request', () => {
  const reviewSteps = steps(release.jobs.review);
  const testSteps = steps(ci.jobs.test);
  const setupNode = (s: Step) => /^actions\/setup-node@/.test(s.uses ?? '');
  const runIs = (cmd: string) => (s: Step) => (s.run ?? '').trim() === cmd;

  it('ci.yml test runs setup-node 24, npm ci --ignore-scripts, the scanner install and the install-shape test, all before npm run build', () => {
    const node24 = testSteps.findIndex((s) => setupNode(s) && String(s.with?.['node-version']) === '24');
    const install = testSteps.findIndex(runIs('npm ci --ignore-scripts'));
    const scanner = testSteps.findIndex(installsScanner);
    const shapeTest = testSteps.findIndex(runIs(INSTALL_SHAPE_TEST_CMD));
    const build = testSteps.findIndex(runIs('npm run build'));
    for (const [label, idx] of Object.entries({ node24, install, scanner, shapeTest, build })) {
      expect(idx, `ci.yml test has no ${label} step`).toBeGreaterThanOrEqual(0);
    }
    expect(node24).toBeLessThan(install);
    expect(install).toBeLessThan(scanner);
    expect(scanner).toBeLessThan(shapeTest);
    expect(shapeTest).toBeLessThan(build);
    // Nothing between the first checkout and the install-shape test builds the workspace.
    expect(testSteps.slice(0, shapeTest).some(runIs('npm run build'))).toBe(false);
    expect(testSteps[shapeTest].env?.RELEASE_SCANNER_ROOT).toBe(SCANNER_ROOT_EXPR);
    const npmTest = testSteps.find(runIs('npm run test'));
    expect(npmTest?.env?.RELEASE_SCANNER_ROOT).toBe(SCANNER_ROOT_EXPR);
    expect(npmTest?.env?.GH_TOKEN).toBe('${{ secrets.GITHUB_TOKEN }}');
  });

  it('the scanner install command is identical in both jobs', () => {
    const inReview = reviewSteps.filter(installsScanner).map((s) => s.run?.trim());
    const inTest = testSteps.filter(installsScanner).map((s) => s.run?.trim());
    expect(inReview).toEqual([SCANNER_INSTALL_CMD]);
    expect(inTest).toEqual([SCANNER_INSTALL_CMD]);
  });

  it('none of those steps carries if: or continue-on-error', () => {
    const shaped = [
      ...reviewSteps.filter(
        (s) => runIs('npm ci --ignore-scripts')(s) || installsScanner(s) || (s.run ?? '').includes('scripts/release-artifact-review.mjs')
      ),
      ...testSteps.filter(
        (s) =>
          (setupNode(s) && String(s.with?.['node-version']) === '24') ||
          runIs('npm ci --ignore-scripts')(s) ||
          installsScanner(s) ||
          runIs(INSTALL_SHAPE_TEST_CMD)(s)
      ),
    ];
    expect(shaped).toHaveLength(7);
    for (const s of shaped) {
      const label = s.name ?? s.uses ?? s.run;
      expect(s.if, `${label} must not carry an if:`).toBeUndefined();
      expect(s['continue-on-error'], `${label} must not carry continue-on-error`).toBeUndefined();
    }
  });

  it('both places run node 24', () => {
    const reviewNode = reviewSteps.filter(setupNode).map((s) => String(s.with?.['node-version']));
    expect(reviewNode).toEqual(['24']);
    const firstTestNode = testSteps.find(setupNode);
    expect(String(firstTestNode?.with?.['node-version'])).toBe('24');
  });
});

describe('package-manager-config guard', () => {
  const files: Array<[string, Workflow]> = [
    ['release.yml', release],
    ['ci.yml', ci],
  ];

  it('every job that installs (npm ci or the scanner install) carries the guard before its first install step, unconditionally', () => {
    for (const [file, wf] of files) {
      for (const [jobName, job] of Object.entries(wf.jobs)) {
        const jobSteps = steps(job);
        const firstInstall = jobSteps.findIndex(runsInstall);
        if (firstInstall === -1) continue;

        const label = `${file} job ${jobName}`;
        const guardIdx = jobSteps.findIndex((s) => (s.run ?? '').includes(GUARD_CMD));
        expect(guardIdx, `${label}: no step carries the exact guard command`).toBeGreaterThanOrEqual(0);
        expect(guardIdx, `${label}: the guard must run BEFORE the first install`).toBeLessThan(firstInstall);

        const guard = jobSteps[guardIdx];
        // The guard fails the job when the grep prints anything: either an
        // explicit `exit 1`, or the negated form ci.yml carries since #312
        // (`! <grep>`), which fails the step only as its LAST command — bash
        // -e does not stop on a negated pipeline mid-script.
        const lines = (guard.run ?? '')
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l && !l.startsWith('#'));
        const failsOnMatch = /exit 1/.test(guard.run ?? '') || lines.at(-1) === `! ${GUARD_CMD}`;
        expect(failsOnMatch, `${label}: the guard must fail on a match\n${guard.run}`).toBe(true);
        // ...and nothing may make that failure skippable or advisory.
        expect(guard.if, `${label}: the guard must not carry an if:`).toBeUndefined();
        expect(
          guard['continue-on-error'],
          `${label}: the guard must not carry continue-on-error`
        ).toBeUndefined();
      }
    }
  });

  it('the guarded jobs are exactly the installing jobs in both files', () => {
    const installing = (wf: Workflow) =>
      Object.entries(wf.jobs)
        .filter(([, job]) => steps(job).some(runsInstall))
        .map(([name]) => name)
        .sort();
    // Pinned lists, so a NEW job that starts installing shows up here and has
    // to be added deliberately — with its guard — rather than slipping in.
    expect(installing(ci)).toEqual(['build', 'lint', 'test']);
    expect(installing(release)).toEqual(['build', 'review']);
  });

  it('the release build job keeps npm ci --ignore-scripts', () => {
    const hasBare = steps(release.jobs.build).some((s) => (s.run ?? '').trim() === 'npm ci --ignore-scripts');
    expect(hasBare, 'release.yml build must install with --ignore-scripts').toBe(true);
    // And nothing in release.yml may install WITHOUT --ignore-scripts: this
    // file runs on the publish path, where a dependency postinstall executes
    // unreviewed third-party code next to release artifacts.
    for (const [jobName, job] of Object.entries(release.jobs)) {
      for (const s of steps(job)) {
        if (!runsNpmCi(s)) continue;
        expect(s.run, `release.yml job ${jobName} must pass --ignore-scripts to npm ci`).toContain(
          'npm ci --ignore-scripts'
        );
      }
    }
    // The scanner install runs its own npm ci, and it too runs no dependency's
    // install script.
    const installer = readFileSync(path.join(REPO_ROOT, 'scripts', 'install-release-scanner.mjs'), 'utf8');
    expect(installer).toContain("spawnSync('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund']");
  });
});

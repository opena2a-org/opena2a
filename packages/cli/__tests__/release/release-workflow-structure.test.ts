/**
 * Structural tests over .github/workflows/release.yml and ci.yml (QGF OPA-04,
 * AC1 + AC4).
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
 *  - every job that runs `npm ci`, in both files, first proves no tracked
 *    package-manager config file exists to redirect or poison the install.
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

/**
 * The exact guard command from the OPA-04 contract (AC4). Asserted as a
 * literal substring, not a paraphrase: the criterion pins the command text,
 * and a "similar" grep with a narrower class list would pass a looser test
 * while guarding less.
 */
const GUARD_CMD = String.raw`git ls-files | grep -E '(^|/)(\.npmrc|\.yarnrc(\.yml)?|\.pnpmfile\.cjs|\.envrc)$'`;

describe('release.yml job graph (OPA-04.AC1)', () => {
  it('OPA-04.AC1 review sits between build and publish in the needs chain', () => {
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

  it('OPA-04.AC1 top-level permissions stay empty and review holds contents: read only', () => {
    expect(release.permissions).toEqual({});
    expect(release.jobs.review.permissions).toEqual({ contents: 'read' });
    expect(release.jobs.build.permissions).toEqual({ contents: 'read', actions: 'read' });
  });

  it('OPA-04.AC1 no job other than publish carries id-token: write', () => {
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

  it('OPA-04.AC1 publish still has no checkout', () => {
    for (const s of steps(release.jobs.publish)) {
      expect(s.uses ?? '', 'publish must not check out the repository').not.toMatch(/checkout/);
    }
  });

  it('OPA-04.AC1 review downloads npm-tarballs and verifies the manifest digest exactly as publish does', () => {
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

  it('OPA-04.AC1 the review step runs the script per manifest tarball with GH_TOKEN, after npm ci --ignore-scripts', () => {
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

    // The script resolves node_modules/.bin/hackmyagent, so the install must
    // come first in the same job — and with --ignore-scripts, because this
    // job runs before anything is signed but still inside the release path.
    const installIdx = reviewSteps.findIndex((s) => (s.run ?? '').trim() === 'npm ci --ignore-scripts');
    expect(installIdx, 'review must npm ci --ignore-scripts').toBeGreaterThanOrEqual(0);
    expect(installIdx).toBeLessThan(scriptIdx);
  });
});

describe('package-manager-config guard (OPA-04.AC4)', () => {
  const files: Array<[string, Workflow]> = [
    ['release.yml', release],
    ['ci.yml', ci],
  ];

  it('OPA-04.AC4 every job that runs npm ci carries the guard before its install step, unconditionally', () => {
    for (const [file, wf] of files) {
      for (const [jobName, job] of Object.entries(wf.jobs)) {
        const jobSteps = steps(job);
        const firstInstall = jobSteps.findIndex(runsNpmCi);
        if (firstInstall === -1) continue;

        const label = `${file} job ${jobName}`;
        const guardIdx = jobSteps.findIndex((s) => (s.run ?? '').includes(GUARD_CMD));
        expect(guardIdx, `${label}: no step carries the exact guard command`).toBeGreaterThanOrEqual(0);
        expect(guardIdx, `${label}: the guard must run BEFORE npm ci`).toBeLessThan(firstInstall);

        const guard = jobSteps[guardIdx];
        // The guard fails the job when the grep prints anything...
        expect(guard.run, `${label}: the guard must fail on a match`).toMatch(/exit 1/);
        // ...and nothing may make that failure skippable or advisory.
        expect(guard.if, `${label}: the guard must not carry an if:`).toBeUndefined();
        expect(
          guard['continue-on-error'],
          `${label}: the guard must not carry continue-on-error`
        ).toBeUndefined();
      }
    }
  });

  it('OPA-04.AC4 the guarded jobs are exactly the installing jobs in both files', () => {
    const installing = (wf: Workflow) =>
      Object.entries(wf.jobs)
        .filter(([, job]) => steps(job).some(runsNpmCi))
        .map(([name]) => name)
        .sort();
    // Pinned lists, so a NEW job that starts installing shows up here and has
    // to be added deliberately — with its guard — rather than slipping in.
    expect(installing(ci)).toEqual(['build', 'lint', 'test']);
    expect(installing(release)).toEqual(['build', 'review']);
  });

  it('OPA-04.AC4 the release build job keeps npm ci --ignore-scripts', () => {
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
  });
});

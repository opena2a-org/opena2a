import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

// A tracked .npmrc with a `node-options` line (or its yarn/pnpm/direnv
// equivalents) executes before the first instruction of anything started
// through `npx`, `npm exec` or `npm run` inside that tree. No in-process
// check can see it, so the only tree-state defense is refusing the files
// at install time, in every job that installs. This test pins that guard:
// it must exist in every job that runs `npm ci`, sit BEFORE the install,
// and be unconditional -- a guard that can be skipped or that only prints
// is not a guard.

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

const GUARD_GREP =
  "git ls-files | grep -E '(^|/)(\\.npmrc|\\.yarnrc(\\.yml)?|\\.pnpmfile\\.cjs|\\.envrc)$'";

// The two accepted failing forms. A step that runs the grep without
// negation "succeeds" precisely when a forbidden file is tracked.
const GUARD_FORMS = [`! ${GUARD_GREP}`, `test -z "$(${GUARD_GREP})"`];

const WORKFLOWS = ['.github/workflows/ci.yml', '.github/workflows/release.yml'];

// Jobs that must exist and must install; a rename or removal has to be a
// deliberate edit here, not a silent loss of coverage.
const EXPECTED_INSTALL_JOBS: Record<string, string[]> = {
  '.github/workflows/ci.yml': ['build', 'test', 'lint'],
  '.github/workflows/release.yml': ['build'],
};

interface Step {
  name?: string;
  run?: string;
  if?: unknown;
  'continue-on-error'?: unknown;
}

function loadJobs(file: string): Record<string, { steps: Step[] }> {
  const doc = yaml.load(fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8')) as {
    jobs: Record<string, { steps: Step[] }>;
  };
  return doc.jobs;
}

const runsNpmCi = (run: string) => /(^|[\s(&|;])npm ci($|[\s)&|;])/.test(run);

const isGuard = (run: string) => {
  const lines = run
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  return lines.some((l) => GUARD_FORMS.includes(l));
};

describe('tree-local package-manager config guard in workflows', () => {
  it('OPA-02.AC1 every npm-ci job guards against tracked package-manager config before installing', () => {
    const problems: string[] = [];

    for (const file of WORKFLOWS) {
      const jobs = loadJobs(file);

      for (const expected of EXPECTED_INSTALL_JOBS[file]) {
        const steps = jobs[expected]?.steps ?? [];
        if (!steps.some((s) => typeof s.run === 'string' && runsNpmCi(s.run))) {
          problems.push(`${file}: expected job "${expected}" with an npm ci step is missing`);
        }
      }

      for (const [jobName, job] of Object.entries(jobs)) {
        const steps = job.steps ?? [];
        const installIdx = steps.findIndex((s) => typeof s.run === 'string' && runsNpmCi(s.run));
        if (installIdx === -1) continue; // job installs nothing; nothing to guard

        const guardIdx = steps.findIndex((s) => typeof s.run === 'string' && isGuard(s.run));
        if (guardIdx === -1) {
          problems.push(`${file}: job "${jobName}" runs npm ci with no tree-local config guard`);
          continue;
        }
        if (guardIdx >= installIdx) {
          problems.push(
            `${file}: job "${jobName}" has the guard at step ${guardIdx}, after its install at step ${installIdx}`
          );
        }
        const guard = steps[guardIdx];
        if ('continue-on-error' in guard) {
          problems.push(`${file}: job "${jobName}" guard carries continue-on-error`);
        }
        if ('if' in guard) {
          problems.push(`${file}: job "${jobName}" guard carries an if: condition`);
        }
      }
    }

    expect(problems).toEqual([]);
  });
});

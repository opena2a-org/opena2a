/**
 * .github/workflows/recipe.yml runs the CLI's published CI recipe against
 * three agents, two of which must be refused. A gate that can be told to
 * pass is no gate, so this reads the workflow and fails on every way a step
 * could pass whatever the recipe returned: `continue-on-error`, `||` in any
 * form, `; true`, `set +e`, a pipe, a script without `shell: bash`, an `if:`
 * condition, and a test for "non-zero" where the refusal code is 1. Each of
 * those is then injected into every step in turn, and the check must name
 * the step it was put in; no step is excluded by name.
 *
 * It also holds the three fixture runs to one source for the command they
 * run (the scripts the extractor wrote from the guide, invoked by the same
 * line in every run, with only the scanned directory changed), each control
 * to the refusal code and the score that make it a control, and the job to
 * its triggers, permissions, timeout and name.
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { dump, load } from 'js-yaml';

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const WORKFLOW = path.join(REPO_ROOT, '.github', 'workflows', 'recipe.yml');
const EXTRACTOR = path.join(REPO_ROOT, 'scripts', 'ci', 'extract-recipe.mjs');
const GUIDE = path.join(REPO_ROOT, 'docs', 'use-cases', 'ci-cd.md');

const JOB_NAME = 'Published recipe (own build)';
const CONTROL_REVIEW = 'Recipe control (review below 50)';
const CONTROL_GOVERNANCE = 'Recipe control (governance below 60)';
const BENIGN = 'Recipe (benign fixture)';
const FIXTURE_STEPS = [CONTROL_REVIEW, CONTROL_GOVERNANCE, BENIGN];

type Mapping = Record<string, unknown>;

const isRecord = (v: unknown): v is Mapping => typeof v === 'object' && v !== null && !Array.isArray(v);

const stepLabel = (step: Mapping, index: number): string =>
  typeof step.name === 'string' ? step.name : typeof step.uses === 'string' ? step.uses : `step #${index + 1}`;

const lines = (run: string): string[] => run.split('\n').map((l) => l.trim());

/** Each run script line that invokes one of the extracted recipe steps. */
const recipeInvocations = (run: string): string[] => lines(run).filter((l) => l.includes('/recipe/step-'));

/**
 * The lines each fixture run must hold: the refusal code (1, never "non-zero")
 * or the pass (0) of each step it runs, and the score the recipe wrote. The
 * JSON comparisons are bounded on both sides, so a missing or non-numeric
 * field cannot satisfy them (in jq, null sorts below every number).
 */
const REQUIRED_LINES: Record<string, string[]> = {
  [CONTROL_REVIEW]: [
    'test "$step1" -eq 0',
    'test "$step2" -eq 1',
    `jq -e '.compositeScore >= 0 and .compositeScore < 50' "$subject/review-results.json"`,
    `jq -e '.summary.governanceScore >= 60 and .summary.governanceScore <= 100' "$subject/detect-results.json"`,
  ],
  [CONTROL_GOVERNANCE]: [
    'test "$step1" -eq 0',
    'test "$step2" -eq 0',
    'test "$step3" -eq 1',
    `jq -e '.summary.governanceScore >= 0 and .summary.governanceScore < 60' "$subject/detect-results.json"`,
    `jq -e '.compositeScore >= 50 and .compositeScore <= 100' "$subject/review-results.json"`,
    `witness=$(grep -E -x 'Governance score: [0-9]+ / 100' "$RUNNER_TEMP/step-3.out")`,
    'test "$score" -eq "$governance"',
    'test "$score" -lt 60',
  ],
  [BENIGN]: [
    'test "$step1" -eq 0',
    'test "$step2" -eq 0',
    'test "$step3" -eq 0',
    `jq -e '.summary.governanceScore >= 60 and .summary.governanceScore <= 100' "$subject/detect-results.json"`,
    `jq -e '.compositeScore >= 50 and .compositeScore <= 100' "$subject/review-results.json"`,
    `witness=$(grep -E -x 'Governance score: [0-9]+ / 100' "$RUNNER_TEMP/step-3.out")`,
    'test "$score" -eq "$governance"',
    'test "$score" -ge 60',
  ],
};

/** Shell text that lets a failing command pass, or that cannot tell a refusal from a crash. */
const MASKS: { what: string; pattern: RegExp }[] = [
  { what: '`||`', pattern: /\|\|/ },
  { what: 'a pipe', pattern: /\|/ },
  { what: '`; true` or `; :`', pattern: /;\s*(?:true|:)(?=\s|;|$)/m },
  { what: '`set +` (errexit or pipefail turned off)', pattern: /(?:^|[\s;&(])set\s+\+/m },
  { what: 'a test for non-zero', pattern: /-ne\s+0\b/ },
];

/** Every way this workflow fails its contract, one line each; empty when it holds. */
function problems(text: string): string[] {
  const found: string[] = [];
  let doc: unknown;
  try {
    doc = load(text);
  } catch (err) {
    return [`does not parse: ${(err as Error).message}`];
  }
  if (!isRecord(doc)) return ['is not a mapping'];

  if (text.includes('${{ secrets.')) found.push('reads a secret');

  // Triggers: pull requests and pushes to main, nothing filtered by path.
  const on = isRecord(doc.on) ? doc.on : {};
  for (const trigger of ['pull_request', 'push']) {
    if (!(trigger in on)) found.push(`does not run on ${trigger}`);
  }
  const push = isRecord(on.push) ? on.push : {};
  if (JSON.stringify(push.branches) !== JSON.stringify(['main'])) found.push('push is not limited to main');
  for (const [trigger, filters] of Object.entries(on)) {
    if (!isRecord(filters)) continue;
    for (const key of ['paths', 'paths-ignore', 'branches-ignore', 'tags', 'tags-ignore']) {
      if (key in filters) found.push(`${trigger} is filtered by ${key}`);
    }
  }
  for (const trigger of ['pull_request_target', 'workflow_run']) {
    if (trigger in on) found.push(`runs on ${trigger}`);
  }

  if (JSON.stringify(doc.permissions) !== JSON.stringify({ contents: 'read' })) {
    found.push('permissions are not exactly contents: read');
  }

  const jobs = isRecord(doc.jobs) ? Object.entries(doc.jobs) : [];
  if (jobs.length !== 1) found.push(`has ${jobs.length} jobs, not one`);
  for (const [id, raw] of jobs) {
    const job = isRecord(raw) ? raw : {};
    if (job.name !== JOB_NAME) found.push(`job ${id} is not named "${JOB_NAME}"`);
    if (job['timeout-minutes'] !== 10) found.push(`job ${id} has no timeout-minutes: 10`);
    if ('if' in job) found.push(`job ${id} has an if: condition`);
    if ('continue-on-error' in job) found.push(`job ${id} has continue-on-error`);
    if ('permissions' in job) found.push(`job ${id} sets its own permissions`);
    if ('defaults' in job || 'defaults' in doc) found.push('sets defaults for run steps');
    const env = { ...(isRecord(doc.env) ? doc.env : {}), ...(isRecord(job.env) ? job.env : {}) };
    if (env.OPENA2A_TELEMETRY !== 'off') found.push('does not set OPENA2A_TELEMETRY=off');

    const steps = Array.isArray(job.steps) ? job.steps.filter(isRecord) : [];
    steps.forEach((step, i) => {
      const label = stepLabel(step, i);
      if ('if' in step) found.push(`${label}: has an if: condition`);
      if ('continue-on-error' in step) found.push(`${label}: has continue-on-error`);
      if (typeof step.run !== 'string') return;
      if (step.shell !== 'bash') found.push(`${label}: runs without shell: bash`);
      for (const { what, pattern } of MASKS) {
        if (pattern.test(step.run)) found.push(`${label}: holds ${what}`);
      }
      for (const forbidden of ['opena2a-cli', 'dist/index.js', 'npx ']) {
        if (step.run.includes(forbidden)) found.push(`${label}: names the CLI itself ("${forbidden}")`);
      }
    });

    const checkout = steps.find((s) => typeof s.uses === 'string' && s.uses.startsWith('actions/checkout@'));
    if (!checkout || !isRecord(checkout.with) || checkout.with['persist-credentials'] !== false) {
      found.push('checkout keeps the token (persist-credentials is not false)');
    }

    // The build is linked into runner.temp in one step; no other names it.
    const linkers = steps.filter((s) => typeof s.run === 'string' && s.run.includes('packages/cli'));
    if (linkers.length !== 1) found.push(`${linkers.length} steps name packages/cli, not one`);

    // The three fixture runs: found by what they run, in their order.
    const runs = steps.filter((s) => typeof s.run === 'string' && recipeInvocations(s.run).length > 0);
    const names = runs.map((s, i) => stepLabel(s, i));
    if (JSON.stringify(names) !== JSON.stringify(FIXTURE_STEPS)) {
      found.push(`fixture runs are ${JSON.stringify(names)}, not ${JSON.stringify(FIXTURE_STEPS)}`);
    }
    const byStep = new Map<string, Set<string>>();
    for (const [i, run] of runs.entries()) {
      const label = stepLabel(run, i);
      const script = lines(run.run as string);
      const subjects = script.filter((l) => /^subject="\$GITHUB_WORKSPACE\/test\/fixtures\/recipe\/[a-z0-9-]+"$/.test(l));
      if (subjects.length !== 1 || script[0] !== subjects[0]) {
        found.push(`${label}: does not open with one subject line under test/fixtures/recipe/`);
      }
      for (const line of recipeInvocations(run.run as string)) {
        const which = /\/recipe\/(step-\d)\.sh/.exec(line)?.[1] ?? line;
        if (!byStep.has(which)) byStep.set(which, new Set());
        byStep.get(which)?.add(line);
      }
      const order = ['cd "$RUNNER_TEMP"', 'step-1.sh', 'step-2.sh'].map((needle) =>
        script.findIndex((l) => l === needle || l.includes(`/recipe/${needle}`)),
      );
      if (order.some((at) => at < 0) || !(order[0] < order[1] && order[1] < order[2])) {
        found.push(`${label}: does not start steps 1 and 2 from runner.temp`);
      }
      const step3 = script.findIndex((l) => l.includes('/recipe/step-3.sh'));
      if (step3 >= 0 && script.lastIndexOf('cd "$subject"', step3) < order[2]) {
        found.push(`${label}: does not start step 3 from the scanned directory`);
      }
      if (label === CONTROL_REVIEW && step3 >= 0) {
        found.push(`${label}: runs step 3 after step 2 is refused; the guide's job ends there`);
      }
      if (label !== CONTROL_REVIEW && step3 < 0) found.push(`${label}: does not run step 3`);
      for (const required of REQUIRED_LINES[label] ?? []) {
        if (!script.includes(required)) found.push(`${label}: lacks the line ${required}`);
      }
    }
    for (const [which, variants] of byStep) {
      if (variants.size !== 1) found.push(`${which} is invoked by ${variants.size} different lines, not one`);
    }
  }
  return found;
}

const workflowText = (): string => fs.readFileSync(WORKFLOW, 'utf-8');

describe('.github/workflows/recipe.yml', () => {
  it('holds the contract: no step can pass a refused run', () => {
    expect(problems(workflowText())).toEqual([]);
  });

  it('starts the job with the checkout and Node.js setup the guide uses', async () => {
    const { extractQuickStart } = (await import(/* @vite-ignore */ pathToFileURL(EXTRACTOR).href)) as {
      extractQuickStart(markdown: string): { setup: { uses: string; with: Record<string, string> }[] };
    };
    const { setup } = extractQuickStart(fs.readFileSync(GUIDE, 'utf-8'));
    const doc = load(workflowText()) as { jobs: Record<string, { steps: Mapping[] }> };
    const steps = Object.values(doc.jobs)[0].steps;
    const uses = steps.filter((s) => typeof s.uses === 'string');
    expect(uses.map((s) => s.uses)).toEqual(setup.map((s) => s.uses));
    const node = (list: { with?: unknown }[]) =>
      list.map((s) => (isRecord(s.with) && 'node-version' in s.with ? String(s.with['node-version']) : null));
    expect(node(uses)).toEqual(node(setup));
  });
});

/** Text appended to the first line of a script, where it binds to that command. */
const onFirstLine = (run: string, tail: string): string => {
  const [first, ...rest] = run.split('\n');
  return [`${first}${tail}`, ...rest].join('\n');
};

const MUTANTS: { name: string; apply(step: Mapping): Mapping | null }[] = [
  { name: 'continue-on-error', apply: (s) => ({ ...s, 'continue-on-error': true }) },
  { name: 'an if: condition', apply: (s) => ({ ...s, if: 'always()' }) },
  { name: '|| true', apply: (s) => (typeof s.run === 'string' ? { ...s, run: onFirstLine(s.run, ' || true') } : null) },
  { name: '|| echo', apply: (s) => (typeof s.run === 'string' ? { ...s, run: onFirstLine(s.run, ' || echo skipped') } : null) },
  { name: '|| :', apply: (s) => (typeof s.run === 'string' ? { ...s, run: onFirstLine(s.run, ' || :') } : null) },
  { name: '; true', apply: (s) => (typeof s.run === 'string' ? { ...s, run: onFirstLine(s.run, '; true') } : null) },
  { name: 'set +e', apply: (s) => (typeof s.run === 'string' ? { ...s, run: `set +e\n${s.run}` } : null) },
  {
    name: 'a pipe under the default shell',
    apply: (s) => {
      if (typeof s.run !== 'string') return null;
      const { shell: _shell, ...rest } = s;
      return { ...rest, run: onFirstLine(s.run, ' | cat') };
    },
  },
  {
    name: 'a shell that does not stop on errors',
    apply: (s) => (typeof s.run === 'string' ? { ...s, shell: 'bash {0}' } : null),
  },
];

type WorkflowDoc = Mapping & { on: Mapping; jobs: Record<string, { steps: Mapping[] } & Mapping> };

describe('the check names every masked step, with no step excluded by name', () => {
  const base = load(workflowText()) as WorkflowDoc;
  const [jobId] = Object.keys(base.jobs);
  const steps = base.jobs[jobId].steps;

  it('reads every step of the job (calibration: the job has the steps the cases below mutate)', () => {
    expect(steps.length).toBeGreaterThanOrEqual(8);
    expect(steps.filter((s) => typeof s.run === 'string').length).toBeGreaterThanOrEqual(6);
  });

  for (const mutant of MUTANTS) {
    it(`${mutant.name}, in each step in turn`, () => {
      let applied = 0;
      steps.forEach((step, i) => {
        const mutated = mutant.apply(step);
        if (mutated === null) return;
        applied++;
        const doc = structuredClone(base);
        doc.jobs[jobId].steps[i] = mutated;
        const label = stepLabel(step, i);
        const report = problems(dump(doc, { lineWidth: -1 }));
        expect(
          report.some((p) => p.startsWith(`${label}:`)),
          `${mutant.name} in "${label}" was not reported: ${JSON.stringify(report)}`,
        ).toBe(true);
      });
      expect(applied).toBeGreaterThan(0);
    });
  }

  it('continue-on-error or an if: condition on the job', () => {
    for (const [key, value] of [
      ['continue-on-error', true],
      ['if', 'always()'],
    ] as const) {
      const doc = structuredClone(base);
      doc.jobs[jobId] = { ...doc.jobs[jobId], [key]: value };
      expect(problems(dump(doc, { lineWidth: -1 })).some((p) => p.startsWith(`job ${jobId}`)), key).toBe(true);
    }
  });

  it('a control whose refusal is tested as "non-zero" instead of 1', () => {
    const doc = structuredClone(base);
    const i = steps.findIndex((s) => s.name === CONTROL_REVIEW);
    const run = steps[i].run as string;
    doc.jobs[jobId].steps[i] = { ...steps[i], run: run.replace('test "$step2" -eq 1', 'test "$step2" -ne 0') };
    const report = problems(dump(doc, { lineWidth: -1 }));
    expect(report).toContain(`${CONTROL_REVIEW}: holds a test for non-zero`);
    expect(report).toContain(`${CONTROL_REVIEW}: lacks the line test "$step2" -eq 1`);
  });

  it('a fixture run whose invocation differs from the others (one argv source)', () => {
    const doc = structuredClone(base);
    const i = steps.findIndex((s) => s.name === BENIGN);
    const run = steps[i].run as string;
    const edited = run.replace(/(\/recipe\/step-2\.sh")/, '$1 --verbose');
    expect(edited).not.toBe(run);
    doc.jobs[jobId].steps[i] = { ...steps[i], run: edited };
    expect(problems(dump(doc, { lineWidth: -1 }))).toContain('step-2 is invoked by 2 different lines, not one');
  });

  it('a fixture run that names the CLI instead of the extracted recipe', () => {
    const doc = structuredClone(base);
    const i = steps.findIndex((s) => s.name === CONTROL_GOVERNANCE);
    const run = steps[i].run as string;
    doc.jobs[jobId].steps[i] = { ...steps[i], run: `${run}\nnode packages/cli/dist/index.js --version\n` };
    const report = problems(dump(doc, { lineWidth: -1 }));
    expect(report).toContain(`${CONTROL_GOVERNANCE}: names the CLI itself ("dist/index.js")`);
  });

  it('a paths filter, a missing trigger, or wider permissions', () => {
    const filtered = structuredClone(base);
    filtered.on = { ...filtered.on, pull_request: { branches: ['main'], paths: ['packages/**'] } };
    expect(problems(dump(filtered, { lineWidth: -1 }))).toContain('pull_request is filtered by paths');

    const noPush = structuredClone(base);
    const { push: _push, ...rest } = noPush.on;
    noPush.on = rest;
    expect(problems(dump(noPush, { lineWidth: -1 }))).toContain('does not run on push');

    const wide = structuredClone(base);
    wide.permissions = { contents: 'write' };
    expect(problems(dump(wide, { lineWidth: -1 }))).toContain('permissions are not exactly contents: read');
  });
});

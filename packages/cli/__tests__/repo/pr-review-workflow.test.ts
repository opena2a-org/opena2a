import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'node:child_process';
import * as yaml from 'js-yaml';

// Pins the shape of the required `review` check (.github/workflows/pr-review.yml)
// to the review-gate decision of 2026-09-23 (unit 9908): the verdict is computed by
// .github/scripts/pr-review.mjs, a review event can only substitute through the
// recorded human path and never calls the model, the job cannot be skipped
// into a green check, and nothing widens what the job can reach. A change to
// any of this has to be a deliberate edit here.

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const WORKFLOW = path.join(REPO_ROOT, '.github', 'workflows', 'pr-review.yml');
const RAW = fs.readFileSync(WORKFLOW, 'utf-8');

interface Step {
  name?: string;
  id?: string;
  uses?: string;
  run?: string;
  if?: string;
  env?: Record<string, string>;
  with?: Record<string, unknown>;
  'continue-on-error'?: unknown;
}
interface Job {
  if?: unknown;
  permissions?: unknown;
  env: Record<string, string>;
  steps: Step[];
}
interface Workflow {
  on: Record<string, { types?: string[]; branches?: string[] }>;
  permissions: Record<string, string>;
  concurrency: { group: string; 'cancel-in-progress': boolean };
  jobs: Record<string, Job>;
}

const doc = yaml.load(RAW) as Workflow;
const job = doc.jobs.review;
const step = (name: string) => {
  const s = job.steps.find((x) => x.name === name);
  if (!s) throw new Error(`no step named ${name}`);
  return s;
};

describe('pr-review workflow shape', () => {
  it('9908.AC5 triggers: pull_request into main and pull_request_review, nothing that runs base-branch code or on demand', () => {
    expect(Object.keys(doc.on).sort()).toEqual(['pull_request', 'pull_request_review']);
    expect(doc.on.pull_request).toEqual({ types: ['opened', 'synchronize', 'reopened'], branches: ['main'] });
    expect(doc.on.pull_request_review).toEqual({ types: ['submitted', 'edited', 'dismissed'] });
    for (const banned of ['pull_request_target', 'workflow_dispatch', 'repository_dispatch', 'workflow_run', 'issue_comment']) {
      expect(RAW).not.toContain(banned + ':');
    }
  });

  it('9908.AC5 permissions are exactly pull-requests: write, contents: read and actions: read, with no job-level widening', () => {
    expect(doc.permissions).toEqual({ 'pull-requests': 'write', contents: 'read', actions: 'read' });
    expect(job.permissions).toBeUndefined();
  });

  it('9908.AC5 the only secrets referenced are ANTHROPIC_API_KEY (model round only) and GITHUB_TOKEN', () => {
    const refs = new Set([...RAW.matchAll(/secrets\.([A-Za-z0-9_]+)/g)].map((m) => m[1]));
    expect([...refs].sort()).toEqual(['ANTHROPIC_API_KEY', 'GITHUB_TOKEN']);
    const withKey = job.steps.filter((s) => JSON.stringify(s).includes('ANTHROPIC_API_KEY'));
    expect(withKey.map((s) => s.name)).toEqual(['Model round']);
    expect(withKey[0].if).toBe("github.event_name == 'pull_request'");
  });

  it('9908.AC5 one job named review, never skipped: no job-level if, the enforce step always runs and cannot be softened', () => {
    expect(Object.keys(doc.jobs)).toEqual(['review']);
    expect(job.if).toBeUndefined();
    const enforce = step('Enforce verdict');
    expect(job.steps[job.steps.length - 1]).toBe(enforce);
    expect(enforce.if).toBeUndefined();
    expect(enforce['continue-on-error']).toBeUndefined();
    expect(enforce.env).toEqual({ VERDICT: '${{ steps.model.outputs.verdict || steps.human.outputs.verdict }}' });
    // Posting is the only step allowed to fail without failing the job.
    const soft = job.steps.filter((s) => s['continue-on-error'] !== undefined).map((s) => s.name);
    expect(soft).toEqual(['Post review']);
  });

  it.each([
    ['APPROVE', 0],
    ['REQUEST_CHANGES', 1],
    ['INCONCLUSIVE', 1],
    ['', 1],
    ['approve', 1],
  ])('9908.AC5 the enforce step exits %s -> %i', (verdict, code) => {
    const run = step('Enforce verdict').run as string;
    let status = 0;
    try {
      execFileSync('bash', ['-c', run], { env: { PATH: process.env.PATH, VERDICT: verdict }, stdio: 'pipe' });
    } catch (e) {
      status = (e as { status: number }).status;
    }
    expect(status).toBe(code);
  });

  it('9908.AC5 the model round runs only on pull_request and the human round only on pull_request_review, both through the script', () => {
    expect(step('Get PR diff').if).toBe("github.event_name == 'pull_request'");
    expect(step('Model round')).toMatchObject({
      id: 'model',
      if: "github.event_name == 'pull_request'",
      run: 'node .github/scripts/pr-review.mjs model-round',
    });
    expect(step('Human round')).toMatchObject({
      id: 'human',
      if: "github.event_name == 'pull_request_review'",
      run: 'node .github/scripts/pr-review.mjs human-round',
    });
    // The human round must not be able to reach the model.
    expect(JSON.stringify(step('Human round'))).not.toContain('ANTHROPIC');
  });

  it('9908.AC5 the reviewed diff is fetched for the event head sha, never for "the pull request"', () => {
    const run = step('Get PR diff').run as string;
    expect(run).toContain('compare/$BASE_SHA...$HEAD_SHA');
    expect(run).not.toContain('gh pr diff');
    expect(job.env.BASE_SHA).toBe('${{ github.event.pull_request.base.sha }}');
    expect(step('Model round').env).toMatchObject({
      FETCHED: '${{ steps.diff.outputs.fetched }}',
      FILE_COUNT: '${{ steps.diff.outputs.file_count }}',
      RUN_ATTEMPT: '${{ github.run_attempt }}',
      EVENT_ACTION: '${{ github.event.action }}',
      PR_AUTHOR: '${{ github.event.pull_request.user.login }}',
    });
  });

  it('9908.AC5 the job has a timeout', () => {
    expect((job as unknown as { 'timeout-minutes': number })['timeout-minutes']).toBe(15);
  });

  it('9908.AC5 no step interpolates an expression into a shell script', () => {
    for (const s of job.steps) {
      if (s.run) expect(s.run, s.name).not.toContain('${{');
    }
  });

  it('9908.AC5 the checkout is the default merge ref with no persisted token', () => {
    const co = job.steps.filter((s) => s.uses?.startsWith('actions/checkout@'));
    expect(co).toHaveLength(1);
    expect(co[0].with).toEqual({ 'persist-credentials': false });
  });

  it('9908.AC5 a review event cannot cancel a model round: the concurrency group is per event', () => {
    expect(doc.concurrency.group).toBe('pr-review-${{ github.event.pull_request.number }}-${{ github.event_name }}');
  });

  it('9908.AC4 the approver set equals the gate-file approval set', () => {
    const gate = fs.readFileSync(path.join(REPO_ROOT, '.github', 'workflows', 'gate-file-approval.yml'), 'utf-8');
    const m = /approvers="([^"]+)"/.exec(gate);
    expect(m).not.toBeNull();
    expect(job.env.APPROVERS).toBe(m![1]);
  });

  it('9908.AC5 the script lives under .github, so changing it needs gate-file approval like the workflow', () => {
    expect(fs.existsSync(path.join(REPO_ROOT, '.github', 'scripts', 'pr-review.mjs'))).toBe(true);
    expect(RAW).not.toMatch(/node (?!\.github\/scripts\/pr-review\.mjs)/);
  });
});

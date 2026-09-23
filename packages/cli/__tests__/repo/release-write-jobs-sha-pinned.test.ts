import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

// Any action in a job can request that job's token, the OIDC token included.
// A `uses:` pinned by tag runs whatever the tag points at on the day of the
// run, so in a job that holds a write scope or `id-token` a moved tag is a
// write (or a publish) by code nobody reviewed. A full 40-hex commit sha
// cannot move. This cell holds every such job to sha pins.
//
// "Holds a write scope" is read from the job's `permissions:`, falling back
// to the workflow's. A job with neither holds the repository default token,
// which is `read` on this repository (`gh api
// repos/opena2a-org/opena2a/actions/permissions/workflow` returned
// `default_workflow_permissions: read` on 2026-09-23). A test cannot read that
// setting; if it is ever changed to `write`, every job without a
// `permissions:` key is write-scoped and this cell under-reports.

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const WORKFLOW_DIR = path.join(REPO_ROOT, '.github', 'workflows');

const SHA_PIN = /@[0-9a-f]{40}$/;

// Write-scoped jobs that still run a tag-pinned action, each owned by a unit
// that removes it. The cell fails if an entry stops violating, so a fix has
// to delete its entry here. release.yml can never appear: its publish and
// github-release jobs hold the npm publish identity and repo write.
const KNOWN_TAG_PINNED: Record<string, string> = {
  // In #348's diff, which a pin binds; pinned under unit 9947 after it lands.
  'pr-review.yml#review': 'unit 9947',
  'shield-check.yml#shield': 'unit 9947',
};

type Permissions = string | Record<string, string> | undefined;

interface Job {
  permissions?: Permissions;
  uses?: string;
  steps?: Array<{ uses?: string }>;
}

interface Workflow {
  permissions?: Permissions;
  jobs?: Record<string, Job>;
}

function holdsWrite(p: Permissions): boolean {
  if (p === undefined) return false; // repository default, measured `read` (above)
  if (typeof p === 'string') return p === 'write-all';
  return Object.values(p).some((v) => v === 'write');
}

/** `<file>#<job>: <uses>` for every non-sha `uses:` in a write-scoped job. */
function tagPinnedWriteUses(file: string, text: string): string[] {
  const wf = (yaml.load(text) ?? {}) as Workflow;
  const out: string[] = [];
  for (const [name, job] of Object.entries(wf.jobs ?? {})) {
    const perms = job.permissions !== undefined ? job.permissions : wf.permissions;
    if (!holdsWrite(perms)) continue;
    const uses = [job.uses, ...(job.steps ?? []).map((s) => s.uses)].filter(
      (u): u is string => typeof u === 'string',
    );
    for (const u of uses) {
      if (u.startsWith('./')) continue; // same-repo code, fixed by the commit under review
      if (!SHA_PIN.test(u)) out.push(`${file}#${name}: ${u}`);
    }
  }
  return out;
}

function workflowFiles(): string[] {
  return fs
    .readdirSync(WORKFLOW_DIR)
    .filter((f) => /\.ya?ml$/.test(f))
    .sort();
}

function allViolations(): string[] {
  return workflowFiles().flatMap((f) =>
    tagPinnedWriteUses(f, fs.readFileSync(path.join(WORKFLOW_DIR, f), 'utf-8')),
  );
}

const jobKey = (v: string) => v.slice(0, v.indexOf(':'));

describe('write-scoped jobs run only sha-pinned actions', () => {
  it('every uses: in a job holding a write scope or id-token is a full commit sha, outside the known set', () => {
    const unexpected = allViolations().filter((v) => !(jobKey(v) in KNOWN_TAG_PINNED));
    expect(unexpected).toEqual([]);
  });

  it('release.yml publish and github-release are pinned, and release.yml is never excepted', () => {
    const text = fs.readFileSync(path.join(WORKFLOW_DIR, 'release.yml'), 'utf-8');
    const wf = yaml.load(text) as Workflow;
    for (const name of ['publish', 'github-release']) {
      const job = wf.jobs?.[name];
      expect(job, `release.yml has no ${name} job`).toBeDefined();
      expect(holdsWrite(job!.permissions)).toBe(true);
      const uses = (job!.steps ?? []).map((s) => s.uses).filter(Boolean) as string[];
      expect(uses.length).toBeGreaterThan(0);
      for (const u of uses) expect(u, `release.yml#${name}`).toMatch(SHA_PIN);
    }
    expect(Object.keys(KNOWN_TAG_PINNED).filter((k) => k.startsWith('release.yml#'))).toEqual([]);
  });

  it('every known exception still violates, so a fix has to remove its entry', () => {
    const violating = new Set(allViolations().map(jobKey));
    const stale = Object.keys(KNOWN_TAG_PINNED).filter((k) => !violating.has(k));
    expect(stale).toEqual([]);
  });

  it('the checker is able to fail: tag pins in write jobs are reported, read jobs and sha pins are not', () => {
    const sha = 'a'.repeat(40);
    const fixture = [
      'permissions: {}',
      'jobs:',
      '  oidc:',
      '    permissions: { id-token: write }',
      '    steps:',
      '      - uses: actions/setup-node@v4',
      `      - uses: actions/download-artifact@${sha}`,
      '  all:',
      '    permissions: write-all',
      '    steps:',
      '      - uses: owner/action@main',
      '  reusable:',
      '    permissions: { contents: write }',
      '    uses: owner/repo/.github/workflows/x.yml@v1',
      '  local:',
      '    permissions: { contents: write }',
      '    steps:',
      '      - uses: ./.github/actions/local',
      '  readonly:',
      '    permissions: { contents: read }',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '  inherits-none:',
      '    steps:',
      '      - uses: actions/checkout@v4',
    ].join('\n');
    expect(tagPinnedWriteUses('f.yml', fixture)).toEqual([
      'f.yml#oidc: actions/setup-node@v4',
      'f.yml#all: owner/action@main',
      'f.yml#reusable: owner/repo/.github/workflows/x.yml@v1',
    ]);
    // A job inherits a write-scoped workflow-level block.
    const inherited = ['permissions: { contents: write }', 'jobs:', '  j:', '    steps:', '      - uses: actions/checkout@v4'].join('\n');
    expect(tagPinnedWriteUses('g.yml', inherited)).toEqual(['g.yml#j: actions/checkout@v4']);
    // A short or uppercase hex is not a full sha.
    const short = ['jobs:', '  j:', '    permissions: { id-token: write }', '    steps:', `      - uses: a/b@${'A'.repeat(40)}`, '      - uses: a/c@abc1234'].join('\n');
    expect(tagPinnedWriteUses('h.yml', short)).toHaveLength(2);
  });
});

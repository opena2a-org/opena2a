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

// Write-scoped jobs that still run a tag-pinned action. Each entry freezes
// the job's write scopes and its exact non-sha `uses:` list, so an excepted
// job cannot take on a new write scope or a new unpinned action and stay
// green: any difference from the entry fails. Read scopes are not frozen.
// An entry that stops violating fails too, so a fix has to delete it here.
// release.yml can never appear: its publish and github-release jobs hold the
// npm publish identity and repo write.
interface Exception {
  writes: string[];
  uses: string[];
  reason: string;
}
const KNOWN_TAG_PINNED: Record<string, Exception> = {
  'pr-review.yml#review': {
    writes: ['pull-requests'],
    uses: ['actions/checkout@v4'],
    reason:
      'pr-review.yml is in the diff of open PR #348, which a CISO pin binds; editing it here would move that diff. Pinned under unit 9947 once #348 lands.',
  },
  'shield-check.yml#shield': {
    writes: ['pull-requests'],
    uses: ['actions/checkout@v4', 'actions/setup-node@v4'],
    reason:
      'Outside release.yml, which is the scope of this change (unit 9948); repo-wide pinning, including this job, is unit 9947.',
  },
};

type Permissions = string | Record<string, string> | undefined;

interface Job {
  permissions?: Permissions;
  uses?: string;
  steps?: Array<{ uses?: string }>;
}

/** Reads a same-repo action's metadata, or returns null when there is none. */
type LocalActionReader = (ref: string) => string | null;

interface Workflow {
  permissions?: Permissions;
  jobs?: Record<string, Job>;
}

/** The scopes a job's token can write: `*` for write-all, none for the default. */
function writeScopes(p: Permissions): string[] {
  if (p === undefined) return []; // repository default, measured `read` (above)
  if (typeof p === 'string') return p === 'write-all' ? ['*'] : [];
  return Object.entries(p)
    .filter(([, v]) => v === 'write')
    .map(([k]) => k)
    .sort();
}

// A same-repo composite action runs its own `uses:` with the job's token, so
// it is walked, not skipped. Anything local that cannot be walked (a missing
// or non-composite action, a local reusable workflow) is reported.
function expandUses(u: string, readLocal: LocalActionReader, seen: Set<string> = new Set()): string[] {
  if (!u.startsWith('./')) return [u];
  const meta = seen.has(u) ? null : readLocal(u);
  if (meta === null) return [`${u} (local, not walked)`];
  const action = (yaml.load(meta) ?? {}) as { runs?: { using?: string; steps?: Array<{ uses?: string }> } };
  if (action.runs?.using !== 'composite') return [`${u} (local, not walked)`];
  const next = new Set(seen).add(u);
  return (action.runs.steps ?? [])
    .map((s) => s.uses)
    .filter((x): x is string => typeof x === 'string')
    .flatMap((x) => expandUses(x, readLocal, next));
}

interface WriteJob {
  key: string;
  writes: string[];
  /** Every `uses:` that is not a full sha, local actions expanded. */
  unpinned: string[];
}

function writeJobs(file: string, text: string, readLocal: LocalActionReader): WriteJob[] {
  const wf = (yaml.load(text) ?? {}) as Workflow;
  const out: WriteJob[] = [];
  for (const [name, job] of Object.entries(wf.jobs ?? {})) {
    const writes = writeScopes(job.permissions !== undefined ? job.permissions : wf.permissions);
    if (writes.length === 0) continue;
    const uses = [job.uses, ...(job.steps ?? []).map((s) => s.uses)]
      .filter((u): u is string => typeof u === 'string')
      .flatMap((u) => expandUses(u, readLocal));
    out.push({ key: `${file}#${name}`, writes, unpinned: uses.filter((u) => !SHA_PIN.test(u)) });
  }
  return out;
}

/** `<file>#<job>: <uses>` for every non-sha `uses:` in a write-scoped job. */
function tagPinnedWriteUses(file: string, text: string, readLocal: LocalActionReader = () => null): string[] {
  return writeJobs(file, text, readLocal).flatMap((j) => j.unpinned.map((u) => `${j.key}: ${u}`));
}

/** Differences between the known exceptions and what the workflows hold; empty when they match. */
function exceptionDrift(jobs: WriteJob[], known: Record<string, Exception>): string[] {
  const out: string[] = [];
  const byKey = new Map(jobs.map((j) => [j.key, j]));
  for (const [key, e] of Object.entries(known)) {
    const j = byKey.get(key);
    if (!j || j.unpinned.length === 0) {
      out.push(`${key}: no longer violates; delete its entry`);
      continue;
    }
    const same = (a: string[], b: string[]) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
    if (!same(j.writes, e.writes)) out.push(`${key}: write scopes ${JSON.stringify(j.writes)}, entry freezes ${JSON.stringify(e.writes)}`);
    if (!same(j.unpinned, e.uses)) out.push(`${key}: unpinned uses ${JSON.stringify(j.unpinned)}, entry freezes ${JSON.stringify(e.uses)}`);
  }
  return out;
}

const readRepoAction: LocalActionReader = (ref) => {
  for (const name of ['action.yml', 'action.yaml']) {
    const p = path.join(REPO_ROOT, ref, name);
    if (fs.existsSync(p)) return fs.readFileSync(p, 'utf-8');
  }
  return null;
};

function workflowFiles(): string[] {
  return fs
    .readdirSync(WORKFLOW_DIR)
    .filter((f) => /\.ya?ml$/.test(f))
    .sort();
}

function allWriteJobs(): WriteJob[] {
  return workflowFiles().flatMap((f) => writeJobs(f, fs.readFileSync(path.join(WORKFLOW_DIR, f), 'utf-8'), readRepoAction));
}

describe('write-scoped jobs run only sha-pinned actions', () => {
  it('every uses: in a job holding a write scope or id-token is a full commit sha, outside the known set', () => {
    const unexpected = allWriteJobs()
      .filter((j) => !(j.key in KNOWN_TAG_PINNED))
      .flatMap((j) => j.unpinned.map((u) => `${j.key}: ${u}`));
    expect(unexpected).toEqual([]);
  });

  it('each known exception matches its frozen write scopes and unpinned uses exactly, and gives a reason', () => {
    expect(exceptionDrift(allWriteJobs(), KNOWN_TAG_PINNED)).toEqual([]);
    for (const [key, e] of Object.entries(KNOWN_TAG_PINNED)) expect(e.reason.length, key).toBeGreaterThan(20);
  });

  it('release.yml publish and github-release are pinned, and release.yml is never excepted', () => {
    const text = fs.readFileSync(path.join(WORKFLOW_DIR, 'release.yml'), 'utf-8');
    const wf = yaml.load(text) as Workflow;
    for (const name of ['publish', 'github-release']) {
      const job = wf.jobs?.[name];
      expect(job, `release.yml has no ${name} job`).toBeDefined();
      expect(writeScopes(job!.permissions).length).toBeGreaterThan(0);
      const uses = (job!.steps ?? []).map((s) => s.uses).filter(Boolean) as string[];
      expect(uses.length).toBeGreaterThan(0);
      for (const u of uses) expect(u, `release.yml#${name}`).toMatch(SHA_PIN);
    }
    expect(Object.keys(KNOWN_TAG_PINNED).filter((k) => k.startsWith('release.yml#'))).toEqual([]);
  });

  it('an exception is red when its job gains a write scope, gains or changes an unpinned action, or stops violating', () => {
    const known = { 'x.yml#j': { writes: ['pull-requests'], uses: ['actions/checkout@v4'], reason: 'control entry for this cell' } };
    const wf = (perms: string, uses: string[]) =>
      ['jobs:', '  j:', `    permissions: ${perms}`, '    steps:', ...uses.map((u) => `      - uses: ${u}`)].join('\n');
    const drift = (perms: string, uses: string[]) => exceptionDrift(writeJobs('x.yml', wf(perms, uses), () => null), known);
    // The frozen shape, plus a read scope (read scopes are not frozen): green.
    expect(drift('{ pull-requests: write, contents: read, actions: read }', ['actions/checkout@v4'])).toEqual([]);
    // A new write scope, the OIDC token included: red.
    expect(drift('{ pull-requests: write, id-token: write }', ['actions/checkout@v4'])).toHaveLength(1);
    expect(drift('write-all', ['actions/checkout@v4'])).toHaveLength(1);
    // A new unpinned action, or the frozen one retagged: red.
    expect(drift('{ pull-requests: write }', ['actions/checkout@v4', 'evil/action@main'])).toHaveLength(1);
    expect(drift('{ pull-requests: write }', ['actions/checkout@v5'])).toHaveLength(1);
    // Pinned by sha, or no longer write-scoped: the entry is stale, red.
    expect(drift('{ pull-requests: write }', [`actions/checkout@${'b'.repeat(40)}`])).toEqual(['x.yml#j: no longer violates; delete its entry']);
    expect(drift('{ pull-requests: read }', ['actions/checkout@v4'])).toEqual(['x.yml#j: no longer violates; delete its entry']);
  });

  it('a same-repo action is walked: its own unpinned uses count, and one that cannot be walked is reported', () => {
    const local: Record<string, string> = {
      './.github/actions/composite': ['runs:', '  using: composite', '  steps:', '    - uses: actions/cache@v4', `    - uses: a/b@${'c'.repeat(40)}`, '    - uses: ./.github/actions/nested'].join('\n'),
      './.github/actions/nested': ['runs:', '  using: composite', '  steps:', '    - uses: owner/deep@v1', '    - uses: ./.github/actions/composite'].join('\n'),
      './.github/actions/node': ['runs:', '  using: node20', '  main: index.js'].join('\n'),
    };
    const reader: LocalActionReader = (ref) => local[ref] ?? null;
    const wf = ['jobs:', '  j:', '    permissions: { contents: write }', '    steps:', '      - uses: ./.github/actions/composite', '      - uses: ./.github/actions/node', '      - uses: ./.github/actions/missing'].join('\n');
    expect(tagPinnedWriteUses('w.yml', wf, reader)).toEqual([
      'w.yml#j: actions/cache@v4',
      'w.yml#j: owner/deep@v1',
      'w.yml#j: ./.github/actions/composite (local, not walked)',
      'w.yml#j: ./.github/actions/node (local, not walked)',
      'w.yml#j: ./.github/actions/missing (local, not walked)',
    ]);
    // A local reusable workflow at job level is reported, not trusted.
    const reusable = ['jobs:', '  j:', '    permissions: { contents: write }', '    uses: ./.github/workflows/other.yml'].join('\n');
    expect(tagPinnedWriteUses('r.yml', reusable, reader)).toEqual(['r.yml#j: ./.github/workflows/other.yml (local, not walked)']);
  });

  it('the checker is able to fail: tag pins and unwalked local actions in write jobs are reported, read jobs and sha pins are not', () => {
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
      'f.yml#local: ./.github/actions/local (local, not walked)',
    ]);
    // A job inherits a write-scoped workflow-level block.
    const inherited = ['permissions: { contents: write }', 'jobs:', '  j:', '    steps:', '      - uses: actions/checkout@v4'].join('\n');
    expect(tagPinnedWriteUses('g.yml', inherited)).toEqual(['g.yml#j: actions/checkout@v4']);
    // A short or uppercase hex is not a full sha.
    const short = ['jobs:', '  j:', '    permissions: { id-token: write }', '    steps:', `      - uses: a/b@${'A'.repeat(40)}`, '      - uses: a/c@abc1234'].join('\n');
    expect(tagPinnedWriteUses('h.yml', short)).toHaveLength(2);
  });
});

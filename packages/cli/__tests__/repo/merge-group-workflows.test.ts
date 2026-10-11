/**
 * The merge-group bind and the review relay, run as written.
 *
 * gate-file-approval.yml and review-merge-group.yml each carry a copy of the
 * shell block that binds a merge group commit M to the pull request it was
 * built from. The two copies must stay byte-identical: the review relay's
 * verdict on M rests on the same bind the gate check uses. This file extracts
 * both blocks from the workflow text and compares them, then runs each
 * workflow's `run:` script under bash against a stub `gh` on PATH. The stub
 * answers each API path from a per-case table and records every call, so the
 * cases below pin the verdict, the posted check run and the error line for
 * the bound case, each clause that leaves M unbound, each gate-file verdict
 * and each refusal of the review relay (#462).
 *
 * `bash` and `jq` are the tools the workflow steps themselves run; both are
 * preinstalled on the ubuntu-latest runners this suite runs on.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { load } from 'js-yaml';

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const GATE_WORKFLOW = '.github/workflows/gate-file-approval.yml';
const RELAY_WORKFLOW = '.github/workflows/review-merge-group.yml';
const BIND_BEGIN = '# --- BEGIN MERGE-GROUP BIND ---';
const BIND_END = '# --- END MERGE-GROUP BIND ---';

const TOOLS_REQUIRED =
  'bash and jq are required to run the workflow scripts (`apt-get install jq` / `brew install jq`); ' +
  'both are preinstalled on the ubuntu-latest runners this suite runs on';

interface Workflow {
  jobs: Record<string, { steps?: { name?: string; run?: string }[] }>;
}

function stepScript(file: string, job: string, step: string): string {
  const doc = load(fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8')) as Workflow;
  const run = doc.jobs[job]?.steps?.find((s) => s.name === step)?.run;
  if (!run) throw new Error(`${file}: job ${job} has no run: script in the step "${step}"`);
  return run;
}

function bindBlock(script: string, file: string): string {
  const lines = script.split('\n');
  const begins = lines.flatMap((l, i) => (l.trim() === BIND_BEGIN ? [i] : []));
  const ends = lines.flatMap((l, i) => (l.trim() === BIND_END ? [i] : []));
  if (begins.length !== 1 || ends.length !== 1 || ends[0] <= begins[0]) {
    throw new Error(
      `${file}: expected one "${BIND_BEGIN}" line before one "${BIND_END}" line, ` +
        `found ${begins.length} and ${ends.length}`,
    );
  }
  return lines.slice(begins[0], ends[0] + 1).join('\n');
}

const GATE_SCRIPT = stepScript(GATE_WORKFLOW, 'evaluate', 'Evaluate and post the check run');
const RELAY_SCRIPT = stepScript(
  RELAY_WORKFLOW,
  'review',
  'Bind the merge group and read the pull request review',
);
const APPROVER = /^approvers="([^"]+)"$/m.exec(GATE_SCRIPT)?.[1] ?? '';

// ---------------------------------------------------------------------------
// The stub gh. Only `gh api` is routed: `-X`, `-f`, `--jq` and `--paginate`
// are the flags the two scripts pass. A route's reply is { body } or
// { fail: true }; an array of replies is consumed one per call to that route,
// the last repeating. A route the case does not list fails like a 404, except
// a POST of a check run, which echoes the posted conclusion back.
// ---------------------------------------------------------------------------

interface Reply {
  body?: unknown;
  fail?: boolean;
}
type Routes = Record<string, Reply | Reply[]>;
interface Call {
  key: string;
  fields: Record<string, string>;
}

const STUB_GH = `#!${process.execPath}
'use strict';
const fs = require('fs');
const { spawnSync } = require('child_process');
const argv = process.argv.slice(2);
if (argv[0] !== 'api') {
  process.stderr.write('stub gh: only "gh api" is routed\\n');
  process.exit(2);
}
let method = 'GET';
let route = '';
let jq = null;
const fields = {};
for (let i = 1; i < argv.length; i++) {
  const a = argv[i];
  if (a === '-X') method = argv[++i];
  else if (a === '-f') {
    const kv = argv[++i];
    const eq = kv.indexOf('=');
    fields[kv.slice(0, eq)] = kv.slice(eq + 1);
  } else if (a === '--jq') jq = argv[++i];
  else if (a === '--paginate') continue;
  else if (route === '') route = a;
  else {
    process.stderr.write('stub gh: unexpected argument ' + a + '\\n');
    process.exit(2);
  }
}
const key = method + ' ' + route;
const log = process.env.GH_STUB_LOG;
const prior = fs.existsSync(log)
  ? fs.readFileSync(log, 'utf8').split('\\n').filter(Boolean).filter((l) => JSON.parse(l).key === key).length
  : 0;
fs.appendFileSync(log, JSON.stringify({ key, fields }) + '\\n');
const routes = JSON.parse(fs.readFileSync(process.env.GH_STUB_ROUTES, 'utf8'));
let reply = routes[key];
if (Array.isArray(reply)) reply = reply[Math.min(prior, reply.length - 1)];
if (reply === undefined && method === 'POST' && route.endsWith('/check-runs')) {
  reply = { body: { id: 1, conclusion: fields.conclusion } };
}
if (!reply || reply.fail) {
  process.stderr.write('gh: Not Found (HTTP 404) [stub: ' + key + ']\\n');
  process.exit(1);
}
const json = JSON.stringify(reply.body);
if (jq === null) {
  process.stdout.write(json + '\\n');
  process.exit(0);
}
const r = spawnSync('jq', ['-r', jq], { input: json, encoding: 'utf8' });
process.stdout.write(r.stdout || '');
process.stderr.write(r.stderr || '');
process.exit(r.status === null ? 1 : r.status);
`;

let scratch = '';
let caseNo = 0;

beforeAll(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'merge-group-workflows-'));
  fs.mkdirSync(path.join(scratch, 'bin'));
  fs.writeFileSync(path.join(scratch, 'bin', 'gh'), STUB_GH, { mode: 0o755 });
  fs.writeFileSync(path.join(scratch, 'gate.sh'), GATE_SCRIPT);
  fs.writeFileSync(path.join(scratch, 'relay.sh'), RELAY_SCRIPT);
});

afterAll(() => {
  if (scratch) fs.rmSync(scratch, { recursive: true, force: true });
});

function haveTools(): boolean {
  return (
    spawnSync('bash', ['-c', 'true']).status === 0 &&
    spawnSync('jq', ['--version'], { encoding: 'utf-8' }).status === 0
  );
}

interface Outcome {
  status: number | null;
  stdout: string;
  stderr: string;
  calls: Call[];
  posts: Call[];
}

/** Runs one workflow script the way the runner does: `bash -e <file>`. */
function runScript(script: 'gate' | 'relay', env: Record<string, string>, routes: Routes): Outcome {
  const dir = path.join(scratch, `case-${++caseNo}`);
  fs.mkdirSync(dir);
  const routesFile = path.join(dir, 'routes.json');
  const logFile = path.join(dir, 'calls.jsonl');
  fs.writeFileSync(routesFile, JSON.stringify(routes));
  const r = spawnSync('bash', ['-e', path.join(scratch, `${script}.sh`)], {
    env: {
      PATH: `${path.join(scratch, 'bin')}${path.delimiter}${process.env.PATH ?? ''}`,
      GH_STUB_ROUTES: routesFile,
      GH_STUB_LOG: logFile,
      ...env,
    },
    encoding: 'utf-8',
    timeout: 60_000,
  });
  const calls: Call[] = fs.existsSync(logFile)
    ? fs
        .readFileSync(logFile, 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as Call)
    : [];
  return {
    status: r.status,
    stdout: r.stdout,
    stderr: r.stderr,
    calls,
    posts: calls.filter((c) => c.key.startsWith('POST ')),
  };
}

// ---------------------------------------------------------------------------
// A merge group commit M bound to pull request #412 at head H: the queue ref
// names #412, M's parents are the queue base and H, and M changes the one
// file the pull request changes, with the same blob.
// ---------------------------------------------------------------------------

const REPO = 'example-org/example-repo';
const PR = 412;
const hex = (c: string): string => c.repeat(40);
const BASE = hex('b');
const M = hex('c');
const H = hex('a');
const OTHER = hex('d');
const QUEUE_REF = `refs/heads/gh-readonly-queue/main/pr-${PR}-${BASE}`;
const SRC_FILE = 'packages/cli/src/index.ts';
const BLOB = hex('1');
const MAIN_BLOB = hex('2');

const PR_ROUTE = `GET repos/${REPO}/pulls/${PR}`;
const PR_FILES_ROUTE = `GET repos/${REPO}/compare/${BASE}...${H}`;
const M_PARENTS_ROUTE = `GET repos/${REPO}/commits/${M}`;
const M_FILES_ROUTE = `GET repos/${REPO}/compare/${BASE}...${M}`;
const REVIEWS_ROUTE = `GET repos/${REPO}/pulls/${PR}/reviews`;
const RUNS_ROUTE = `GET repos/${REPO}/actions/workflows/pr-review.yml/runs?head_sha=${H}&event=pull_request&per_page=100`;
const attemptRoute = (run: number, attempt: number): string =>
  `GET repos/${REPO}/actions/runs/${run}/attempts/${attempt}`;

interface FileEntry {
  filename: string;
  status: string;
  sha?: string;
  previous_filename?: string;
}

interface PullRequest {
  number: number;
  state: string;
  base: { ref: string };
  head: { sha: string };
  changed_files: number | null;
}

interface Scenario {
  env: Record<string, string>;
  routes: Routes;
}

const pullRequest = (files: FileEntry[]): PullRequest => ({
  number: PR,
  state: 'open',
  base: { ref: 'main' },
  head: { sha: H },
  changed_files: files.length,
});

/** Every variable the gate step's env block sets; GitHub sets an absent field to ''. */
function gateEnv(overrides: Record<string, string>): Record<string, string> {
  return {
    REPO,
    PR_NUMBER: '',
    HEAD_SHA: '',
    MG_HEAD_SHA: '',
    MG_BASE_SHA: '',
    MG_HEAD_REF: '',
    MG_BASE_REF: '',
    EVENT_NAME: '',
    REVIEW_AUTHOR: '',
    ...overrides,
  };
}

function boundGroup(files: FileEntry[] = [{ filename: SRC_FILE, status: 'modified', sha: BLOB }]): Scenario {
  return {
    env: {
      REPO,
      EVENT_NAME: 'merge_group',
      MG_HEAD_SHA: M,
      MG_BASE_SHA: BASE,
      MG_HEAD_REF: QUEUE_REF,
      MG_BASE_REF: 'refs/heads/main',
    },
    routes: {
      [PR_ROUTE]: { body: pullRequest(files) },
      [PR_FILES_ROUTE]: { body: { files } },
      [M_PARENTS_ROUTE]: { body: { parents: [{ sha: BASE }, { sha: H }] } },
      [M_FILES_ROUTE]: { body: { files } },
    },
  };
}

const run = (id: number, attempts: number, status = 'completed') => ({
  id,
  status,
  run_attempt: attempts,
  path: '.github/workflows/pr-review.yml',
  html_url: `https://github.com/${REPO}/actions/runs/${id}`,
});

/** Two review runs on H, every attempt a success. */
function passingReview(s: Scenario): Scenario {
  s.routes[RUNS_ROUTE] = { body: { total_count: 2, workflow_runs: [run(101, 1), run(102, 2)] } };
  s.routes[attemptRoute(101, 1)] = { body: { conclusion: 'success' } };
  s.routes[attemptRoute(102, 1)] = { body: { conclusion: 'success' } };
  s.routes[attemptRoute(102, 2)] = { body: { conclusion: 'success' } };
  return s;
}

function runGate(s: Scenario): Outcome {
  return runScript('gate', gateEnv(s.env), s.routes);
}

function runRelay(s: Scenario): Outcome {
  return runScript('relay', s.env, s.routes);
}

function setPr(s: Scenario, edit: (pr: PullRequest) => void): void {
  const pr = structuredClone((s.routes[PR_ROUTE] as Reply).body) as PullRequest;
  edit(pr);
  s.routes[PR_ROUTE] = { body: pr };
}

function setFiles(s: Scenario, route: string, files: FileEntry[]): void {
  s.routes[route] = { body: { files } };
}

const manyFiles = (n: number): FileEntry[] =>
  Array.from({ length: n }, (_, i) => ({ filename: `docs/page-${i}.md`, status: 'modified', sha: BLOB }));

interface UnboundCase {
  clause: string;
  edit: (s: Scenario) => void;
  reason: string;
  /** The gate script only reads the bind result on a merge_group event. */
  relayOnly?: boolean;
  /** The commit the gate posts on, when it is not M. */
  postedOn?: string;
}

const UNBOUND: UnboundCase[] = [
  {
    clause: 'the event is not merge_group',
    edit: (s) => (s.env.EVENT_NAME = 'push'),
    reason: "The event is 'push', not merge_group.",
    relayOnly: true,
  },
  {
    clause: 'the group targets a branch other than main',
    edit: (s) => (s.env.MG_BASE_REF = 'refs/heads/release'),
    reason: "The merge group targets 'refs/heads/release', not refs/heads/main.",
  },
  {
    clause: 'the group head commit is not a 40-character SHA',
    edit: (s) => (s.env.MG_HEAD_SHA = 'not-a-sha'),
    reason: "The merge group head commit 'not-a-sha' is not a 40-character hexadecimal SHA.",
    postedOn: 'not-a-sha',
  },
  {
    clause: 'the group base commit is not lowercase hexadecimal',
    edit: (s) => (s.env.MG_BASE_SHA = BASE.toUpperCase()),
    reason: `The merge group base commit '${BASE.toUpperCase()}' is not a 40-character hexadecimal SHA.`,
  },
  {
    clause: 'the ref is not a queue ref for main',
    edit: (s) => (s.env.MG_HEAD_REF = 'refs/heads/feature/queue'),
    reason: "The merge group ref 'refs/heads/feature/queue' is not a queue ref for main.",
  },
  {
    clause: 'the ref names no pull request number',
    edit: (s) => (s.env.MG_HEAD_REF = `refs/heads/gh-readonly-queue/main/pr-x-${BASE}`),
    reason: `The merge group ref 'refs/heads/gh-readonly-queue/main/pr-x-${BASE}' does not name a pull request number.`,
  },
  {
    clause: 'the ref carries more than a number and one SHA',
    edit: (s) => (s.env.MG_HEAD_REF = `${QUEUE_REF}-2`),
    reason: `The merge group ref '${QUEUE_REF}-2' carries more than a pull request number and one 40-character SHA.`,
  },
  {
    clause: 'the pull request cannot be read',
    edit: (s) => (s.routes[PR_ROUTE] = { fail: true }),
    reason: `The pull request read for the merge group is '', not #${PR}.`,
  },
  {
    clause: 'the pull request read is another number',
    edit: (s) => setPr(s, (pr) => (pr.number = PR + 1)),
    reason: `The pull request read for the merge group is '${PR + 1}', not #${PR}.`,
  },
  {
    clause: 'the pull request is closed',
    edit: (s) => setPr(s, (pr) => (pr.state = 'closed')),
    reason: `Pull request #${PR} is 'closed', not open.`,
  },
  {
    clause: 'the pull request targets another branch',
    edit: (s) => setPr(s, (pr) => (pr.base.ref = 'release')),
    reason: `Pull request #${PR} targets 'release', not main.`,
  },
  {
    clause: 'the pull request head is not a 40-character SHA',
    edit: (s) => setPr(s, (pr) => (pr.head.sha = 'abc123')),
    reason: `Pull request #${PR} has no 40-character head commit: 'abc123'.`,
  },
  {
    clause: 'the pull request changes 3000 files',
    edit: (s) => setPr(s, (pr) => (pr.changed_files = 3000)),
    reason: `Pull request #${PR} changes '3000' files, not a count below the 3000-entry listing cap.`,
  },
  {
    clause: 'the pull request carries no changed-file count',
    edit: (s) => setPr(s, (pr) => (pr.changed_files = null)),
    reason: `Pull request #${PR} changes '' files, not a count below the 3000-entry listing cap.`,
  },
  {
    clause: 'the pull request head moves while its files are read',
    edit: (s) => {
      const first = (s.routes[PR_ROUTE] as Reply).body as PullRequest;
      s.routes[PR_ROUTE] = [{ body: first }, { body: { ...first, head: { sha: OTHER } } }];
    },
    reason: `Pull request #${PR} moved from ${H} to '${OTHER}' while its files were read.`,
  },
  {
    clause: 'the group commit cannot be read',
    edit: (s) => (s.routes[M_PARENTS_ROUTE] = { fail: true }),
    reason: `Merge group commit ${M} has 0 parents; one or two are expected.`,
  },
  {
    clause: 'the group commit has three parents',
    edit: (s) => (s.routes[M_PARENTS_ROUTE] = { body: { parents: [{ sha: BASE }, { sha: H }, { sha: OTHER }] } }),
    reason: `Merge group commit ${M} has 3 parents; one or two are expected.`,
  },
  {
    clause: 'the first parent is not the group base',
    edit: (s) => (s.routes[M_PARENTS_ROUTE] = { body: { parents: [{ sha: OTHER }, { sha: H }] } }),
    reason: `The first parent of ${M} is ${OTHER}, not the merge group base ${BASE}.`,
  },
  {
    clause: 'the second parent is not the pull request head',
    edit: (s) => (s.routes[M_PARENTS_ROUTE] = { body: { parents: [{ sha: BASE }, { sha: OTHER }] } }),
    reason: `The second parent of ${M} is ${OTHER}, not the pull request head ${H}.`,
  },
  {
    clause: 'the files of the group commit cannot be read',
    edit: (s) => (s.routes[M_FILES_ROUTE] = { fail: true }),
    reason: `The files ${M} changes against its base could not be read.`,
  },
  {
    clause: 'a file of the pull request carries no blob',
    edit: (s) => setFiles(s, PR_FILES_ROUTE, [{ filename: SRC_FILE, status: 'modified' }]),
    reason: `The files pull request #${PR} changes could not be read.`,
  },
  {
    clause: 'the group comparison lists 300 files',
    edit: (s) => {
      setPr(s, (pr) => (pr.changed_files = 300));
      setFiles(s, PR_FILES_ROUTE, manyFiles(300));
      setFiles(s, M_FILES_ROUTE, manyFiles(300));
    },
    reason: `The comparison of ${M} with its base lists '300' files; at 300 the listing may be truncated.`,
  },
  {
    clause: 'the group changes a file the pull request does not',
    edit: (s) =>
      setFiles(s, M_FILES_ROUTE, [
        { filename: SRC_FILE, status: 'modified', sha: BLOB },
        { filename: 'docs/extra.md', status: 'added', sha: MAIN_BLOB },
      ]),
    reason: 'docs/extra.md is changed in the merge group but not in the pull request.',
  },
  {
    clause: 'the pull request changes a file the group does not',
    edit: (s) => setFiles(s, M_FILES_ROUTE, []),
    reason: `${SRC_FILE} is changed in the pull request but not in the merge group.`,
  },
  {
    clause: 'a file has another status in the group',
    edit: (s) => setFiles(s, M_FILES_ROUTE, [{ filename: SRC_FILE, status: 'added', sha: BLOB }]),
    reason: `The status of ${SRC_FILE} is "added" in the merge group and "modified" in the pull request.`,
  },
  {
    clause: 'a renamed file has another previous path in the group',
    edit: (s) => {
      setFiles(s, PR_FILES_ROUTE, [
        { filename: SRC_FILE, status: 'renamed', previous_filename: 'packages/cli/src/old.ts', sha: BLOB },
      ]);
      setFiles(s, M_FILES_ROUTE, [
        { filename: SRC_FILE, status: 'renamed', previous_filename: 'packages/cli/src/older.ts', sha: BLOB },
      ]);
    },
    reason:
      `The previous path of ${SRC_FILE} is "packages/cli/src/older.ts" in the merge group ` +
      'and "packages/cli/src/old.ts" in the pull request.',
  },
  {
    // main changed the same file after the pull request's merge-base, so
    // the group's blob is the merge of both sides
    clause: 'a file carries another blob in the group',
    edit: (s) => setFiles(s, M_FILES_ROUTE, [{ filename: SRC_FILE, status: 'modified', sha: MAIN_BLOB }]),
    reason: `The blob of ${SRC_FILE} is "${MAIN_BLOB}" in the merge group and "${BLOB}" in the pull request.`,
  },
];

function unbound(c: UnboundCase): Scenario {
  const s = boundGroup();
  c.edit(s);
  return s;
}

describe('merge-group bind block', () => {
  it('gate-file-approval.yml and review-merge-group.yml carry the same bind block, byte for byte', () => {
    const gate = bindBlock(GATE_SCRIPT, GATE_WORKFLOW);
    const relay = bindBlock(RELAY_SCRIPT, RELAY_WORKFLOW);
    expect(gate).toContain('bind_ok=true');
    expect(relay).toBe(gate);
  });

  it('finds the approver the gate script names', () => {
    expect(APPROVER).toMatch(/^[A-Za-z0-9-]+$/);
  });

  it('has bash and jq to run the workflow scripts', () => {
    expect(haveTools(), TOOLS_REQUIRED).toBe(true);
  });
});

describe('merge-group bind, run by the gate-file check', () => {
  it('posts one success on the group commit when it is bound and touches nothing under .github/', () => {
    const out = runGate(boundGroup());
    expect(out.status, out.stderr).toBe(0);
    expect(out.posts).toHaveLength(1);
    expect(out.posts[0].fields).toMatchObject({
      name: 'Gate file approval',
      head_sha: M,
      status: 'completed',
      conclusion: 'success',
      'output[title]': 'No gate files touched',
    });
  });

  it('binds a group commit whose only parent is the group base', () => {
    const s = boundGroup();
    s.routes[M_PARENTS_ROUTE] = { body: { parents: [{ sha: BASE }] } };
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(0);
    expect(out.posts.map((p) => p.fields.conclusion)).toEqual(['success']);
  });

  it.each(UNBOUND.filter((c) => !c.relayOnly))(
    'posts one failure naming the clause when $clause',
    (c) => {
      const out = runGate(unbound(c));
      expect(out.status, out.stderr).toBe(1);
      expect(out.posts).toHaveLength(1);
      expect(out.posts[0].fields).toEqual({
        name: 'Gate file approval',
        head_sha: c.postedOn ?? M,
        status: 'completed',
        conclusion: 'failure',
        'output[title]': 'Merge group not bound to its pull request',
        'output[summary]': c.reason,
      });
    },
    30_000,
  );
});

describe('merge-group bind, run by the review relay', () => {
  it('reports the bind and passes when every attempt of every review run on the head succeeded', () => {
    const out = runRelay(passingReview(boundGroup()));
    expect(out.status, out.stderr).toBe(0);
    expect(out.stdout).toContain(`Merge group commit ${M} is bound to pull request #${PR} at ${H}.`);
    expect(out.stdout).toContain(
      `The review of pull request #${PR} at ${H} passed: 2 run(s), every attempt concluded with success.`,
    );
    expect(out.posts).toHaveLength(0);
  });

  it.each(UNBOUND)(
    'fails with an error line naming the clause when $clause',
    (c) => {
      const out = runRelay(passingReview(unbound(c)));
      expect(out.status, out.stderr).toBe(1);
      expect(out.stdout.split('\n')).toContain(`::error::${c.reason}`);
      expect(out.calls.filter((call) => call.key === RUNS_ROUTE)).toHaveLength(0);
      expect(out.posts).toHaveLength(0);
    },
    30_000,
  );
});

describe('gate-file verdicts', () => {
  const GATE_FILE = '.github/workflows/ci.yml';
  const GATE_WORKFLOW_FILE = '.github/workflows/gate-file-approval.yml';
  const gateFiles = (filename = GATE_FILE): FileEntry[] => [
    { filename: SRC_FILE, status: 'modified', sha: BLOB },
    { filename, status: 'modified', sha: MAIN_BLOB },
  ];
  const review = (state: string, commit: string) => ({ state, user: { login: APPROVER }, commit_id: commit });
  const contentRoute = (head: string): string =>
    `GET repos/${REPO}/contents/${GATE_WORKFLOW_FILE}?ref=${head}`;

  /** A pull_request_target event on #412 at H. */
  function pullRequestEvent(files: FileEntry[], changedFiles = files.length): Scenario {
    return {
      env: { EVENT_NAME: 'pull_request_target', PR_NUMBER: String(PR), HEAD_SHA: H },
      routes: {
        [PR_ROUTE]: { body: { ...pullRequest(files), changed_files: changedFiles } },
        [`GET repos/${REPO}/pulls/${PR}/files`]: { body: files },
      },
    };
  }

  function onlyPost(out: Outcome): Record<string, string> {
    expect(out.posts).toHaveLength(1);
    return out.posts[0].fields;
  }

  it('posts nothing for a review by anyone but the approver', () => {
    const s = pullRequestEvent(gateFiles());
    s.env = { ...s.env, EVENT_NAME: 'pull_request_review', REVIEW_AUTHOR: 'someone-else' };
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(0);
    expect(out.calls).toHaveLength(0);
    expect(out.stdout).toContain('Review by someone-else is not an input to the verdict; nothing posted.');
  });

  it('passes a pull request that touches nothing under .github/', () => {
    const out = runGate(pullRequestEvent([{ filename: SRC_FILE, status: 'modified', sha: BLOB }]));
    expect(out.status, out.stderr).toBe(0);
    expect(onlyPost(out)).toMatchObject({ head_sha: H, conclusion: 'success', 'output[title]': 'No gate files touched' });
  });

  it('fails a pull request at the 3000-file listing cap', () => {
    const out = runGate(pullRequestEvent([{ filename: SRC_FILE, status: 'modified', sha: BLOB }], 3000));
    expect(out.status, out.stderr).toBe(1);
    expect(onlyPost(out)).toMatchObject({ conclusion: 'failure', 'output[title]': 'Too many changed files to evaluate' });
  });

  it('passes a gate-file change the approver approved on the head', () => {
    const s = pullRequestEvent(gateFiles());
    s.routes[REVIEWS_ROUTE] = { body: [review('APPROVED', H)] };
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(0);
    expect(onlyPost(out)).toMatchObject({ conclusion: 'success', 'output[title]': 'Gate-file change approved' });
  });

  it('asks for approval, and exits 0, when the approval is on an older commit', () => {
    const s = pullRequestEvent(gateFiles());
    s.routes[REVIEWS_ROUTE] = { body: [review('APPROVED', OTHER)] };
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(0);
    expect(onlyPost(out)).toMatchObject({
      head_sha: H,
      conclusion: 'action_required',
      'output[title]': 'Gate-file change needs approval',
    });
  });

  it('asks for approval when changes were requested after the approval', () => {
    const s = pullRequestEvent(gateFiles());
    s.routes[REVIEWS_ROUTE] = { body: [review('APPROVED', H), review('CHANGES_REQUESTED', H)] };
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(0);
    expect(onlyPost(out).conclusion).toBe('action_required');
  });

  it('refuses a proposed gate workflow that references a secret, even when approved', () => {
    const s = pullRequestEvent(gateFiles(GATE_WORKFLOW_FILE));
    const proposed = 'env:\n  VALUE: ${{ ' + 'secrets.' + 'EXAMPLE }}\n';
    s.routes[contentRoute(H)] = { body: { content: Buffer.from(proposed).toString('base64') } };
    s.routes[REVIEWS_ROUTE] = { body: [review('APPROVED', H)] };
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(1);
    expect(onlyPost(out)).toMatchObject({ conclusion: 'failure', 'output[title]': 'Gate workflow hardening violated' });
  });

  it('refuses a proposed gate workflow whose copy reads back empty', () => {
    const s = pullRequestEvent(gateFiles(GATE_WORKFLOW_FILE));
    s.routes[contentRoute(H)] = { body: { content: '' } };
    s.routes[REVIEWS_ROUTE] = { body: [review('APPROVED', H)] };
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(1);
    expect(onlyPost(out)).toMatchObject({ conclusion: 'failure', 'output[title]': 'Gate workflow copy unreadable' });
  });

  it('passes a bound group whose gate-file change the approver approved on the pull request head', () => {
    const s = boundGroup(gateFiles());
    s.routes[REVIEWS_ROUTE] = { body: [review('APPROVED', H)] };
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(0);
    expect(onlyPost(out)).toMatchObject({
      head_sha: M,
      conclusion: 'success',
      'output[title]': 'Gate-file change approved',
    });
  });

  it('fails a bound group whose gate-file change still needs approval, since none can be given in the queue', () => {
    const s = boundGroup(gateFiles());
    s.routes[REVIEWS_ROUTE] = { body: [review('APPROVED', OTHER)] };
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(1);
    expect(onlyPost(out)).toMatchObject({
      head_sha: M,
      conclusion: 'failure',
      'output[title]': 'Gate-file change needs approval',
    });
  });

  it('fails a bound group whose bound file list is shorter than the pull request count', () => {
    const s = boundGroup();
    setPr(s, (pr) => (pr.changed_files = 2));
    const out = runGate(s);
    expect(out.status, out.stderr).toBe(1);
    expect(onlyPost(out)).toEqual({
      name: 'Gate file approval',
      head_sha: M,
      status: 'completed',
      conclusion: 'failure',
      'output[title]': 'Merge group file count differs from its pull request',
      'output[summary]': `The comparison bound to pull request #${PR} at ${H} lists 1 files; the pull request reports 2 changed files.`,
    });
  });

  it('posts one failure on a bound group when a read fails before the verdict is posted', () => {
    const s = boundGroup(gateFiles());
    s.routes[REVIEWS_ROUTE] = { fail: true };
    const out = runGate(s);
    expect(out.status).not.toBe(0);
    expect(onlyPost(out)).toMatchObject({
      head_sha: M,
      conclusion: 'failure',
      'output[title]': 'Merge group verdict could not be evaluated',
    });
  });
});

describe('review relay refusals on a bound group', () => {
  interface RelayCase {
    refusal: string;
    edit: (s: Scenario) => void;
    error: string;
  }

  const RELAY: RelayCase[] = [
    {
      refusal: 'the review runs cannot be read',
      edit: (s) => (s.routes[RUNS_ROUTE] = { fail: true }),
      error: `The review runs of pull request #${PR} at ${H} could not be read.`,
    },
    {
      refusal: 'the run list is not complete',
      edit: (s) => (s.routes[RUNS_ROUTE] = { body: { total_count: 3, workflow_runs: [run(101, 1), run(102, 2)] } }),
      error: `The review runs of pull request #${PR} at ${H} list 2 runs of a total of '3'; the list is not complete.`,
    },
    {
      refusal: 'no listed run is of pr-review.yml',
      edit: (s) =>
        (s.routes[RUNS_ROUTE] = {
          body: { total_count: 1, workflow_runs: [{ ...run(101, 1), path: '.github/workflows/ci.yml' }] },
        }),
      error: `No run of .github/workflows/pr-review.yml is listed for pull request #${PR} at ${H}.`,
    },
    {
      refusal: 'a run carries no id',
      edit: (s) =>
        (s.routes[RUNS_ROUTE] = { body: { total_count: 1, workflow_runs: [{ ...run(101, 1), id: null }] } }),
      error: `Run 1 of the review runs of pull request #${PR} at ${H} carries no run id: ''.`,
    },
    {
      refusal: 'a run carries no attempt number',
      edit: (s) =>
        (s.routes[RUNS_ROUTE] = { body: { total_count: 1, workflow_runs: [{ ...run(101, 1), run_attempt: 0 }] } }),
      error: `Review run 101 at ${H} carries no attempt number: '0'. https://github.com/${REPO}/actions/runs/101`,
    },
    {
      refusal: 'a run is still in progress',
      edit: (s) =>
        (s.routes[RUNS_ROUTE] = { body: { total_count: 1, workflow_runs: [run(101, 1, 'in_progress')] } }),
      error: `Review run 101 at ${H}, attempt 1, is status 'in_progress', not completed. https://github.com/${REPO}/actions/runs/101`,
    },
    {
      refusal: 'an attempt cannot be read',
      edit: (s) => (s.routes[attemptRoute(102, 2)] = { fail: true }),
      error: `Review run 102 at ${H}, attempt 2 of 2, could not be read. https://github.com/${REPO}/actions/runs/102`,
    },
    {
      refusal: 'a failed attempt was re-run to success',
      edit: (s) => (s.routes[attemptRoute(102, 1)] = { body: { conclusion: 'failure' } }),
      error: `Review run 102 at ${H}, attempt 1 of 2, concluded 'failure', not success. https://github.com/${REPO}/actions/runs/102`,
    },
    {
      refusal: 'the only run was cancelled',
      edit: (s) => {
        s.routes[RUNS_ROUTE] = { body: { total_count: 1, workflow_runs: [run(101, 1)] } };
        s.routes[attemptRoute(101, 1)] = { body: { conclusion: 'cancelled' } };
      },
      error: `Review run 101 at ${H}, attempt 1 of 1, concluded 'cancelled', not success. https://github.com/${REPO}/actions/runs/101`,
    },
  ];

  it.each(RELAY)(
    'fails with an error line when $refusal',
    (c) => {
      const s = passingReview(boundGroup());
      c.edit(s);
      const out = runRelay(s);
      expect(out.status, out.stderr).toBe(1);
      expect(out.stdout.split('\n')).toContain(`::error::${c.error}`);
      expect(out.posts).toHaveLength(0);
    },
    30_000,
  );
});

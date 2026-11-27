/**
 * The merge-group bind and the review relay (issue #462).
 *
 * gate-file-approval.yml and review-merge-group.yml each carry the
 * merge-group bind block, which ties a merge group commit M to the pull
 * request it was built from, and the comments in both say the two copies are
 * byte for byte the same. The first test holds them to that.
 *
 * The rest extract the `run:` script of each workflow as written and run it
 * under bash with a stub `gh` first on PATH. The stub answers each API read
 * from a fixture table and records every call, so each case sets up exactly
 * the reads the workflow makes and checks the exit status, the reason it
 * prints and the check run it posts. The cases cover a bound merge group,
 * each clause of the bind that can leave it unbound, each conclusion a review
 * attempt can carry, and each refusal of the review relay. jq and bash must
 * be on PATH, as they are on the runners.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const GATE_WORKFLOW = path.join(REPO_ROOT, '.github', 'workflows', 'gate-file-approval.yml');
const RELAY_WORKFLOW = path.join(REPO_ROOT, '.github', 'workflows', 'review-merge-group.yml');

const BIND_BEGIN = '# --- BEGIN MERGE-GROUP BIND ---';
const BIND_END = '# --- END MERGE-GROUP BIND ---';

/**
 * The literal block scalars of every `run: |` key in a workflow, with the
 * block's indentation removed and one trailing newline, as YAML reads them.
 */
function runScripts(file) {
  const lines = readFileSync(file, 'utf8').split('\n');
  const scripts = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)(?:- )?run: \|\s*$/.exec(lines[i]);
    if (!m) continue;
    const keyIndent = m[1].length;
    const body = [];
    let j = i + 1;
    for (; j < lines.length; j++) {
      const line = lines[j];
      if (line.trim() === '') {
        body.push('');
        continue;
      }
      if (line.length - line.trimStart().length <= keyIndent) break;
      body.push(line);
    }
    while (body.length && body[body.length - 1] === '') body.pop();
    const first = body.find((l) => l !== '');
    const indent = first.length - first.trimStart().length;
    scripts.push(body.map((l) => l.slice(indent)).join('\n') + '\n');
    i = j - 1;
  }
  return scripts;
}

function onlyRunScript(file) {
  const scripts = runScripts(file);
  assert.equal(scripts.length, 1, `${path.basename(file)} has one run: script`);
  return scripts[0];
}

function bindBlock(script, name) {
  const start = script.indexOf(BIND_BEGIN);
  const end = script.indexOf(BIND_END);
  assert.ok(start >= 0, `${name} has the line "${BIND_BEGIN}"`);
  assert.ok(end > start, `${name} has the line "${BIND_END}" after the first`);
  assert.equal(script.indexOf(BIND_BEGIN, start + 1), -1, `${name} has one bind block`);
  return script.slice(start, end + BIND_END.length);
}

const GATE_SCRIPT = onlyRunScript(GATE_WORKFLOW);
const RELAY_SCRIPT = onlyRunScript(RELAY_WORKFLOW);

test('the merge-group bind block is byte-identical in both workflows', () => {
  const gate = bindBlock(GATE_SCRIPT, 'gate-file-approval.yml');
  const relay = bindBlock(RELAY_SCRIPT, 'review-merge-group.yml');
  // A block this short would mean the markers moved, not that the copies agree.
  assert.ok(gate.split('\n').length > 50, 'the bind block spans the whole bind');
  if (gate !== relay) {
    const a = gate.split('\n');
    const b = relay.split('\n');
    const at = a.findIndex((line, k) => line !== b[k]);
    assert.fail(
      `the bind blocks differ at line ${at + 1} of the block:\n` +
        `  gate-file-approval.yml: ${JSON.stringify(a[at])}\n` +
        `  review-merge-group.yml: ${JSON.stringify(b[at])}`,
    );
  }
});

test('the bind block reads only its inputs and calls no API', () => {
  const block = bindBlock(RELAY_SCRIPT, 'review-merge-group.yml');
  assert.doesNotMatch(block, /(^|[^\w-])gh\s/m, 'no gh call inside the bind');
  assert.doesNotMatch(block, /\$\{\{/, 'no workflow expression inside the bind');
});

test('the review relay header says a cancelled run on the head blocks the merge group', () => {
  const lines = readFileSync(RELAY_WORKFLOW, 'utf8').split('\n');
  const header = lines
    .slice(0, lines.findIndex((l) => !l.startsWith('#')))
    .map((l) => l.replace(/^#\s?/, ''))
    .join(' ');
  assert.match(header, /A cancelled attempt is not success either/);
  assert.match(header, /no re-run and no later run on H can pass the merge group/);
  assert.match(header, /Only a new commit pushed to the pull request/);
});

// --- The stub gh -------------------------------------------------------------

// `gh api [-X METHOD] [-f key=value]... [--paginate] [--jq expr] PATH`.
// GH_STUB_FIXTURES maps "METHOD PATH" to a reply: a JSON value is the body,
// an array under "replies" is one body per call in order, and {"fail": true}
// (or no entry) exits 1 as a failed read does. A POST to check-runs with no
// entry is answered with the posted fields and an id. Every call is appended
// to GH_STUB_LOG as one JSON line.
const GH_STUB = `#!/usr/bin/env node
const fs = require('node:fs');
const cp = require('node:child_process');
const args = process.argv.slice(2);
if (args[0] !== 'api') { process.stderr.write('stub gh: only "gh api" is stubbed\\n'); process.exit(2); }
let method = 'GET';
let jq = null;
let apiPath = null;
const fields = {};
for (let i = 1; i < args.length; i++) {
  const a = args[i];
  if (a === '-X' || a === '--method') method = args[++i];
  else if (a === '-f' || a === '-F' || a === '--raw-field' || a === '--field') {
    const kv = args[++i];
    const eq = kv.indexOf('=');
    fields[kv.slice(0, eq)] = kv.slice(eq + 1);
  } else if (a === '--jq' || a === '-q') jq = args[++i];
  else if (a === '--paginate') {}
  else if (a.startsWith('-')) { process.stderr.write('stub gh: unknown flag ' + a + '\\n'); process.exit(2); }
  else apiPath = a;
}
const key = method + ' ' + apiPath;
fs.appendFileSync(process.env.GH_STUB_LOG, JSON.stringify({ key, fields }) + '\\n');
const fixtures = JSON.parse(fs.readFileSync(process.env.GH_STUB_FIXTURES, 'utf8'));
const countsFile = process.env.GH_STUB_LOG + '.counts';
const counts = fs.existsSync(countsFile) ? JSON.parse(fs.readFileSync(countsFile, 'utf8')) : {};
const n = counts[key] || 0;
counts[key] = n + 1;
fs.writeFileSync(countsFile, JSON.stringify(counts));
let reply;
if (Object.prototype.hasOwnProperty.call(fixtures, key)) {
  reply = fixtures[key];
  if (reply && typeof reply === 'object' && Array.isArray(reply.replies)) {
    reply = reply.replies[Math.min(n, reply.replies.length - 1)];
  }
} else if (method === 'POST' && /\\/check-runs$/.test(apiPath)) {
  reply = Object.assign({ id: 1000 + n }, fields);
} else {
  reply = { fail: true };
}
if (reply && typeof reply === 'object' && reply.fail === true) {
  process.stderr.write('gh: Not Found (HTTP 404)\\n');
  process.exit(1);
}
const body = JSON.stringify(reply);
if (jq === null) { process.stdout.write(body + '\\n'); process.exit(0); }
const r = cp.spawnSync('jq', ['-r', jq], { input: body, encoding: 'utf8' });
process.stdout.write(r.stdout);
process.stderr.write(r.stderr);
process.exit(r.status === 0 ? 0 : 1);
`;

let workDir;
let stubDir;
function ensureStub() {
  if (stubDir) return;
  workDir = mkdtempSync(path.join(tmpdir(), 'merge-group-bind-'));
  stubDir = path.join(workDir, 'bin');
  mkdirSync(stubDir);
  writeFileSync(path.join(stubDir, 'gh'), GH_STUB);
  chmodSync(path.join(stubDir, 'gh'), 0o755);
}
process.on('exit', () => {
  if (workDir) rmSync(workDir, { recursive: true, force: true });
});

let caseSeq = 0;
/** Runs a workflow script as the runner does (bash -e -o pipefail) against the stub. */
function runWorkflow(script, env, fixtures) {
  ensureStub();
  const dir = path.join(workDir, `case-${++caseSeq}`);
  mkdirSync(dir);
  const scriptFile = path.join(dir, 'run.sh');
  const fixturesFile = path.join(dir, 'fixtures.json');
  const logFile = path.join(dir, 'gh.log');
  writeFileSync(scriptFile, script);
  writeFileSync(fixturesFile, JSON.stringify(fixtures));
  writeFileSync(logFile, '');
  const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
    encoding: 'utf8',
    cwd: dir,
    env: {
      PATH: `${stubDir}${path.delimiter}${process.env.PATH}`,
      HOME: dir,
      GH_STUB_FIXTURES: fixturesFile,
      GH_STUB_LOG: logFile,
      ...env,
    },
  });
  const calls = readFileSync(logFile, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, calls };
}

// --- The world a bound merge group lives in -----------------------------------

const REPO = 'example-org/example-repo';
const PR = 42;
const B = '1'.repeat(40); // merge group base: the tip of main
const H = '2'.repeat(40); // pull request head
const M = '3'.repeat(40); // merge group commit
const OTHER = '4'.repeat(40);
const BLOB_A = 'a'.repeat(40);
const BLOB_B = 'b'.repeat(40);
const BLOB_C = 'c'.repeat(40);
const QUEUE_REF = `refs/heads/gh-readonly-queue/main/pr-${PR}-${B}`;
const REVIEW_PATH = '.github/workflows/pr-review.yml';
const RUNS_KEY = `GET repos/${REPO}/actions/workflows/pr-review.yml/runs?head_sha=${H}&event=pull_request&per_page=100`;
const attemptKey = (id, n) => `GET repos/${REPO}/actions/runs/${id}/attempts/${n}`;

const FILES = [
  { filename: 'packages/cli/src/index.ts', status: 'modified', sha: BLOB_A, blob_url: `https://example.test/${H}/a` },
  { filename: 'packages/cli/src/new.ts', status: 'renamed', previous_filename: 'packages/cli/src/old.ts', sha: BLOB_B },
];

const PULL = { number: PR, state: 'open', base: { ref: 'main' }, head: { sha: H }, changed_files: FILES.length };

function reviewRun(id, over = {}) {
  return {
    id,
    status: 'completed',
    run_attempt: 1,
    path: REVIEW_PATH,
    html_url: `https://example.test/runs/${id}`,
    ...over,
  };
}

function baseEnv(over = {}) {
  return {
    GH_TOKEN: 'stub-token',
    REPO,
    EVENT_NAME: 'merge_group',
    MG_HEAD_SHA: M,
    MG_BASE_SHA: B,
    MG_HEAD_REF: QUEUE_REF,
    MG_BASE_REF: 'refs/heads/main',
    ...over,
  };
}

function baseFixtures(over = {}) {
  return {
    [`GET repos/${REPO}/pulls/${PR}`]: PULL,
    [`GET repos/${REPO}/compare/${B}...${H}`]: { files: FILES },
    [`GET repos/${REPO}/compare/${B}...${M}`]: { files: FILES.map((f) => ({ ...f, blob_url: `https://example.test/${M}/x` })) },
    [`GET repos/${REPO}/commits/${M}`]: { parents: [{ sha: B }, { sha: H }] },
    [RUNS_KEY]: { total_count: 1, workflow_runs: [reviewRun(7)] },
    [attemptKey(7, 1)]: { conclusion: 'success' },
    ...over,
  };
}

const withFiles = (files) => ({ files });
const manyFiles = (n) =>
  Array.from({ length: n }, (_, k) => ({ filename: `f/${k}.txt`, status: 'added', sha: BLOB_C }));

/** The single ::error:: line a refusal prints, or null. */
function errorLine(stdout) {
  const lines = stdout.split('\n').filter((l) => l.startsWith('::error::'));
  assert.ok(lines.length <= 1, `at most one ::error:: line, got:\n${stdout}`);
  return lines.length ? lines[0].slice('::error::'.length) : null;
}

// --- The bind, through the review relay ------------------------------------

const BOUND = `Merge group commit ${M} is bound to pull request #${PR} at ${H}.`;

const BIND_CASES = [
  // Bound.
  { name: 'bound with two parents', bound: true },
  {
    name: 'bound with one parent (the queue base alone)',
    fixtures: { [`GET repos/${REPO}/commits/${M}`]: { parents: [{ sha: B }] } },
    bound: true,
  },
  {
    name: 'bound when the listings differ only in order, duplicates and URLs',
    fixtures: {
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles([FILES[1], FILES[0], FILES[0]]),
    },
    bound: true,
  },

  // The event and its payload.
  {
    name: 'unbound: the event is not merge_group',
    env: { EVENT_NAME: 'pull_request' },
    reason: "The event is 'pull_request', not merge_group.",
    reads: 0,
  },
  {
    name: 'unbound: the merge group targets another branch',
    env: { MG_BASE_REF: 'refs/heads/release' },
    reason: "The merge group targets 'refs/heads/release', not refs/heads/main.",
  },
  {
    name: 'unbound: the merge group head commit is not a full SHA',
    env: { MG_HEAD_SHA: M.slice(0, 7) },
    reason: `The merge group head commit '${M.slice(0, 7)}' is not a 40-character hexadecimal SHA.`,
  },
  {
    name: 'unbound: the merge group head commit is empty',
    env: { MG_HEAD_SHA: '' },
    reason: "The merge group head commit '' is not a 40-character hexadecimal SHA.",
  },
  {
    name: 'unbound: the merge group base commit is not a full SHA',
    env: { MG_BASE_SHA: 'G'.repeat(40) },
    reason: `The merge group base commit '${'G'.repeat(40)}' is not a 40-character hexadecimal SHA.`,
  },
  {
    name: 'unbound: the ref is not a queue ref for main',
    env: { MG_HEAD_REF: `refs/heads/gh-readonly-queue/release/pr-${PR}-${B}` },
    reason: `The merge group ref 'refs/heads/gh-readonly-queue/release/pr-${PR}-${B}' is not a queue ref for main.`,
  },
  {
    name: 'unbound: the ref names no pull request number',
    env: { MG_HEAD_REF: `refs/heads/gh-readonly-queue/main/pr-0${PR}-${B}` },
    reason: `The merge group ref 'refs/heads/gh-readonly-queue/main/pr-0${PR}-${B}' does not name a pull request number.`,
  },
  {
    name: 'unbound: the ref carries more than a number and one SHA',
    env: { MG_HEAD_REF: `${QUEUE_REF}-extra` },
    reason: `The merge group ref '${QUEUE_REF}-extra' carries more than a pull request number and one 40-character SHA.`,
  },
  {
    name: 'unbound: the ref carries a short SHA',
    env: { MG_HEAD_REF: `refs/heads/gh-readonly-queue/main/pr-${PR}-${B.slice(0, 39)}` },
    reason: `The merge group ref 'refs/heads/gh-readonly-queue/main/pr-${PR}-${B.slice(0, 39)}' carries more than a pull request number and one 40-character SHA.`,
  },

  // The pull request.
  {
    name: 'unbound: the pull request read is another number',
    fixtures: { [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, number: 43 } },
    reason: `The pull request read for the merge group is '43', not #${PR}.`,
  },
  {
    name: 'unbound: the pull request cannot be read',
    fixtures: { [`GET repos/${REPO}/pulls/${PR}`]: { fail: true } },
    reason: `The pull request read for the merge group is '', not #${PR}.`,
  },
  {
    name: 'unbound: the pull request is closed',
    fixtures: { [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, state: 'closed' } },
    reason: `Pull request #${PR} is 'closed', not open.`,
  },
  {
    name: 'unbound: the pull request targets another branch',
    fixtures: { [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, base: { ref: 'release' } } },
    reason: `Pull request #${PR} targets 'release', not main.`,
  },
  {
    name: 'unbound: the pull request has no full head commit',
    fixtures: { [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, head: { sha: H.slice(0, 12) } } },
    reason: `Pull request #${PR} has no 40-character head commit: '${H.slice(0, 12)}'.`,
  },
  {
    name: 'unbound: the pull request changes 3000 files',
    fixtures: { [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, changed_files: 3000 } },
    reason: `Pull request #${PR} changes '3000' files, not a count below the 3000-entry listing cap.`,
  },
  {
    name: 'unbound: the pull request carries no file count',
    fixtures: { [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, changed_files: null } },
    reason: `Pull request #${PR} changes '' files, not a count below the 3000-entry listing cap.`,
  },
  {
    name: 'unbound: the pull request head moved while its files were read',
    fixtures: {
      [`GET repos/${REPO}/pulls/${PR}`]: { replies: [PULL, { ...PULL, head: { sha: OTHER } }] },
    },
    reason: `Pull request #${PR} moved from ${H} to '${OTHER}' while its files were read.`,
  },

  // M's parents.
  {
    name: 'unbound: M has no parent',
    fixtures: { [`GET repos/${REPO}/commits/${M}`]: { parents: [] } },
    reason: `Merge group commit ${M} has 0 parents; one or two are expected.`,
  },
  {
    name: 'unbound: M has three parents',
    fixtures: { [`GET repos/${REPO}/commits/${M}`]: { parents: [{ sha: B }, { sha: H }, { sha: OTHER }] } },
    reason: `Merge group commit ${M} has 3 parents; one or two are expected.`,
  },
  {
    name: 'unbound: the parents of M cannot be read',
    fixtures: { [`GET repos/${REPO}/commits/${M}`]: { fail: true } },
    reason: `Merge group commit ${M} has 0 parents; one or two are expected.`,
  },
  {
    name: 'unbound: the first parent of M is not the queue base',
    fixtures: { [`GET repos/${REPO}/commits/${M}`]: { parents: [{ sha: OTHER }, { sha: H }] } },
    reason: `The first parent of ${M} is ${OTHER}, not the merge group base ${B}.`,
  },
  {
    name: 'unbound: the second parent of M is not the pull request head',
    fixtures: { [`GET repos/${REPO}/commits/${M}`]: { parents: [{ sha: B }, { sha: OTHER }] } },
    reason: `The second parent of ${M} is ${OTHER}, not the pull request head ${H}.`,
  },

  // M's changes against the pull request's.
  {
    name: "unbound: M's changes cannot be read",
    fixtures: { [`GET repos/${REPO}/compare/${B}...${M}`]: { fail: true } },
    reason: `The files ${M} changes against its base could not be read.`,
  },
  {
    name: "unbound: M's changes list a file with no blob",
    fixtures: {
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles([FILES[0], { filename: 'gone.txt', status: 'removed' }]),
    },
    reason: `The files ${M} changes against its base could not be read.`,
  },
  {
    name: "unbound: the pull request's changes cannot be read",
    fixtures: { [`GET repos/${REPO}/compare/${B}...${H}`]: { fail: true } },
    reason: `The files pull request #${PR} changes could not be read.`,
  },
  {
    name: 'unbound: the comparison of M lists 300 files',
    fixtures: {
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles(manyFiles(300)),
      [`GET repos/${REPO}/compare/${B}...${H}`]: withFiles(manyFiles(300)),
    },
    reason: `The comparison of ${M} with its base lists '300' files; at 300 the listing may be truncated.`,
  },
  {
    name: 'unbound: M changes a file the pull request does not',
    fixtures: {
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles([
        ...FILES,
        { filename: '.github/workflows/ci.yml', status: 'modified', sha: BLOB_C },
      ]),
    },
    reason: '.github/workflows/ci.yml is changed in the merge group but not in the pull request.',
  },
  {
    name: 'unbound: the pull request changes a file M does not',
    fixtures: { [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles([FILES[0]]) },
    reason: 'packages/cli/src/new.ts is changed in the pull request but not in the merge group.',
  },
  {
    name: 'unbound: a file has another status in M',
    fixtures: {
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles([{ ...FILES[0], status: 'added' }, FILES[1]]),
    },
    reason:
      'The status of packages/cli/src/index.ts is "added" in the merge group and "modified" in the pull request.',
  },
  {
    name: 'unbound: a file has another previous path in M',
    fixtures: {
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles([FILES[0], { ...FILES[1], previous_filename: 'elsewhere.ts' }]),
    },
    reason:
      'The previous path of packages/cli/src/new.ts is "elsewhere.ts" in the merge group and "packages/cli/src/old.ts" in the pull request.',
  },
  {
    name: 'unbound: a file has another blob in M',
    fixtures: {
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles([{ ...FILES[0], sha: BLOB_C }, FILES[1]]),
    },
    reason: `The blob of packages/cli/src/index.ts is "${BLOB_C}" in the merge group and "${BLOB_A}" in the pull request.`,
  },
  {
    name: 'unbound: a file name carries a newline, and the reason stays on one line',
    fixtures: {
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles([
        ...FILES,
        { filename: 'evil\n::warning::x', status: 'added', sha: BLOB_C },
      ]),
    },
    reason: 'evil ::warning::x is changed in the merge group but not in the pull request.',
  },
];

for (const c of BIND_CASES) {
  test(`review relay bind: ${c.name}`, () => {
    const r = runWorkflow(RELAY_SCRIPT, baseEnv(c.env), baseFixtures(c.fixtures));
    if (c.bound) {
      assert.equal(r.status, 0, `exit 0\n${r.stdout}${r.stderr}`);
      assert.equal(errorLine(r.stdout), null);
      assert.ok(r.stdout.split('\n').includes(BOUND), `prints the bind:\n${r.stdout}`);
    } else {
      assert.equal(r.status, 1, `exit 1\n${r.stdout}${r.stderr}`);
      assert.equal(errorLine(r.stdout), c.reason);
      assert.ok(!r.calls.some((call) => call.key.includes('/actions/')), 'no review run is read when unbound');
    }
    if (c.reads !== undefined) assert.equal(r.calls.length, c.reads, 'API reads');
  });
}

// --- The review relay ----------------------------------------------------------

const PASSED = (runs) =>
  `The review of pull request #${PR} at ${H} passed: ${runs} run(s), every attempt concluded with success.`;

const CANCELLED_HINT =
  'A cancelled run stays listed for this head, so no re-run and no later run on it can pass; push a new commit to the pull request to review a new head.';

const RELAY_CASES = [
  // Passing.
  { name: 'one run, one attempt, success', passes: 1 },
  {
    name: 'two runs, every attempt success',
    fixtures: {
      [RUNS_KEY]: { total_count: 2, workflow_runs: [reviewRun(7), reviewRun(8, { run_attempt: 3 })] },
      [attemptKey(8, 1)]: { conclusion: 'success' },
      [attemptKey(8, 2)]: { conclusion: 'success' },
      [attemptKey(8, 3)]: { conclusion: 'success' },
    },
    passes: 2,
    attempts: 4,
  },

  // Each verdict an attempt can carry other than success. A cancelled
  // attempt fails too, and says that only a new head is reviewed afresh.
  {
    name: 'an attempt concluded cancelled',
    fixtures: { [attemptKey(7, 1)]: { conclusion: 'cancelled' } },
    reason: `Review run 7 at ${H}, attempt 1 of 1, concluded 'cancelled', not success. ${CANCELLED_HINT} https://example.test/runs/7`,
  },
  {
    name: 'a cancelled run followed by a run that succeeded on the same head',
    fixtures: {
      [RUNS_KEY]: { total_count: 2, workflow_runs: [reviewRun(8), reviewRun(7)] },
      [attemptKey(7, 1)]: { conclusion: 'cancelled' },
      [attemptKey(8, 1)]: { conclusion: 'success' },
    },
    reason: `Review run 7 at ${H}, attempt 1 of 1, concluded 'cancelled', not success. ${CANCELLED_HINT} https://example.test/runs/7`,
  },
  ...['failure', 'timed_out', 'skipped', 'neutral', 'action_required', 'stale', 'startup_failure'].map(
    (verdict) => ({
      name: `an attempt concluded ${verdict}`,
      fixtures: { [attemptKey(7, 1)]: { conclusion: verdict } },
      reason: `Review run 7 at ${H}, attempt 1 of 1, concluded '${verdict}', not success. https://example.test/runs/7`,
    }),
  ),
  {
    name: 'an attempt carries no conclusion',
    fixtures: { [attemptKey(7, 1)]: { conclusion: null } },
    reason: `Review run 7 at ${H}, attempt 1 of 1, concluded 'none', not success. https://example.test/runs/7`,
  },
  {
    name: 'a failed attempt re-run to success',
    fixtures: {
      [RUNS_KEY]: { total_count: 1, workflow_runs: [reviewRun(7, { run_attempt: 2 })] },
      [attemptKey(7, 1)]: { conclusion: 'failure' },
      [attemptKey(7, 2)]: { conclusion: 'success' },
    },
    reason: `Review run 7 at ${H}, attempt 1 of 2, concluded 'failure', not success. https://example.test/runs/7`,
  },
  {
    name: 'a later run failed after an earlier one passed',
    fixtures: {
      [RUNS_KEY]: { total_count: 2, workflow_runs: [reviewRun(7), reviewRun(8)] },
      [attemptKey(8, 1)]: { conclusion: 'failure' },
    },
    reason: `Review run 8 at ${H}, attempt 1 of 1, concluded 'failure', not success. https://example.test/runs/8`,
  },

  // Each refusal of the relay.
  {
    name: 'the run list cannot be read',
    fixtures: { [RUNS_KEY]: { fail: true } },
    reason: `The review runs of pull request #${PR} at ${H} could not be read.`,
  },
  {
    name: 'the run list carries no runs array',
    fixtures: { [RUNS_KEY]: { total_count: 1 } },
    reason: `The review runs of pull request #${PR} at ${H} could not be read.`,
  },
  {
    name: 'the run list is not complete',
    fixtures: { [RUNS_KEY]: { total_count: 101, workflow_runs: [reviewRun(7)] } },
    reason: `The review runs of pull request #${PR} at ${H} list 1 runs of a total of '101'; the list is not complete.`,
  },
  {
    name: 'the run list carries no total',
    fixtures: { [RUNS_KEY]: { workflow_runs: [reviewRun(7)] } },
    reason: `The review runs of pull request #${PR} at ${H} list 1 runs of a total of ''; the list is not complete.`,
  },
  {
    name: 'no run is listed',
    fixtures: { [RUNS_KEY]: { total_count: 0, workflow_runs: [] } },
    reason: `No run of ${REVIEW_PATH} is listed for pull request #${PR} at ${H}.`,
  },
  {
    name: 'no listed run is of pr-review.yml',
    fixtures: {
      [RUNS_KEY]: { total_count: 1, workflow_runs: [reviewRun(7, { path: '.github/workflows/other.yml' })] },
    },
    reason: `No run of ${REVIEW_PATH} is listed for pull request #${PR} at ${H}.`,
  },
  {
    name: 'a run carries no id',
    fixtures: { [RUNS_KEY]: { total_count: 2, workflow_runs: [reviewRun(7), reviewRun(0)] } },
    reason: `Run 2 of the review runs of pull request #${PR} at ${H} carries no run id: '0'.`,
  },
  {
    name: 'a run carries no attempt number',
    fixtures: { [RUNS_KEY]: { total_count: 1, workflow_runs: [reviewRun(7, { run_attempt: 0 })] } },
    reason: `Review run 7 at ${H} carries no attempt number: '0'. https://example.test/runs/7`,
  },
  {
    name: 'a run carries an attempt number too large to walk',
    fixtures: { [RUNS_KEY]: { total_count: 1, workflow_runs: [reviewRun(7, { run_attempt: 1e10 })] } },
    reason: `Review run 7 at ${H} carries no attempt number: '10000000000'. https://example.test/runs/7`,
  },
  {
    name: 'a run is still in progress',
    fixtures: { [RUNS_KEY]: { total_count: 1, workflow_runs: [reviewRun(7, { status: 'in_progress' })] } },
    reason: `Review run 7 at ${H}, attempt 1, is status 'in_progress', not completed. https://example.test/runs/7`,
  },
  {
    name: 'a run carries no status',
    fixtures: { [RUNS_KEY]: { total_count: 1, workflow_runs: [reviewRun(7, { status: null })] } },
    reason: `Review run 7 at ${H}, attempt 1, is status 'none', not completed. https://example.test/runs/7`,
  },
  {
    name: 'an attempt cannot be read',
    fixtures: { [attemptKey(7, 1)]: { fail: true } },
    reason: `Review run 7 at ${H}, attempt 1 of 1, could not be read. https://example.test/runs/7`,
  },
];

for (const c of RELAY_CASES) {
  test(`review relay verdict: ${c.name}`, () => {
    const r = runWorkflow(RELAY_SCRIPT, baseEnv(), baseFixtures(c.fixtures));
    assert.ok(r.stdout.split('\n').includes(BOUND), `the merge group is bound first:\n${r.stdout}${r.stderr}`);
    if (c.passes) {
      assert.equal(r.status, 0, `exit 0\n${r.stdout}${r.stderr}`);
      assert.equal(errorLine(r.stdout), null);
      assert.ok(r.stdout.split('\n').includes(PASSED(c.passes)), `prints the pass:\n${r.stdout}`);
      const read = r.calls.filter((call) => call.key.includes('/attempts/')).length;
      assert.equal(read, c.attempts ?? 1, 'every attempt is read');
    } else {
      assert.equal(r.status, 1, `exit 1\n${r.stdout}${r.stderr}`);
      assert.equal(errorLine(r.stdout), c.reason);
    }
    assert.ok(
      r.calls.every((call) => call.key.startsWith('GET ')),
      'the relay writes nothing',
    );
  });
}

// --- The bind, through the gate ------------------------------------------------

const CHECK_RUNS = `POST repos/${REPO}/check-runs`;
const GATE_FILES = [
  { filename: '.github/workflows/ci.yml', status: 'modified', sha: BLOB_C },
  { filename: 'README.md', status: 'modified', sha: BLOB_A },
];

function gateFixtures(over = {}) {
  return baseFixtures({ [`GET repos/${REPO}/pulls/${PR}/reviews`]: [], ...over });
}

const GATE_CASES = [
  {
    name: 'unbound: the failure names the clause',
    fixtures: { [`GET repos/${REPO}/commits/${M}`]: { parents: [{ sha: OTHER }] } },
    passes: false,
    conclusion: 'failure',
    title: 'Merge group not bound to its pull request',
    summary: `The first parent of ${M} is ${OTHER}, not the merge group base ${B}.`,
  },
  {
    name: 'unbound: the pull request cannot be read',
    fixtures: { [`GET repos/${REPO}/pulls/${PR}`]: { fail: true } },
    passes: false,
    conclusion: 'failure',
    title: 'Merge group not bound to its pull request',
    summary: `The pull request read for the merge group is '', not #${PR}.`,
  },
  {
    name: 'bound, no gate file touched',
    passes: true,
    conclusion: 'success',
    title: 'No gate files touched',
  },
  {
    name: 'bound, a gate file touched and approved on the head',
    fixtures: {
      [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, changed_files: GATE_FILES.length },
      [`GET repos/${REPO}/compare/${B}...${H}`]: withFiles(GATE_FILES),
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles(GATE_FILES),
      [`GET repos/${REPO}/pulls/${PR}/reviews`]: [
        { state: 'APPROVED', commit_id: H, user: { login: 'thebenignhacker', type: 'User' } },
      ],
    },
    passes: true,
    conclusion: 'success',
    title: 'Gate-file change approved',
  },
  {
    name: 'bound, a gate file touched without approval fails in the queue',
    fixtures: {
      [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, changed_files: GATE_FILES.length },
      [`GET repos/${REPO}/compare/${B}...${H}`]: withFiles(GATE_FILES),
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles(GATE_FILES),
      [`GET repos/${REPO}/pulls/${PR}/reviews`]: [
        { state: 'APPROVED', commit_id: OTHER, user: { login: 'thebenignhacker', type: 'User' } },
      ],
    },
    passes: false,
    conclusion: 'failure',
    title: 'Gate-file change needs approval',
  },
  {
    name: 'bound, but the bound list is not the whole pull request',
    fixtures: { [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, changed_files: FILES.length + 1 } },
    passes: false,
    conclusion: 'failure',
    title: 'Merge group file count differs from its pull request',
  },
  {
    name: 'bound, a read after the bind fails',
    fixtures: {
      [`GET repos/${REPO}/pulls/${PR}`]: { ...PULL, changed_files: GATE_FILES.length },
      [`GET repos/${REPO}/compare/${B}...${H}`]: withFiles(GATE_FILES),
      [`GET repos/${REPO}/compare/${B}...${M}`]: withFiles(GATE_FILES),
      [`GET repos/${REPO}/pulls/${PR}/reviews`]: { fail: true },
    },
    passes: false,
    conclusion: 'failure',
    title: 'Merge group verdict could not be evaluated',
  },
];

for (const c of GATE_CASES) {
  test(`gate bind: ${c.name}`, () => {
    const r = runWorkflow(GATE_SCRIPT, baseEnv({ PR_NUMBER: '', HEAD_SHA: '', REVIEW_AUTHOR: '' }), gateFixtures(c.fixtures));
    // A failure exits non-zero: 1 where the step exits itself, the failed
    // command's status where the exit trap posts.
    if (c.passes) assert.equal(r.status, 0, `exit 0\n${r.stdout}${r.stderr}`);
    else assert.notEqual(r.status, 0, `exit non-zero\n${r.stdout}${r.stderr}`);
    const posts = r.calls.filter((call) => call.key === CHECK_RUNS);
    assert.equal(posts.length, 1, 'M receives exactly one check run');
    const post = posts[0].fields;
    assert.equal(post.name, 'Gate file approval');
    assert.equal(post.head_sha, M, 'the check run is posted on M');
    assert.equal(post.conclusion, c.conclusion);
    assert.equal(post['output[title]'], c.title);
    if (c.summary !== undefined) assert.equal(post['output[summary]'], c.summary);
    assert.ok(
      r.calls.every((call) => call.key.startsWith('GET ') || call.key === CHECK_RUNS),
      'the gate posts nothing but its check run',
    );
  });
}

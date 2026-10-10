/**
 * The published-artifact advisory incident.
 *
 * The weekly PUBLISHED consumer-resolution audit measures a tree no pull request
 * can change: what a user installing `opena2a-cli` from npm resolves today. When
 * it fails, that fact lives in a scheduled run's log, a surface nobody is
 * subscribed to. `scripts/advisory-incident.mjs` turns the failing run into ONE
 * issue labelled `published-artifact-advisory` and closes it when the audit
 * passes again.
 *
 * What this file measures:
 *
 *   the record    built from the COMBINED stdout and stderr of the audit: the
 *                 resolved version is written with `console.log` and the
 *                 advisory ids with `console.error`, so the captures below are
 *                 two named halves joined, and a parser that reads one half
 *                 fails here.
 *
 *   the capture   is untrusted. The audit installs a registry tree, and npm's
 *                 stderr and a publisher's deprecation text end up in the file.
 *                 Nothing from it may leave the quoted block as markup, close
 *                 the block early, or stop the issue from being filed.
 *
 *   the writes    exactly one create when no labelled issue is open, a comment
 *                 when one is, a failure when two are, and none at all for a
 *                 capture of the CANDIDATE artifact.
 *
 * No test here reaches GitHub or runs the real `gh`. In-process tests inject the
 * issues client. Tests that start the script give it a PATH holding one stand-in
 * `gh` that records its arguments, so "gh was never started" is read off a file
 * and not assumed.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'advisory-incident.mjs');
const AUDIT_SCRIPT = path.join(REPO_ROOT, 'scripts', 'audit-consumer-resolution.mjs');

const LABEL = 'published-artifact-advisory';
const ASSIGNEE = 'thebenignhacker';
const RUN_URL = 'https://github.com/opena2a-org/opena2a/actions/runs/17482910463';
const TITLE = 'Published-artifact consumer audit failing: opena2a-cli@';

/**
 * Imported per test, not at file scope: while the module is absent a file-scope
 * import fails the whole file as one unnamed error, and imported here each test
 * fails under its own name.
 */
const incident = () => import(pathToFileURL(SCRIPT).href);

// --- Captures --------------------------------------------------------------
//
// These mirror what audit-consumer-resolution.mjs prints, and one test below
// holds them to that script's own source, so a change of wording on either side
// fails here and does not file an incident titled `opena2a-cli@unknown`.

const ADVISORY_HIGH = 'GHSA-xcpc-8h2w-3j85';
const ADVISORY_CRITICAL = 'GHSA-7fh5-64p2-3v2j';
const RESOLVED_VERSION = '0.10.13';
const PACKAGE_COUNT = '412';

/** What `npm run` writes before the script starts. */
const NPM_PREAMBLE = ['', '> opena2a@0.1.0 audit:consumer', '> node scripts/audit-consumer-resolution.mjs', '', ''].join('\n');

/** The `console.log` half: the banner, the resolved line, the counts. */
const PUBLISHED_STDOUT = [
  '[PUBLISHED] PUBLISHED artifact — the tree a user resolves from npm right now',
  '[PUBLISHED] Has the already-shipped tree drifted into an advisory since release?',
  '[PUBLISHED] Target: opena2a-cli@latest',
  '',
  `[PUBLISHED] Resolved opena2a-cli@${RESOLVED_VERSION} — ${PACKAGE_COUNT} packages in the production closure`,
  '',
  'Consumer resolution: 1 critical, 1 high, 3 moderate, 0 low',
  '',
].join('\n');

function unlisted(severity, id, via) {
  return [
    `  - Unlisted ${severity} advisory in the consumer tree: ${id} (via ${via}).`,
    '    A user installing opena2a-cli inherits it. Either raise the floor to a patched version,',
    '    drop the dependency, or add it to ALLOWED in scripts/audit-consumer-resolution.mjs.',
    '',
  ];
}

const FAILED_BANNER =
  '[PUBLISHED] Consumer-resolution audit FAILED — PUBLISHED artifact — the tree a user resolves from npm right now:';

/** The `console.error` half: the FAILED banner and every failure entry. */
const PUBLISHED_STDERR = [
  '',
  FAILED_BANNER,
  '',
  ...unlisted('high', ADVISORY_HIGH, 'adm-zip'),
  ...unlisted('critical', ADVISORY_CRITICAL, 'onnxruntime-node, hackmyagent'),
  '  This is the PUBLISHED run. It measured what users can install right now, so a',
  '  failure here is NOT fixable by merging — it clears when a fix is released.',
  '',
].join('\n');

/** The file a `2>&1 | tee` leaves behind: both halves, one file. */
const PUBLISHED_CAPTURE = `${NPM_PREAMBLE}${PUBLISHED_STDOUT}${PUBLISHED_STDERR}`;

/** What the audit writes when it throws before measuring anything. */
const UNMEASURED_REASON =
  'npm install --omit=dev --ignore-scripts failed: request to registry.npmjs.org failed, reason: getaddrinfo EAI_AGAIN';
const UNMEASURED_CAPTURE = [
  NPM_PREAMBLE,
  '[PUBLISHED] PUBLISHED artifact — the tree a user resolves from npm right now',
  '[PUBLISHED] Target: opena2a-cli@latest',
  '',
  FAILED_BANNER,
  '',
  '  - The consumer tree was not measured, so this run produced no result:',
  `    ${UNMEASURED_REASON}`,
  '',
].join('\n');

/** The other artifact: a pull request's run, which never files an incident. */
const CANDIDATE_CAPTURE = [
  NPM_PREAMBLE,
  '[CANDIDATE] CANDIDATE artifact — the tree a user would resolve from THIS BRANCH',
  '[CANDIDATE] Target: /home/runner/work/_temp/candidate/opena2a-cli-0.10.14.tgz',
  '',
  '[CANDIDATE] Resolved opena2a-cli@0.10.14 — 413 packages in the production closure',
  '',
  '[CANDIDATE] Consumer-resolution audit FAILED — CANDIDATE artifact — the tree a user would resolve from THIS BRANCH:',
  '',
  ...unlisted('high', ADVISORY_HIGH, 'adm-zip'),
].join('\n');

function publishedCaptureWith(stderrLines) {
  return `${NPM_PREAMBLE}${PUBLISHED_STDOUT}\n${FAILED_BANNER}\n\n${stderrLines.join('\n')}\n`;
}

// --- The injected issues client -------------------------------------------

const READ = 'listOpenLabelled';

/**
 * Stands in for the forge. It answers one question, which OPEN issues carry the
 * label, and records every call, so "performs zero writes" and "performs exactly
 * one create" are counted.
 */
function fakeClient(open, { failOn } = {}) {
  const calls = [];
  let nextNumber = 900;
  const record = (method, args) => {
    calls.push({ method, args });
    if (method === failOn) throw new Error(`${method} refused`);
  };
  return {
    calls,
    writes: () => calls.filter((c) => c.method !== READ),
    of: (method) => calls.filter((c) => c.method === method),
    listOpenLabelled(label) {
      record(READ, [label]);
      // A copy, so the module cannot mutate the fixture into agreement.
      return open.map((issue) => ({ ...issue }));
    },
    createIssue(issue) {
      record('createIssue', [issue]);
      return { number: nextNumber++ };
    },
    commentIssue(number, body) {
      record('commentIssue', [number, body]);
    },
    setIssueTitle(number, title) {
      record('setIssueTitle', [number, title]);
    },
    closeIssue(number) {
      record('closeIssue', [number]);
    },
  };
}

function fakeLog() {
  const out = [];
  const err = [];
  return {
    out: (line) => void out.push(line),
    err: (line) => void err.push(line),
    stdout: () => out.join('\n'),
    stderr: () => err.join('\n'),
  };
}

// --- Starting the script ---------------------------------------------------

/**
 * A `gh` that records its arguments (one call per line, tab-separated) and the
 * body it was given on stdin, then answers like the real one. It is the only
 * program on the PATH the script is started with.
 */
const GH_STAND_IN = [
  '#!/bin/sh',
  "IFS='\t'",
  'printf \'%s\\n\' "$*" >> "$GH_STAND_IN_DIR/calls.log"',
  'case "$1 $2" in',
  "  'issue list') printf '%s\\n' \"$GH_STAND_IN_OPEN\" ;;",
  "  'issue create')",
  '    /bin/cat > "$GH_STAND_IN_DIR/create.body"',
  '    if [ "$GH_STAND_IN_CREATE_EXIT" != 0 ]; then',
  '      echo "could not assign user: not found" >&2',
  '      exit "$GH_STAND_IN_CREATE_EXIT"',
  '    fi',
  "    echo 'https://github.com/example/none/issues/7' ;;",
  "  'issue comment') /bin/cat > \"$GH_STAND_IN_DIR/comment.body\" ;;",
  "  'issue edit' | 'issue close') ;;",
  '  *) exit 64 ;;',
  'esac',
  '',
].join('\n');

const NO_SHELL = process.platform === 'win32' ? 'needs a POSIX shell for the stand-in gh, and symlinks' : false;

function sandbox(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'advisory-incident-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = path.join(dir, 'bin');
  const state = path.join(dir, 'gh-state');
  mkdirSync(bin);
  mkdirSync(state);
  writeFileSync(path.join(bin, 'gh'), GH_STAND_IN, { mode: 0o755 });
  return {
    dir,
    file(name, content) {
      const file = path.join(dir, name);
      writeFileSync(file, content);
      return file;
    },
    /** Every `gh` call the script made, as argument lists. */
    ghCalls() {
      const log = path.join(state, 'calls.log');
      if (!existsSync(log)) return [];
      return readFileSync(log, 'utf-8').trimEnd().split('\n').map((line) => line.split('\t'));
    },
    stdinOf: (command) => readFileSync(path.join(state, `${command}.body`), 'utf-8'),
    run(args, { open = '[]', createExit = '0', entry = SCRIPT } = {}) {
      return spawnSync(process.execPath, [entry, ...args], {
        encoding: 'utf-8',
        env: {
          PATH: bin,
          HOME: dir,
          GITHUB_REPOSITORY: 'example/none',
          GH_STAND_IN_DIR: state,
          GH_STAND_IN_OPEN: open,
          GH_STAND_IN_CREATE_EXIT: createExit,
        },
      });
    },
  };
}

function longestBacktickRun(text) {
  return Math.max(0, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
}

// --- The record ------------------------------------------------------------

test('one record from the combined capture: title, label, assignee, and a body naming the run, the version and every advisory', async () => {
  const { buildIncidentRecord } = await incident();
  const record = buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL });

  assert.equal(record.title, `${TITLE}${RESOLVED_VERSION}`);
  assert.deepEqual(record.labels, [LABEL]);
  assert.deepEqual(record.assignees, [ASSIGNEE]);
  for (const fact of [RUN_URL, `opena2a-cli@${RESOLVED_VERSION}`, PACKAGE_COUNT, ADVISORY_HIGH, ADVISORY_CRITICAL]) {
    assert.ok(record.body.includes(fact), `the body does not carry ${fact}`);
  }
});

test('the parser names every advisory in the capture once, and only the ids', async () => {
  const { parseAuditCapture } = await incident();
  const repeated = publishedCaptureWith([
    ...unlisted('high', ADVISORY_HIGH, 'adm-zip'),
    ...unlisted('critical', ADVISORY_CRITICAL, 'onnxruntime-node, hackmyagent'),
    ...unlisted('high', ADVISORY_HIGH, 'adm-zip'),
  ]);
  const parsed = parseAuditCapture(repeated);

  // Not the severity, not the packages it lands on, not the sentence after it.
  assert.deepEqual(parsed.advisoryIds, [ADVISORY_HIGH, ADVISORY_CRITICAL]);
  assert.equal(parsed.withheldAdvisoryLines, 0);
  assert.equal(parsed.mode, 'PUBLISHED');
  assert.equal(parsed.name, 'opena2a-cli');
  assert.equal(parsed.version, RESOLVED_VERSION);
  assert.equal(parsed.packageCount, PACKAGE_COUNT);
});

test('the stdout half alone names no advisory: the combined file is what the record needs', async () => {
  const { buildIncidentRecord } = await incident();
  const stdoutOnly = buildIncidentRecord({ capture: PUBLISHED_STDOUT, runUrl: RUN_URL });
  const combined = buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL });

  assert.ok(!stdoutOnly.body.includes(ADVISORY_HIGH));
  assert.ok(combined.body.includes(ADVISORY_HIGH));
  assert.equal(combined.title, stdoutOnly.title);
});

test('the shapes it parses are the shapes the audit script writes', async () => {
  const source = readFileSync(AUDIT_SCRIPT, 'utf-8');
  for (const template of [
    '`[${target.mode}] Resolved ${liveness.rootName}@${liveness.rootVersion} — `',
    '`${liveness.packageCount} packages in the production closure\\n`',
    '`Unlisted ${adv.severity} advisory in the consumer tree: ${adv.id} `',
    "`(via ${[...adv.packages].join(', ')}).\\n`",
    '`The consumer tree was not measured, so this run produced no result:\\n',
    '`\\n[${target.mode}] Consumer-resolution audit FAILED — ${target.headline}:\\n`',
    '`[${target.mode}] Consumer-resolution audit passed (${rootName}).`',
  ]) {
    assert.ok(source.includes(template), `audit-consumer-resolution.mjs no longer writes ${template}`);
  }
});

test('a capture with no resolved line invents no version and carries the failure text', async () => {
  const { buildIncidentRecord } = await incident();
  const record = buildIncidentRecord({ capture: UNMEASURED_CAPTURE, runUrl: RUN_URL });

  assert.equal(record.title, `${TITLE}unknown`);
  assert.ok(record.body.includes('The consumer tree was not measured, so this run produced no result:'));
  assert.ok(record.body.includes(UNMEASURED_REASON));
  assert.ok(record.body.includes(RUN_URL));
});

test('a capture with no banner at all still yields a record: a failed run reaches a reader whatever it printed', async () => {
  const { buildIncidentRecord, parseAuditCapture } = await incident();
  const crash = `${NPM_PREAMBLE}SyntaxError: Unexpected token\n    at file:///scripts/audit-consumer-resolution.mjs:1\n`;

  assert.equal(parseAuditCapture(crash).mode, null);
  for (const capture of [crash, '']) {
    const record = buildIncidentRecord({ capture, runUrl: RUN_URL });
    assert.equal(record.title, `${TITLE}unknown`);
    assert.ok(record.body.includes(RUN_URL));
  }
  assert.ok(buildIncidentRecord({ capture: crash, runUrl: RUN_URL }).body.includes('SyntaxError: Unexpected token'));
});

test('the title pairs opena2a-cli with a version only when the audit resolved opena2a-cli', async () => {
  const { buildIncidentRecord } = await incident();
  const other = PUBLISHED_CAPTURE.replace('Resolved opena2a-cli@', 'Resolved some-other-package@');
  const record = buildIncidentRecord({ capture: other, runUrl: RUN_URL });

  assert.equal(record.title, `${TITLE}unknown`);
  assert.ok(record.body.includes(`some-other-package@${RESOLVED_VERSION}`));
});

test('a run that failed after the audit passed is filed, and the record says the audit passed', async () => {
  const { buildIncidentRecord } = await incident();
  const passed = `${NPM_PREAMBLE}${PUBLISHED_STDOUT}[PUBLISHED] Consumer-resolution audit passed (opena2a-cli).\n`;

  const record = buildIncidentRecord({ capture: passed, runUrl: RUN_URL });
  assert.equal(record.title, `${TITLE}${RESOLVED_VERSION}`);
  assert.match(record.body, /The output shows the audit passing/);

  const failed = buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL });
  assert.doesNotMatch(failed.body, /The output shows the audit passing/);
  // A pass line beside a failure banner is not a pass.
  const both = buildIncidentRecord({ capture: `${PUBLISHED_CAPTURE}${passed}`, runUrl: RUN_URL });
  assert.doesNotMatch(both.body, /The output shows the audit passing/);
});

// --- The capture is untrusted ----------------------------------------------

test('a quoted capture cannot close its own block: the fence is longer than any backtick run inside it', async () => {
  const { buildIncidentRecord, buildFollowUpComment, parseAuditCapture } = await incident();
  const capture = publishedCaptureWith([
    ...unlisted('high', ADVISORY_HIGH, 'adm-zip'),
    'npm warn deprecated left-pad@1.3.0: use `String.prototype.padStart()`',
    '```',
    '@everyone this text would render as markup outside the block',
    '`````',
    '[a link](https://example.invalid/outside-the-block)',
  ]);
  const { excerpt } = parseAuditCapture(capture);
  assert.equal(longestBacktickRun(excerpt), 5);

  const fence = '`'.repeat(6);
  for (const text of [
    buildIncidentRecord({ capture, runUrl: RUN_URL }).body,
    buildFollowUpComment({ capture, runUrl: RUN_URL }),
  ]) {
    // The block opens on the fence, holds the whole excerpt, and nothing
    // follows the closing fence.
    assert.ok(text.endsWith(`\n${fence}\n${excerpt}\n${fence}`), 'the excerpt is not the last thing inside one fence');
    assert.equal(text.split('\n').filter((line) => line === fence).length, 2);
  }

  // The ordinary case keeps the ordinary fence.
  const plain = buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL }).body;
  assert.ok(plain.endsWith('\n```'));
});

test('nothing from the capture is repeated outside the quoted block unless it is a plain version or advisory id', async () => {
  const { buildIncidentRecord, parseAuditCapture } = await incident();
  const hostileId = '[GHSA-xcpc-8h2w-3j85](https://example.invalid/x)';
  const capture = [
    NPM_PREAMBLE,
    '[PUBLISHED] Resolved opena2a-cli@1.0.0](https://example.invalid/v) — 412 packages in the production closure',
    '',
    FAILED_BANNER,
    '',
    ...unlisted('high', hostileId, 'adm-zip'),
    ...unlisted('high', '@some-org/some-team', 'adm-zip'),
    ...unlisted('critical', ADVISORY_CRITICAL, 'hackmyagent'),
  ].join('\n');

  const parsed = parseAuditCapture(capture);
  assert.equal(parsed.version, null);
  assert.deepEqual(parsed.advisoryIds, [ADVISORY_CRITICAL]);
  assert.equal(parsed.withheldAdvisoryLines, 2);

  const record = buildIncidentRecord({ capture, runUrl: RUN_URL });
  assert.equal(record.title, `${TITLE}unknown`);
  const beforeBlock = record.body.slice(0, record.body.indexOf('\n```\n'));
  assert.ok(!beforeBlock.includes('example.invalid'));
  assert.ok(!beforeBlock.includes('@some-org'));
  // A line it will not repeat is still counted, never dropped silently.
  assert.match(beforeBlock, /2 advisory lines/);
  assert.ok(record.body.includes(hostileId), 'the quoted block still carries the line as written');

  // A scoped package name begins with `@`. It is a well-formed name, so it is
  // repeated, and only inside a code span, where it notifies nobody.
  const scoped = PUBLISHED_CAPTURE.replace('Resolved opena2a-cli@', 'Resolved @some-org/some-team@');
  const scopedBody = buildIncidentRecord({ capture: scoped, runUrl: RUN_URL }).body;
  assert.ok(scopedBody.includes(`\`@some-org/some-team@${RESOLVED_VERSION}\``));
  assert.equal(scopedBody.slice(0, scopedBody.indexOf('\n```\n')).split('@some-org').length, 2);
});

test('control characters and colour codes never reach the record, and a long capture is bounded', async () => {
  const { buildIncidentRecord, parseAuditCapture, EXCERPT_LIMIT } = await incident();
  const noisy = PUBLISHED_CAPTURE.replace(FAILED_BANNER, `\u001b[31m${FAILED_BANNER}\u001b[0m\u0000\u0007`).replace(/\n/g, '\r\n');
  const record = buildIncidentRecord({ capture: noisy, runUrl: RUN_URL });

  assert.doesNotMatch(record.body, /[\u0000-\u0008\u000b-\u001f\u007f]/);
  assert.ok(record.body.includes(`\n${FAILED_BANNER}\n`));
  assert.equal(record.title, `${TITLE}${RESOLVED_VERSION}`);

  const many = [];
  for (let i = 0; i < 1000; i++) many.push(...unlisted('high', `GHSA-${String(i).padStart(4, '0')}-aaaa-bbbb`, 'adm-zip'));
  const flood = publishedCaptureWith(many);
  const parsed = parseAuditCapture(flood);
  assert.equal(parsed.advisoryIds.length, 1000);
  assert.ok(parsed.excerpt.length <= EXCERPT_LIMIT + 200);

  // GitHub refuses an issue body over 65536 characters, and a refused body is
  // an incident that was never filed.
  const body = buildIncidentRecord({ capture: flood, runUrl: RUN_URL }).body;
  assert.ok(body.length < 65536, `body is ${body.length} characters`);
  assert.match(body, /and \d+ more in the output below/);
  assert.ok(body.startsWith('The scheduled'));
});

test('the fixed text of the record carries no role tag, ticket id or link other than the run', async () => {
  const { buildIncidentRecord, buildFollowUpComment, buildResolutionComment } = await incident();
  // Three shapes that mark text as written for the maintainers' own tooling.
  const markers = (text) =>
    [
      ...text.matchAll(/\[[A-Z][A-Z0-9]*-[A-Z0-9]+\]/g),
      ...text.matchAll(/\b[A-Z]{2,6}-\d+\b/g),
      ...text.split(RUN_URL).join('').matchAll(/\bhttps?:\/\/\S+/g),
    ].length;

  // A capture with nothing in it but a resolved line, so what is measured is
  // the text this script writes and not the text an audit happened to print.
  const capture = '[PUBLISHED] Resolved opena2a-cli@1.2.3 — 10 packages in the production closure\n';
  const texts = [
    buildIncidentRecord({ capture, runUrl: RUN_URL }).body,
    buildFollowUpComment({ capture, runUrl: RUN_URL }),
    buildResolutionComment(RUN_URL),
  ];
  for (const text of texts) {
    assert.equal(markers(text), 0, text);
    // The control: the same count over the same text with one tag planted.
    assert.equal(markers(`${text}\n[ROLE-X]`), 1);
  }
});

test('a run URL that is not an https link to one Actions run is refused', async () => {
  const { buildIncidentRecord, buildResolutionComment } = await incident();
  for (const runUrl of [
    undefined,
    '',
    'http://github.com/opena2a-org/opena2a/actions/runs/1',
    'https://github.com/opena2a-org/opena2a/actions/runs/',
    'https://github.com/opena2a-org/opena2a/actions/runs/1 [x](https://example.invalid)',
    'https://github.com/opena2a-org/opena2a/issues/1',
  ]) {
    assert.throws(() => buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl }), /--run-url/, String(runUrl));
    assert.throws(() => buildResolutionComment(runUrl), /--run-url/, String(runUrl));
  }
});

// --- The writes ------------------------------------------------------------

test('a CANDIDATE capture performs no client call of any kind and exits non-zero', async () => {
  const { openIncident } = await incident();
  const client = fakeClient([]);
  const log = fakeLog();

  const code = await openIncident({ capture: CANDIDATE_CAPTURE, runUrl: RUN_URL, client, log });

  assert.notEqual(code, 0);
  assert.match(log.stderr(), /CANDIDATE/);
  assert.deepEqual(client.calls, []);
});

test('with no open labelled issue: exactly one create, and no other write', async () => {
  const { openIncident, buildIncidentRecord } = await incident();
  const client = fakeClient([]);

  const code = await openIncident({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL, client, log: fakeLog() });

  assert.equal(code, 0);
  assert.equal(client.writes().length, 1);
  assert.deepEqual(client.of('createIssue')[0].args, [buildIncidentRecord({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL })]);
  // The open set is read through the label, once.
  assert.deepEqual(client.of(READ).map((c) => c.args), [[LABEL]]);
});

test('with exactly one open: one comment on that issue, its title moved to this run, zero creates', async () => {
  const { openIncident } = await incident();
  const client = fakeClient([{ number: 41, title: `${TITLE}0.10.11` }]);

  const code = await openIncident({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL, client, log: fakeLog() });

  assert.equal(code, 0);
  assert.deepEqual(client.of('createIssue'), []);
  assert.equal(client.of('commentIssue').length, 1);
  const [number, body] = client.of('commentIssue')[0].args;
  assert.equal(number, 41);
  for (const fact of [RUN_URL, `opena2a-cli@${RESOLVED_VERSION}`, ADVISORY_HIGH, ADVISORY_CRITICAL]) {
    assert.ok(body.includes(fact), `the comment does not carry ${fact}`);
  }
  assert.deepEqual(client.of('setIssueTitle').map((c) => c.args), [[41, `${TITLE}${RESOLVED_VERSION}`]]);
  assert.deepEqual(client.of('closeIssue'), []);
});

test('with two or more open: comments the lowest number, creates nothing, exits non-zero naming the invariant', async () => {
  const { openIncident } = await incident();
  const client = fakeClient([
    { number: 57, title: `${TITLE}0.10.12` },
    { number: 41, title: `${TITLE}0.10.11` },
  ]);
  const log = fakeLog();

  const code = await openIncident({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL, client, log });

  assert.notEqual(code, 0);
  assert.deepEqual(client.of('createIssue'), []);
  assert.deepEqual(client.of('commentIssue').map((c) => c.args[0]), [41]);
  assert.match(log.stderr(), /at most one open issue/);
  assert.match(log.stderr(), /#41, #57/);
});

test('a refused create is a failed open, never a quiet success', async () => {
  const { openIncident } = await incident();
  const client = fakeClient([], { failOn: 'createIssue' });

  await assert.rejects(
    openIncident({ capture: PUBLISHED_CAPTURE, runUrl: RUN_URL, client, log: fakeLog() }),
    /createIssue refused/
  );
});

test('resolve closes every open labelled issue with a comment naming the run', async () => {
  const { resolveIncident } = await incident();
  const client = fakeClient([
    { number: 57, title: `${TITLE}0.10.12` },
    { number: 41, title: `${TITLE}0.10.11` },
  ]);

  const code = await resolveIncident({ runUrl: RUN_URL, client, log: fakeLog() });

  assert.equal(code, 0);
  assert.deepEqual(client.of('closeIssue').map((c) => c.args[0]), [41, 57]);
  assert.deepEqual(client.of('commentIssue').map((c) => c.args[0]), [41, 57]);
  for (const call of client.of('commentIssue')) {
    assert.ok(call.args[1].includes(RUN_URL));
    assert.match(call.args[1], /passed/);
  }
  assert.deepEqual(client.of('createIssue'), []);
  assert.deepEqual(client.of(READ).map((c) => c.args), [[LABEL]]);
});

test('resolve performs zero writes and exits 0 when no labelled issue is open', async () => {
  const { resolveIncident } = await incident();
  const client = fakeClient([]);

  assert.equal(await resolveIncident({ runUrl: RUN_URL, client, log: fakeLog() }), 0);
  assert.deepEqual(client.writes(), []);
});

// --- The gh client ---------------------------------------------------------

test('the gh client passes every value as its own argument and every body on stdin', async () => {
  const { ghIssuesClient } = await incident();
  const calls = [];
  const answers = {
    list: JSON.stringify([{ number: 41, title: 't', url: 'ignored' }]),
    create: 'https://github.com/example/none/issues/912\n',
  };
  const client = ghIssuesClient({
    exec: (args, input) => {
      calls.push({ args, input });
      return answers[args[1]] ?? '';
    },
    repo: () => 'example/none',
  });
  const repo = ['--repo', 'example/none'];

  assert.deepEqual(client.listOpenLabelled(LABEL), [{ number: 41, title: 't' }]);
  assert.deepEqual(client.createIssue({ title: 'a title', body: 'a body', labels: [LABEL], assignees: [ASSIGNEE] }), {
    number: 912,
  });
  client.commentIssue(41, 'a comment');
  client.setIssueTitle(41, 'a new title');
  client.closeIssue(41);

  assert.deepEqual(calls, [
    {
      args: ['issue', 'list', ...repo, '--state', 'open', '--label', LABEL, '--json', 'number,title', '--limit', '100'],
      input: undefined,
    },
    {
      args: ['issue', 'create', ...repo, '--title', 'a title', '--body-file', '-', '--label', LABEL, '--assignee', ASSIGNEE],
      input: 'a body',
    },
    { args: ['issue', 'comment', '41', ...repo, '--body-file', '-'], input: 'a comment' },
    { args: ['issue', 'edit', '41', ...repo, '--title', 'a new title'], input: undefined },
    { args: ['issue', 'close', '41', ...repo], input: undefined },
  ]);
});

test('the gh client fails when a create reports no issue, or a listing is not a list', async () => {
  const { ghIssuesClient } = await incident();
  const silent = ghIssuesClient({ exec: () => '', repo: () => 'example/none' });
  assert.throws(
    () => silent.createIssue({ title: 't', body: 'b', labels: [LABEL], assignees: [ASSIGNEE] }),
    /printed no issue URL/
  );
  assert.throws(() => silent.listOpenLabelled(LABEL), /open issues/);

  const object = ghIssuesClient({ exec: () => '{"message":"Not Found"}', repo: () => 'example/none' });
  assert.throws(() => object.listOpenLabelled(LABEL), /open issues/);
});

// --- The audit log file ----------------------------------------------------

test('the audit log must be one regular file under the size cap', { skip: NO_SHELL }, async (t) => {
  const { readAuditLog, AUDIT_LOG_MAX_BYTES } = await incident();
  const box = sandbox(t);

  const file = box.file('audit.log', PUBLISHED_CAPTURE);
  assert.equal(readAuditLog(file), PUBLISHED_CAPTURE);

  // A link is refused whatever it points at: the file comes from another job,
  // and its target would be quoted into a public issue.
  const link = path.join(box.dir, 'link.log');
  symlinkSync(file, link);
  assert.throws(() => readAuditLog(link), /regular file/);
  assert.throws(() => readAuditLog(box.dir), /regular file/);
  assert.throws(() => readAuditLog(path.join(box.dir, 'absent.log')), /cannot read the audit log/);

  const big = box.file('big.log', 'x'.repeat(AUDIT_LOG_MAX_BYTES + 1));
  assert.throws(() => readAuditLog(big), /larger than/);
  const atCap = box.file('cap.log', 'x'.repeat(AUDIT_LOG_MAX_BYTES));
  assert.equal(readAuditLog(atCap).length, AUDIT_LOG_MAX_BYTES);
});

// --- The command -----------------------------------------------------------

test('the command refuses a CANDIDATE capture, naming it, without starting gh', { skip: NO_SHELL }, (t) => {
  const box = sandbox(t);
  const r = box.run(['open', '--audit-log', box.file('audit.log', CANDIDATE_CAPTURE), '--run-url', RUN_URL]);

  assert.equal(r.error, undefined);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /CANDIDATE/);
  assert.deepEqual(box.ghCalls(), []);
});

test('the command runs when started through a link to the script, not only by its real path', { skip: NO_SHELL }, (t) => {
  const box = sandbox(t);
  const link = path.join(box.dir, 'linked-incident.mjs');
  symlinkSync(SCRIPT, link);

  // A script that compares its own URL with the path it was started by exits 0
  // here having done nothing, which reads as "no incident to file".
  const r = box.run(['open', '--audit-log', box.file('audit.log', CANDIDATE_CAPTURE), '--run-url', RUN_URL], {
    entry: link,
  });

  assert.equal(r.status, 2);
  assert.match(r.stderr, /CANDIDATE/);
});

test('the command opens exactly one issue for a failing published capture', { skip: NO_SHELL }, (t) => {
  const box = sandbox(t);
  const r = box.run(['open', '--audit-log', box.file('audit.log', PUBLISHED_CAPTURE), '--run-url', RUN_URL]);

  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Opened #7/);
  const calls = box.ghCalls();
  assert.deepEqual(calls.map((c) => c.slice(0, 2).join(' ')), ['issue list', 'issue create']);
  const create = calls[1];
  assert.deepEqual(create.slice(2, 4), ['--repo', 'example/none']);
  assert.equal(create[create.indexOf('--title') + 1], `${TITLE}${RESOLVED_VERSION}`);
  assert.equal(create[create.indexOf('--label') + 1], LABEL);
  assert.equal(create[create.indexOf('--assignee') + 1], ASSIGNEE);
  const body = box.stdinOf('create');
  for (const fact of [RUN_URL, ADVISORY_HIGH, ADVISORY_CRITICAL]) assert.ok(body.includes(fact));
});

test('the command fails when gh refuses the create, as it does for an assignee it cannot assign', { skip: NO_SHELL }, (t) => {
  const box = sandbox(t);
  const r = box.run(['open', '--audit-log', box.file('audit.log', PUBLISHED_CAPTURE), '--run-url', RUN_URL], {
    createExit: '1',
  });

  assert.equal(r.status, 2);
  assert.match(r.stderr, /::error::/);
  assert.doesNotMatch(r.stdout, /Opened/);
});

test('the command comments on the open issue and, on a passing run, closes it', { skip: NO_SHELL }, (t) => {
  const box = sandbox(t);
  const open = JSON.stringify([{ number: 41, title: `${TITLE}0.10.11` }]);

  const again = box.run(['open', '--audit-log', box.file('audit.log', PUBLISHED_CAPTURE), '--run-url', RUN_URL], { open });
  assert.equal(again.status, 0, again.stderr);
  assert.ok(box.stdinOf('comment').includes(ADVISORY_HIGH));

  const resolved = box.run(['resolve', '--run-url', RUN_URL], { open });
  assert.equal(resolved.status, 0, resolved.stderr);
  assert.ok(box.stdinOf('comment').includes(RUN_URL));
  assert.deepEqual(
    box.ghCalls().map((c) => c.slice(0, 3).join(' ')),
    ['issue list --repo', 'issue comment 41', 'issue edit 41', 'issue list --repo', 'issue comment 41', 'issue close 41']
  );
});

test('the command exits 2 with its usage on anything it does not understand, without starting gh', { skip: NO_SHELL }, (t) => {
  const box = sandbox(t);
  const log = box.file('audit.log', PUBLISHED_CAPTURE);
  const link = path.join(box.dir, 'link.log');
  symlinkSync(log, link);

  for (const args of [
    [],
    ['reopen', '--run-url', RUN_URL],
    ['open', '--run-url', RUN_URL],
    ['open', '--audit-log', log],
    ['open', '--audit-log', log, '--run-url'],
    ['open', '--audit-log', log, '--run-url', 'not-a-url'],
    ['open', '--audit-log', link, '--run-url', RUN_URL],
    ['open', '--audit-log', log, '--run-url', RUN_URL, '--repo', 'other/repo'],
    ['open', log, '--run-url', RUN_URL],
    ['resolve'],
    ['resolve', '--run-url', RUN_URL, '--audit-log', log],
  ]) {
    const r = box.run(args);
    assert.equal(r.status, 2, `${JSON.stringify(args)} exited ${r.status}: ${r.stderr}`);
    assert.match(r.stderr, /::error::/);
  }
  assert.deepEqual(box.ghCalls(), []);
});
